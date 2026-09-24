//! 事件模型与事件总线：管线各处产生事件，经 channel 送写线程（M9 落 sqlite）。
//!
//! M1 阶段仅落地模型 + 内存 ring 缓冲（控制台 /api/logs 直接读），
//! M9 阶段接入 sqlite 写线程，接口不变。

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// 事件类型（对齐 Python `_emit` 的 type 面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EventType {
    /// 请求已脱敏并转发
    Mask,
    /// 还原完成（响应侧收尾）
    Restore,
    /// 只读/未拦截透传
    Pass,
    /// 主动跳过脱敏（filter_disabled / fail_closed=false 的放行）
    Bypass,
    /// 阻断（fail-closed）
    Block,
    /// 错误
    Err,
    /// 响应侧 PII 告警（幻觉/泄漏扫描）
    ScanWarn,
    /// 命令拦截命中
    CmdHit,
}

/// 事件明细条目（命中的原文/占位符对；凭据类不落原文，见 cred 模块）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventItem {
    pub label: String,
    /// 命中的 token/占位符（**Python 口径字段名是 `tok`**，双向兼容）
    #[serde(rename = "tok", alias = "token", default)]
    pub token: String,
    /// 原文（凭据类为空，只留 digest/preview/length）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub original: String,
    /// 凭据类 = true：original 恒空，digest/preview/length 有效
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cred: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preview: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub length: usize,
    /// Python 侧的 hash 字段（占位符后缀；读取兼容）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
    /// 还原标记（RESTORE items 用）
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restored: bool,
}

fn is_zero(v: &usize) -> bool {
    *v == 0
}

/// 一条请求生命周期事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub id: u64,
    pub ts: f64, // unix seconds
    #[serde(rename = "type")]
    pub event_type: EventType,
    #[serde(default)]
    pub method: String,
    /// 不含 query 的原始路径
    #[serde(default)]
    pub path: String,
    /// HTTP 状态码。**兼容 Python 的 RESTORE payload**：那里的 `status` 是字符串
    /// （restored/unresolved），本字段遇到字符串时取 0（真实状态由 restore_status 承载）。
    #[serde(default, deserialize_with = "de_status_flexible")]
    pub status: u16,
    /// 事件原因码（readonly_method / filter_disabled / non_json_body / ...）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default)]
    pub protocol: String, // chat_completions / responses / anthropic / unknown / ""
    #[serde(default)]
    pub model: String,
    /// 会话 ID（**Python 口径字段名是 `sid`**，双向兼容）
    #[serde(
        rename = "sid",
        alias = "session_id",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub session_id: String,
    /// 流式标记（stream / non_stream；Python 侧恒带此键）
    #[serde(default)]
    pub stream_mode: String,
    /// 引擎实际处理方式（stream / whole；Python 侧恒带此键）
    #[serde(default)]
    pub stream_actual: String,
    /// 上游标识
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub upstream: String,
    /// 会话摘要（凭据已清洗）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dialog: String,
    /// 本次命中的唯一原文数（MASK）/ 还原数（RESTORE）
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub count: usize,
    /// 会话累计脱敏唯一值总数
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub masked_total: usize,
    /// 还原计数（RESTORE）
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub restored: usize,
    /// RESTORE 状态（restored / unresolved / no_sensitive_data / blocked）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub restore_status: String,
    /// 脱敏耗时（毫秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask_ms: Option<f64>,
    /// 首字节耗时（毫秒，流式）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_byte_ms: Option<f64>,
    /// 上游耗时（毫秒）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_ms: Option<f64>,
    /// 请求体大小 / 上游响应大小
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub req_bytes: usize,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub resp_bytes: usize,
    /// 命中明细（最多 30 条）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<EventItem>,
    /// 会话级统计：本次新增签发数 / 复用数
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub new_count: usize,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub reused_count: usize,
    /// 未还原占位符数（响应侧）
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub unresolved: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_samples: Vec<String>,
    /// unknown_shape 标记（D6：已路由未知形态整棵脱敏时置 true）
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unknown_shape: bool,
    /// 错误信息
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

/// 兼容数字与字符串的状态码反序列化（Python 的 RESTORE `status` 是字符串）。
fn de_status_flexible<'de, D>(de: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(de)?;
    Ok(match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0).min(u16::MAX as u64) as u16,
        Some(serde_json::Value::String(s)) => s.parse::<u16>().unwrap_or(0),
        _ => 0,
    })
}

impl Default for Event {
    fn default() -> Self {
        Self {
            id: 0,
            ts: 0.0,
            event_type: EventType::Pass,
            method: String::new(),
            path: String::new(),
            status: 0,
            reason: String::new(),
            protocol: String::new(),
            model: String::new(),
            session_id: String::new(),
            stream_mode: String::new(),
            stream_actual: String::new(),
            upstream: String::new(),
            dialog: String::new(),
            count: 0,
            masked_total: 0,
            restored: 0,
            restore_status: String::new(),
            mask_ms: None,
            first_byte_ms: None,
            upstream_ms: None,
            req_bytes: 0,
            resp_bytes: 0,
            items: vec![],
            new_count: 0,
            reused_count: 0,
            unresolved: 0,
            unresolved_samples: vec![],
            unknown_shape: false,
            message: String::new(),
        }
    }
}

/// 事件总线：异步发射（永不阻塞管线），内存 ring 供 API 读取。
/// 审计事件（M8）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: u64,
    pub ts: f64,
    pub signal_type: String,
    pub severity: String,
    pub evidence: String,
    pub sid: String,
    pub host: String,
    pub method: String,
    pub path: String,
}

pub struct EventBus {
    ring: Mutex<VecDeque<Event>>,
    audits: Mutex<VecDeque<AuditEvent>>,
    next_id: Mutex<u64>,
    capacity: usize,
    /// 每日计数（Dashboard 用）：requests/masked/restored/blocked
    counters: Mutex<Counters>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Counters {
    pub requests: u64,
    pub masked: u64,
    pub restored: u64,
    pub blocked: u64,
    pub bypassed: u64,
    pub errors: u64,
}

const RING_CAPACITY: usize = 2000;

impl EventBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
            audits: Mutex::new(VecDeque::new()),
            next_id: Mutex::new(1),
            capacity: RING_CAPACITY,
            counters: Mutex::new(Counters::default()),
        })
    }

    /// 发射事件（非阻塞；ring 满则丢最老）。
    #[allow(dead_code)] // M6 接线
    pub fn emit(&self, mut ev: Event) {
        {
            let mut id = self.next_id.lock().unwrap();
            ev.id = *id;
            *id += 1;
        }
        if ev.ts == 0.0 {
            ev.ts = now_secs();
        }
        {
            let mut c = self.counters.lock().unwrap();
            c.requests += 1;
            match ev.event_type {
                EventType::Mask => c.masked += 1,
                EventType::Restore => c.restored += 1,
                EventType::Block => c.blocked += 1,
                EventType::Bypass => c.bypassed += 1,
                EventType::Err => c.errors += 1,
                _ => {}
            }
        }
        let mut ring = self.ring.lock().unwrap();
        if ring.len() >= self.capacity {
            ring.pop_front();
        }
        ring.push_back(ev);
    }

    /// 读取最近事件（新→旧），limit 上限。
    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let ring = self.ring.lock().unwrap();
        ring.iter().rev().take(limit).cloned().collect()
    }

    /// 按事件 id 查详情。
    pub fn by_id(&self, id: u64) -> Option<Event> {
        let ring = self.ring.lock().unwrap();
        ring.iter().find(|e| e.id == id).cloned()
    }

    pub fn clear(&self) {
        self.ring.lock().unwrap().clear();
        *self.counters.lock().unwrap() = Counters::default();
    }

    /// 发审计事件（M8）。审计事件独立计数，不进主事件 ring 的 requests。
    pub fn emit_audit(
        &self,
        f: &crate::audit::Finding,
        sid: &str,
        host: &str,
        method: &str,
        path: &str,
    ) {
        let floor = crate::audit::Severity::Medium; // 默认 severity_floor
        let always = crate::audit::ALWAYS_RECORD.contains(&f.signal.as_str());
        if f.severity < floor && !always {
            return;
        }
        let mut audits = self.audits.lock().unwrap();
        if audits.len() >= 1000 {
            audits.pop_front();
        }
        audits.push_back(AuditEvent {
            id: 0,
            ts: now_secs(),
            signal_type: f.signal.clone(),
            severity: f.severity.as_str().to_string(),
            evidence: f.evidence.clone(),
            sid: sid.to_string(),
            host: host.to_string(),
            method: method.to_string(),
            path: path.to_string(),
        });
    }

    /// 读审计事件（新→旧）。
    pub fn recent_audits(&self, limit: usize) -> Vec<AuditEvent> {
        let audits = self.audits.lock().unwrap();
        audits.iter().rev().take(limit).cloned().collect()
    }

    pub fn clear_audits(&self) {
        self.audits.lock().unwrap().clear();
    }

    pub fn counters(&self) -> Counters {
        self.counters.lock().unwrap().clone()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
            audits: Mutex::new(VecDeque::new()),
            next_id: Mutex::new(1),
            capacity: RING_CAPACITY,
            counters: Mutex::new(Counters::default()),
        }
    }
}

#[allow(dead_code)] // M6 使用
pub fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[allow(dead_code)] // M6 使用
pub fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(t: EventType) -> Event {
        Event {
            id: 0,
            ts: 0.0,
            event_type: t,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            status: 200,
            reason: String::new(),
            protocol: "chat_completions".into(),
            model: "gpt-4o".into(),
            session_id: String::new(),
            mask_ms: None,
            first_byte_ms: None,
            upstream_ms: None,
            req_bytes: 0,
            resp_bytes: 0,
            items: vec![],
            new_count: 0,
            reused_count: 0,
            unresolved: 0,
            unresolved_samples: vec![],
            unknown_shape: false,
            message: String::new(),
            ..Default::default()
        }
    }

    #[test]
    fn emit_assigns_id_and_ts() {
        let bus = EventBus::new();
        bus.emit(sample(EventType::Mask));
        bus.emit(sample(EventType::Pass));
        let all = bus.recent(10);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, 2); // 新→旧
        assert!(all[0].ts > 0.0);
        let c = bus.counters();
        assert_eq!(c.requests, 2);
        assert_eq!(c.masked, 1);
    }

    #[test]
    fn ring_capacity_drops_oldest() {
        let bus = EventBus::new();
        for _ in 0..(RING_CAPACITY + 100) {
            bus.emit(sample(EventType::Pass));
        }
        let all = bus.recent(usize::MAX);
        assert_eq!(all.len(), RING_CAPACITY);
        // 最老的事件 id 应该是 101（前 100 个被挤出）
        assert_eq!(all.last().unwrap().id, 101);
    }

    #[test]
    fn by_id_lookup() {
        let bus = EventBus::new();
        bus.emit(sample(EventType::Mask));
        bus.emit(sample(EventType::Mask));
        assert!(bus.by_id(1).is_some());
        assert!(bus.by_id(3).is_none());
    }
}
