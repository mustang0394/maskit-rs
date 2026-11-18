//! 审计引擎：8 类被动信号 + severity 过滤 + 主动探针（M8）。
//!
//! 对齐 Python audit_signals.py 的核心信号（纯函数、永不抛异常、永不改入参）：
//! S1 error_leak / S2 identity_swap / S3 tool_call_rewrite / S4 sse_anomaly /
//! S6 response_poison / S7 cross_request_pollution / S9 dangerous_action /
//! credential_echo（凭据回流）。

pub mod signals;

use serde::{Deserialize, Serialize};

pub use signals::*;

/// 严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord, Default)]
pub enum Severity {
    Low = 1,
    #[default]
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

/// 一条审计发现。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub signal: String,
    pub severity: Severity,
    pub evidence: String,
    pub kind: String,
}

/// 恒落库的信号（不受 severity_floor 拦截）。
pub const ALWAYS_RECORD: &[&str] = &["dangerous_action"];

/// 按 (kind, evidence) 去重，重复次数并入 evidence（对齐 `dedupe_findings`）。
pub fn dedupe_findings(items: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let mut counts: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    let mut index: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    for f in items {
        let key = (f.kind.clone(), f.evidence.clone());
        if let Some(&i) = index.get(&key) {
            *counts.entry(key).or_insert(1) += 1;
            let _ = i;
        } else {
            index.insert(key.clone(), out.len());
            counts.insert(key, 1);
            out.push(f);
        }
    }
    for f in out.iter_mut() {
        let key = (f.kind.clone(), f.evidence.clone());
        if let Some(&n) = counts.get(&key) {
            if n > 1 {
                f.evidence = format!("{} (x{n})", f.evidence);
            }
        }
    }
    out
}

/// 被动审计聚合（对齐 `aggregate_passive`）。
#[derive(Debug, Clone, Serialize)]
pub struct Aggregate {
    pub severity: Severity,
    pub counts: std::collections::BTreeMap<String, usize>,
    pub total: usize,
}

pub fn aggregate_passive(findings_lists: &[Vec<Finding>]) -> Aggregate {
    let mut counts = std::collections::BTreeMap::new();
    let mut total = 0usize;
    let mut top = Severity::Low;
    for list in findings_lists {
        for f in list {
            *counts.entry(f.signal.clone()).or_insert(0) += 1;
            total += 1;
            if f.severity > top {
                top = f.severity;
            }
        }
    }
    Aggregate {
        severity: top,
        counts,
        total,
    }
}

/// 响应侧审计钩子：跑被动信号 + 落库（对齐 `_audit_response`）。
pub fn on_response(
    bus: &crate::store::events::EventBus,
    sid: &str,
    store: &crate::mask::session::SessionStore,
    restored_text: &str,
    meta: &crate::server::response::StreamMeta,
) {
    // 配置门控：关闭审计/被动审计时一条都不跑（此前 audit.* 完全是死配置）。
    if !meta.audit_enabled || !meta.audit_passive {
        return;
    }
    let enabled = |sig: &str| meta.audit_signals.get(sig).copied().unwrap_or(true);
    let mut findings = Vec::new();

    // S2 换芯：请求 model vs 响应 model
    if enabled("identity_swap") {
        let resp_model = extract_response_model(restored_text);
        if let Some(rm) = resp_model {
            findings.extend(scan_identity_swap(&meta.model, &rm));
        }
    }
    // S6 响应投毒 / 凭据回流
    if enabled("response_poison") {
        findings.extend(scan_response_poison(restored_text, None));
    }
    // S1 错误响应泄漏（此前完全没接线）
    if enabled("error_leak") && meta.status >= 400 {
        findings.extend(scan_error_leak(
            Some(meta.status),
            restored_text,
            &meta.req_dialog,
        ));
    }
    // S4 SSE 事件异常（从还原后文本重解析 data: 行，无需流内缓存）
    if enabled("sse_anomaly") {
        let events: Vec<serde_json::Value> = restored_text
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("data:"))
            .filter_map(|p| serde_json::from_str::<serde_json::Value>(p.trim()).ok())
            .collect();
        if events.len() >= 2 {
            findings.extend(scan_sse_anomaly(&events));
        }
    }
    // S9 危险动作（文本扫描 + 命令拦截槽位命中合并）
    let hits = store
        .get(sid)
        .map(|s| s.cmd_hits.clone())
        .unwrap_or_default();
    if enabled("dangerous_action") {
        let reason_snips: Vec<String> = store
            .get(sid)
            .map(|s| s.cmd_reason_snippets.iter().cloned().collect())
            .unwrap_or_default();
        let mut danger = scan_dangerous_action(restored_text, None);
        // 思考通道出现过的片段 → 压掉全量扫描的对应误报
        danger.retain(|f| !reason_snips.iter().any(|s| f.evidence.contains(s.as_str())));
        findings.extend(danger);
        // 命令拦截命中不再丢弃：并入审计 findings（blocked 升 High）
        for h in &hits {
            findings.push(Finding {
                signal: "dangerous_action".into(),
                severity: if h.blocked {
                    Severity::High
                } else {
                    Severity::Medium
                },
                evidence: format!(
                    "cmd_hit channel={} kind={} snippet={}",
                    h.channel,
                    h.kind,
                    crate::util::truncate_utf8(&h.snippet, 120)
                ),
                kind: format!("cmd_hit:{}", h.kind),
            });
        }
    }

    for f in dedupe_findings(findings) {
        bus.emit_audit(
            &f,
            sid,
            &meta.host,
            &meta.method,
            &meta.path,
            meta.audit_floor,
        );
    }

    // CMDHIT 事件（此前 EventType::CmdHit 全仓无 emit 点：命令命中在控制台不可见）
    if meta.audit_enabled {
        for h in hits {
            let ev = crate::store::events::Event {
                id: 0,
                ts: 0.0,
                event_type: crate::store::events::EventType::CmdHit,
                method: meta.method.clone(),
                path: meta.path.clone(),
                status: meta.status,
                reason: h.kind.clone(),
                protocol: meta.protocol.clone(),
                model: meta.model.clone(),
                session_id: sid.into(),
                count: 1,
                message: crate::util::truncate_utf8(&h.snippet, 200).to_string(),
                request_headers: meta.request_headers.clone(),
                ..Default::default()
            };
            bus.emit(ev);
        }
    }
}

/// 从响应文本提取 model 字段（尽力而为）。
pub fn extract_response_model(text: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(m) = v.get("model").and_then(|m| m.as_str()) {
            return Some(m.to_string());
        }
    }
    // SSE：逐行取 data:
    for line in text.lines() {
        if let Some(p) = line.strip_prefix("data:") {
            if let Ok(d) = serde_json::from_str::<serde_json::Value>(p.trim()) {
                if let Some(m) = d.get("model").and_then(|m| m.as_str()) {
                    return Some(m.to_string());
                }
                if let Some(m) = d
                    .get("message")
                    .and_then(|m| m.get("model"))
                    .and_then(|m| m.as_str())
                {
                    return Some(m.to_string());
                }
                if let Some(m) = d
                    .get("response")
                    .and_then(|r| r.get("model"))
                    .and_then(|m| m.as_str())
                {
                    return Some(m.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert_eq!(Severity::parse("HIGH"), Severity::High);
        assert_eq!(Severity::High.as_str(), "HIGH");
    }

    #[test]
    fn dedupe_collapses_with_count() {
        let f = Finding {
            signal: "response_poison".into(),
            severity: Severity::High,
            evidence: "exfil_url host=evil.example".into(),
            kind: "exfil_url".into(),
        };
        let out = dedupe_findings(vec![f.clone(), f.clone(), f]);
        assert_eq!(out.len(), 1);
        assert!(out[0].evidence.contains("(x3)"), "重复次数并入 evidence");
    }

    #[test]
    fn aggregate_top_severity() {
        let a = vec![
            vec![Finding {
                signal: "error_leak".into(),
                severity: Severity::High,
                evidence: "x".into(),
                kind: "sk".into(),
            }],
            vec![Finding {
                signal: "sse_anomaly".into(),
                severity: Severity::Medium,
                evidence: "y".into(),
                kind: "u".into(),
            }],
            vec![],
        ];
        let agg = aggregate_passive(&a);
        assert_eq!(agg.severity, Severity::High);
        assert_eq!(agg.total, 2);
    }

    #[test]
    fn always_record_covers_dangerous_action() {
        assert!(ALWAYS_RECORD.contains(&"dangerous_action"));
    }

    #[test]
    fn extract_model_from_json_and_sse() {
        assert_eq!(
            extract_response_model(r#"{"model":"gpt-4o"}"#),
            Some("gpt-4o".into())
        );
        assert_eq!(
            extract_response_model("data: {\"model\":\"claude-3\"}\n\n"),
            Some("claude-3".into())
        );
        assert_eq!(
            extract_response_model("data: {\"message\":{\"model\":\"deepseek-v3\"}}\n\n"),
            Some("deepseek-v3".into())
        );
        assert_eq!(extract_response_model("no json"), None);
    }
}
