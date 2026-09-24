//! 会话映射 + TTL 复用表 + 后缀索引（对齐 Python sessions/_RECENT_*/_RECENT_SUFFIX）。

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::placeholder;

/// 会话内映射（对齐 Python `_new_session` 的 fwd/rev/labels/pending）。
#[derive(Default)]
pub struct Session {
    /// orig → token
    pub fwd: HashMap<String, String>,
    /// token → orig
    pub rev: HashMap<String, String>,
    /// orig → label
    pub labels: HashMap<String, String>,
    /// 流式通道 → 半截占位符缓冲（channel → pending text）
    pub pending: HashMap<String, String>,
    /// 流式通道 → 最后一个该通道事件的 JSON 模板（收尾补发用）
    pub flush_tmpl: HashMap<String, String>,
    /// 本次请求命中且已登记的唯一原文（累积，跨叶子）
    pub last_hits: std::collections::HashSet<String>,
    /// 本次请求新增原文
    pub new_orig: std::collections::HashSet<String>,
    /// 还原计数 / 未还原计数 / 宽松兜底还原计数
    pub restored: u64,
    pub unresolved: u64,
    pub degraded: u64,
    /// 还原过的 token 集合
    pub restored_tokens: std::collections::HashSet<String>,
    /// 还原过的原文集合（响应侧 PII 扫描防误报）
    pub restored_origs: std::collections::HashSet<String>,
    /// 未还原占位符样本（≤5）
    pub unresolved_samples: Vec<String>,
    /// 危险命令命中（槽位级）
    pub cmd_hits: Vec<CmdHit>,
    pub cmd_blocked: bool,
    /// 回声基线（惰性构建）
    pub cmd_req_window: Option<Vec<u8>>,
    pub cmd_req_snippets: Option<std::collections::HashSet<String>>,
    pub cmd_reason_snippets: std::collections::HashSet<String>,
    pub cmd_pend: HashMap<String, String>,
    /// 请求侧命令窗口切片
    /// 时间戳
    pub ts: f64,
    pub req_ts: f64,
    pub req_t0: f64,
    pub mask_ms: f64,
    pub resp_ts: Option<f64>,
    pub first_byte_ms: Option<f64>,
    /// 请求已发出、响应未到（防 sweep 误删）
    pub inflight: bool,
    /// 模型名 / 流式标记
    pub model: String,
    pub stream_mode: String,
    /// 后缀是否沿用复用表（诊断）
    pub suffix_reused: bool,
}

#[derive(Debug, Clone)]
pub struct CmdHit {
    pub kind: String,
    pub channel: String,
    pub snippet: String,
    pub ts: f64,
    pub blocked: bool,
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl Session {
    pub fn new() -> Self {
        let t = now();
        Session {
            ts: t,
            req_ts: t,
            req_t0: t,
            ..Default::default()
        }
    }
}

/// 复用表条目 [token_or_orig, label, ts]
#[derive(Clone)]
pub struct RecentEntry {
    pub token: String,
    pub label: String,
    pub ts: f64,
}

pub const RECENT_MAX: usize = 2000;
/// 复用表 TTL：至少 24h（对齐 RECENT_TTL）
pub const RECENT_TTL: u64 = 24 * 3600;

/// 全局会话表。
pub struct SessionStore {
    pub sessions: DashMap<String, Session>,
    /// orig → (token, label, ts)
    pub recent_fwd: DashMap<String, RecentEntry>,
    /// token → (orig, label, ts)
    pub recent_rev: DashMap<String, RecentEntry>,
    /// 6位辅音后缀 → token（或 Ambiguous）
    pub recent_suffix: DashMap<String, SuffixIndexValue>,
    /// 自定义词永久映射 orig → token
    pub custom_fwd: DashMap<String, String>,
    /// 自定义词永久映射 token → (orig, label)
    pub custom_rev: DashMap<String, RecentEntry>,
    /// 复用表 TTL（可跟 session_ttl 放大）
    pub ttl_secs: std::sync::atomic::AtomicU64,
}

#[derive(Clone, PartialEq)]
pub enum SuffixIndexValue {
    Token(String),
    Ambiguous,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            recent_fwd: DashMap::new(),
            recent_rev: DashMap::new(),
            recent_suffix: DashMap::new(),
            custom_fwd: DashMap::new(),
            custom_rev: DashMap::new(),
            ttl_secs: std::sync::atomic::AtomicU64::new(RECENT_TTL),
        }
    }

    pub fn set_ttl(&self, session_ttl_secs: u64) {
        self.ttl_secs.store(
            RECENT_TTL.max(session_ttl_secs),
            std::sync::atomic::Ordering::Release,
        );
    }

    pub fn recent_ttl(&self) -> u64 {
        self.ttl_secs.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn new_session(&self, sid: &str) {
        self.sessions.insert(sid.to_string(), Session::new());
    }

    pub fn get(&self, sid: &str) -> Option<dashmap::mapref::one::Ref<'_, String, Session>> {
        self.sessions.get(sid)
    }

    pub fn get_mut(&self, sid: &str) -> Option<dashmap::mapref::one::RefMut<'_, String, Session>> {
        self.sessions.get_mut(sid)
    }

    pub fn touch(&self, sid: &str) {
        if let Some(mut s) = self.sessions.get_mut(sid) {
            s.ts = now();
        }
    }

    pub fn drop_session(&self, sid: &str) {
        self.sessions.remove(sid);
    }

    /// 会话过期清理（对齐 `_sweep`：按 ts + TTL，inflight 跳过）。
    pub fn sweep(&self, ttl_secs: f64) {
        let now = now();
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|kv| {
                let s = kv.value();
                !s.inflight && (now - s.ts) > ttl_secs
            })
            .map(|kv| kv.key().clone())
            .collect();
        for sid in expired {
            self.sessions.remove(&sid);
        }
    }

    /// 该原文是否属于启用的自定义词（永久豁免 TTL/LRU）。
    pub fn is_custom_word_orig(&self, orig: &str) -> bool {
        if let Some(tok) = self.custom_fwd.get(orig) {
            return self.custom_rev.contains_key(tok.as_str());
        }
        false
    }

    /// 取该原文的占位符：TTL 内复用旧的，否则新建并登记（对齐 `_recall_token`）。
    /// `taken(token, suffix)` 由调用方提供后缀冲突检查。
    pub fn recall_token(
        &self,
        orig: &str,
        label: &str,
        taken: &dyn Fn(&str, &str) -> bool,
    ) -> (String, bool) {
        // 安全防套娃：orig 自身是占位符 → 原样返回
        if super::placeholder::placeholder_rx().is_match(orig) {
            return (orig.to_string(), false);
        }
        // 自定义词永久映射
        if let Some(tok) = self.custom_fwd.get(orig) {
            let tok = tok.clone();
            self.touch_recent(&tok, orig);
            self.suffix_index_add(&tok);
            return (tok, false);
        }
        let now = now();
        let ttl = self.recent_ttl() as f64;
        if let Some(hit) = self.recent_fwd.get(orig) {
            let is_custom = self.is_custom_word_orig(orig);
            if is_custom || now - hit.ts <= ttl {
                let token = hit.token.clone();
                drop(hit);
                // 幂等补登记
                self.suffix_index_add(&token);
                if let Some(mut e) = self.recent_fwd.get_mut(orig) {
                    e.ts = now;
                }
                if let Some(mut e) = self.recent_rev.get_mut(&token) {
                    e.ts = now;
                }
                return (token, true);
            }
        }
        let token = placeholder::new_token(label, &taken);
        // 旧映射过期：注销 REV / 后缀索引再覆盖 FWD
        if let Some(prev) = self.recent_fwd.get(orig) {
            if prev.token != token {
                self.recent_rev.remove(&prev.token.clone());
                self.suffix_index_del(&prev.token.clone());
            }
        }
        self.recent_fwd.insert(
            orig.to_string(),
            RecentEntry {
                token: token.clone(),
                label: label.to_string(),
                ts: now,
            },
        );
        self.recent_rev.insert(
            token.clone(),
            RecentEntry {
                token: orig.to_string(),
                label: label.to_string(),
                ts: now,
            },
        );
        self.suffix_index_add(&token);
        self.prune_recent();
        (token, false)
    }

    /// 登记原文→占位符；返回是否沿用复用表旧 token（对齐 `_remember`）。
    pub fn remember(
        &self,
        session: &mut Session,
        orig: &str,
        label: &str,
        taken: &dyn Fn(&str, &str) -> bool,
    ) -> bool {
        if !session.fwd.contains_key(orig) {
            let (token, reused) = self.recall_token(orig, label, taken);
            session.fwd.insert(orig.to_string(), token.clone());
            session.labels.insert(orig.to_string(), label.to_string());
            session.rev.insert(token, orig.to_string());
            return reused;
        }
        false
    }

    fn touch_recent(&self, token: &str, orig: &str) {
        let now = now();
        if let Some(mut e) = self.recent_rev.get_mut(token) {
            e.ts = now;
        }
        if let Some(mut e) = self.recent_fwd.get_mut(orig) {
            e.ts = now;
        }
    }

    /// 后缀索引登记。撞车即置 Ambiguous（对齐 `_suffix_index_add`）。
    pub fn suffix_index_add(&self, token: &str) {
        let sfx = placeholder::token_suffix(token);
        if !placeholder::suffix_indexable(&sfx) {
            return;
        }
        match self.recent_suffix.get(&sfx) {
            None => {
                self.recent_suffix
                    .insert(sfx, SuffixIndexValue::Token(token.to_string()));
            }
            Some(cur) => {
                let cur = cur.clone();
                if cur != SuffixIndexValue::Token(token.to_string()) {
                    self.recent_suffix.insert(sfx, SuffixIndexValue::Ambiguous);
                }
            }
        }
    }

    /// 后缀索引注销（只删确实指向本 token 的条目）。
    pub fn suffix_index_del(&self, token: &str) {
        let sfx = placeholder::token_suffix(token);
        if sfx.is_empty() {
            return;
        }
        if let Some(v) = self.recent_suffix.get(&sfx) {
            if *v == SuffixIndexValue::Token(token.to_string()) {
                drop(v);
                self.recent_suffix.remove(&sfx);
            }
        }
    }

    /// 按后缀反查真实 token（对齐 `_suffix_real_token`：标签归一化后必须相等）。
    pub fn suffix_real_token(&self, token: &str) -> Option<String> {
        let rx = placeholder::any_braced_suffix_rx();
        let caps = rx.captures(token)?;
        let label_raw = caps.get(1)?.as_str();
        let sfx = caps.get(2)?.as_str().to_lowercase();
        let real = match self.recent_suffix.get(&sfx).map(|v| v.clone()) {
            Some(SuffixIndexValue::Token(t)) => t,
            Some(SuffixIndexValue::Ambiguous) | None => return None,
        };
        if real == token {
            return None;
        }
        let real_label = placeholder::token_label(&real);
        if placeholder::safe_label(label_raw) != placeholder::safe_label(&real_label) {
            return None;
        }
        Some(real)
    }

    /// 占位符 → 原文（对齐 `_lookup`：本会话 → 复用表 → 自定义词 → 套娃解包）。
    pub fn lookup(&self, token: &str, sid: &str) -> Option<String> {
        let mut hit: Option<String> = None;
        if let Some(s) = self.sessions.get(sid) {
            if let Some(orig) = s.rev.get(token) {
                hit = Some(orig.clone());
            }
        }
        if hit.is_none() {
            if let Some(rec) = self.recent_rev.get(token) {
                let is_custom = self.is_custom_word_orig(&rec.token.clone());
                if is_custom
                    || placeholder::suffix_indexable(&placeholder::token_suffix(token))
                    || now() - rec.ts <= self.recent_ttl() as f64
                {
                    let orig = rec.token.clone();
                    drop(rec);
                    self.touch_recent(token, &orig);
                    hit = Some(orig);
                }
            }
        }
        if hit.is_none() {
            if let Some(rec) = self.custom_rev.get(token) {
                hit = Some(rec.token.clone());
            }
        }
        // 防套娃解包（≤5 层）
        let mut depth = 0usize;
        let mut cur = hit;
        let rx = placeholder::placeholder_rx();
        while let Some(h) = cur.clone() {
            if !rx.is_match(&h) || depth >= 5 {
                break;
            }
            depth += 1;
            let mut inner: Option<String> = None;
            if let Some(s) = self.sessions.get(sid) {
                if let Some(o) = s.rev.get(&h) {
                    inner = Some(o.clone());
                }
            }
            if inner.is_none() {
                if let Some(rec) = self.recent_rev.get(&h) {
                    let is_custom = self.is_custom_word_orig(&rec.token.clone());
                    if is_custom || now() - rec.ts <= self.recent_ttl() as f64 {
                        inner = Some(rec.token.clone());
                    }
                }
            }
            if inner.is_none() {
                if let Some(rec) = self.custom_rev.get(&h) {
                    inner = Some(rec.token.clone());
                }
            }
            cur = match inner {
                Some(i) if i != h => Some(i),
                _ => break,
            };
        }
        match cur.clone() {
            Some(h) if rx.is_match(&h) => None, // 最终仍是占位符 = 无真实明文
            other => other,
        }
    }

    /// TTL + 条数上限清理复用表（对齐 `_prune_recent`）。
    pub fn prune_recent(&self) {
        let now = now();
        let ttl = self.recent_ttl() as f64;
        let stale: Vec<String> = self
            .recent_fwd
            .iter()
            .filter(|kv| !self.is_custom_word_orig(kv.key()) && now - kv.value().ts > ttl)
            .map(|kv| kv.key().clone())
            .collect();
        for k in stale {
            if let Some(entry) = self.recent_fwd.get(&k) {
                let tok = entry.token.clone();
                drop(entry);
                self.recent_fwd.remove(&k);
                self.recent_rev.remove(&tok);
                self.suffix_index_del(&tok);
            }
        }
        let evictable: Vec<(String, String, f64)> = self
            .recent_fwd
            .iter()
            .filter(|kv| !self.is_custom_word_orig(kv.key()))
            .map(|kv| (kv.key().clone(), kv.value().token.clone(), kv.value().ts))
            .collect();
        if evictable.len() > RECENT_MAX {
            let over = evictable.len() - RECENT_MAX;
            let mut oldest: Vec<(String, String, f64)> = evictable;
            oldest.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
            for (k, tok, _ts) in oldest.into_iter().take(over) {
                self.recent_fwd.remove(&k);
                self.recent_rev.remove(&tok);
                self.suffix_index_del(&tok);
            }
        }
    }

    /// 从事件库预热复用表（M9 接线；此接口保持稳定）。
    pub fn warmup_from_events(&self, _records: Vec<(String, String, String)>) -> usize {
        // records: (token, orig, label) — 按 M9 调用；凭据类已由调用方过滤
        0
    }
}

/// 全局会话存储（进程唯一）。
pub static STORE: Lazy<SessionStore> = Lazy::new(SessionStore::new);

/// 后缀占用检查（new_token 的 taken 回调：查 REV 表与后缀索引）。
pub fn token_taken() -> impl Fn(&str, &str) -> bool {
    |token: &str, suffix: &str| {
        STORE.recent_rev.contains_key(token)
            || STORE.custom_rev.contains_key(token)
            || STORE.recent_suffix.contains_key(suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::placeholder::placeholder_rx;

    fn fresh_store() -> SessionStore {
        SessionStore::new()
    }

    #[test]
    fn remember_and_lookup() {
        let store = fresh_store();
        store.new_session("s1");
        let taken = token_taken_static(&store);
        {
            let mut s = store.get_mut("s1").unwrap();
            store.remember(&mut s, "张三", "NAME", &taken);
        }
        let token = store.get("s1").unwrap().fwd["张三"].clone();
        assert!(placeholder_rx().is_match(&token));
        assert_eq!(store.lookup(&token, "s1"), Some("张三".to_string()));
        // 未知 token → None
        assert_eq!(store.lookup("{{NAME_bcdfgh}}", "s1"), None);
    }

    // 让测试拿到基于具体 store 的 taken 闭包
    fn token_taken_static<'a>(store: &'a SessionStore) -> impl Fn(&str, &str) -> bool + 'a {
        move |token: &str, suffix: &str| {
            store.recent_rev.contains_key(token)
                || store.custom_rev.contains_key(token)
                || store.recent_suffix.contains_key(suffix)
        }
    }

    #[test]
    fn same_orig_reuses_token_across_sessions() {
        let store = fresh_store();
        let taken = token_taken_static(&store);
        store.new_session("a");
        store.new_session("b");
        let t1 = {
            let mut s = store.get_mut("a").unwrap();
            store.remember(&mut s, "13812345678", "PHONE", &taken);
            s.fwd["13812345678"].clone()
        };
        let t2 = {
            let mut s = store.get_mut("b").unwrap();
            store.remember(&mut s, "13812345678", "PHONE", &taken);
            s.fwd["13812345678"].clone()
        };
        assert_eq!(t1, t2, "TTL 内同一原文必须复用同一占位符（多轮一致性）");
    }

    #[test]
    fn suffix_lookup_rescues_rewritten_label() {
        let store = fresh_store();
        store.new_session("s");
        let taken = token_taken_static(&store);
        {
            let mut s = store.get_mut("s").unwrap();
            store.remember(&mut s, "192.168.1.1", "IP_PRIVATE", &taken);
        }
        let real = store.get("s").unwrap().fwd["192.168.1.1"].clone();
        // 模型把 {{IPPRIVATE_x}} 改写成 {{IP_PRIVATE_x}} → 按后缀救回
        let suffix = placeholder::token_suffix(&real);
        let rewritten = format!("{{{{IP_PRIVATE_{suffix}}}}}");
        let rescued = store.suffix_real_token(&rewritten);
        assert_eq!(rescued, Some(real.clone()));
        assert_eq!(store.lookup(&real, "s"), Some("192.168.1.1".to_string()));
        // 标签整体换名（{{HOST_x}}）不认
        let bad = format!("{{{{HOST_{suffix}}}}}");
        assert_eq!(store.suffix_real_token(&bad), None);
    }

    #[test]
    fn custom_word_permanent_mapping() {
        let store = fresh_store();
        store.new_session("s");
        let taken = token_taken_static(&store);
        store
            .custom_fwd
            .insert("张三".into(), "{{TERM_zzwkkk}}".into());
        store.custom_rev.insert(
            "{{TERM_zzwkkk}}".into(),
            RecentEntry {
                token: "张三".into(),
                label: "NAME".into(),
                ts: 0.0, // 很旧也不淘汰
            },
        );
        {
            let mut s = store.get_mut("s").unwrap();
            store.remember(&mut s, "张三", "NAME", &taken);
        }
        assert_eq!(store.get("s").unwrap().fwd["张三"], "{{TERM_zzwkkk}}");
        // TTL 过期仍可还原（永久映射）
        assert_eq!(
            store.lookup("{{TERM_zzwkkk}}", "s"),
            Some("张三".to_string())
        );
    }

    #[test]
    fn sweep_drops_expired_not_inflight() {
        let store = fresh_store();
        store.new_session("old");
        store.new_session("live");
        {
            let mut s = store.get_mut("old").unwrap();
            s.ts = now() - 10000.0;
        }
        {
            let mut s = store.get_mut("live").unwrap();
            s.ts = now() - 10000.0;
            s.inflight = true;
        }
        store.sweep(600.0);
        assert!(store.get("old").is_none());
        assert!(store.get("live").is_some());
    }

    #[test]
    fn prune_keeps_custom_and_evicts_oldest() {
        let store = fresh_store();
        let taken = token_taken_static(&store);
        // 自定义词
        store
            .custom_fwd
            .insert("永久词".into(), "{{TERM_pwwkkk}}".into());
        store.custom_rev.insert(
            "{{TERM_pwwkkk}}".into(),
            RecentEntry {
                token: "永久词".into(),
                label: "T".into(),
                ts: 0.0,
            },
        );
        // 灌满 2010 条普通条目
        for i in 0..2010 {
            let mut fake = Session::new();
            store.remember(&mut fake, &format!("orig{i}"), "TERM", &taken);
            // remember 用的是 fake session 的 fwd；还要真正进复用表 —— recall_token 已写入
        }
        store.prune_recent();
        let normal_count = store
            .recent_fwd
            .iter()
            .filter(|kv| !store.is_custom_word_orig(kv.key()))
            .count();
        assert!(
            normal_count <= RECENT_MAX,
            "普通条目数 {normal_count} 应 ≤ {RECENT_MAX}"
        );
        // 自定义词不被淘汰
        assert!(store.custom_fwd.contains_key("永久词"));
    }
}
