//! 响应侧管线：JSON / SSE / NDJSON 三路径还原 + RESTORE 事件 + 响应侧 PII 扫描 +
//! 命令拦截挂点（M7）。
//!
//! 对齐 Python `response()` / `responseheaders()` / `_handle_json` / `_handle_sse`
//! / `_handle_ndjson` / `_scan_response`。

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;

use crate::mask::engine::RestoreStats;
use crate::mask::session::SessionStore;
use crate::store::events::{Event, EventBus, EventItem, EventType};
use crate::stream::sse::{is_ndjson_ct, Framing, StreamState};

/// 响应处理结果。
pub struct ResponseOutcome {
    pub body: Bytes,
    /// 本次响应观测到的 token 用量（只统计数量，不做价格计算）
    pub usage: crate::store::usage::Usage,
    pub restored: u64,
    pub unresolved: u64,
    pub degraded: u64,
    pub unresolved_samples: Vec<String>,
    /// 响应用到的实际方式（stream / whole / none）
    pub stream_actual: &'static str,
    /// 是否发生了阻断（命令拦截 block 模式）
    pub blocked: bool,
}

/// 判断响应是否可还原（content-type + 是否声明的可流式）。
pub fn restorable(ct: &str, content_encoding: &str) -> bool {
    // 压缩体在解码前不能按事件切分；本实现要求上游返回 identity（请求侧已声明）
    if !content_encoding.is_empty() && content_encoding != "identity" {
        return false;
    }
    let c = ct.to_ascii_lowercase();
    c.contains("json") || c.contains("event-stream")
}

/// 响应侧是否应按流式逐事件处理。
pub fn is_streaming_response(ct: &str) -> bool {
    let c = ct.to_ascii_lowercase();
    c.contains("event-stream") || is_ndjson_ct(&c)
}

/// 判断响应侧 framing。
pub fn framing_of(ct: &str) -> Option<Framing> {
    let c = ct.to_ascii_lowercase();
    if c.contains("event-stream") {
        Some(Framing::Sse)
    } else if is_ndjson_ct(&c) {
        Some(Framing::Ndjson)
    } else {
        None
    }
}

/// 处理整包响应（非流式路径）。
pub fn process_whole(
    body: &[u8],
    ct: &str,
    sid: &str,
    store: &SessionStore,
    cmdblock: &crate::cmdblock::CmdBlockEngine,
) -> ResponseOutcome {
    let mut stats = RestoreStats::default();
    let text = String::from_utf8_lossy(body).to_string();
    let c = ct.to_ascii_lowercase();
    let mut blocked = false;
    // token 用量从**上游原始响应**提取（还原不改数字，但原始体最可靠）
    let usage = crate::store::usage::extract_usage(&text);

    let restored_text = if c.contains("json") && !is_ndjson_ct(&c) {
        // 整包 JSON：整树还原
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => {
                let out = crate::mask::tree::restore_tree(&v, sid, store, &mut stats, 0);
                // 命令拦截（非流式：通道由 JSON 键名判定，final=true）
                let out = cmdblock.process_tree(out, sid, store, &mut blocked);
                serde_json::to_string(&out).unwrap_or(text.clone())
            }
            Err(_) => {
                // 非 JSON 体（或坏 JSON）：原样返回
                text.clone()
            }
        }
    } else if is_ndjson_ct(&c) {
        let mut lines = Vec::new();
        let all: Vec<&str> = text.split('\n').collect();
        let last = all.len().saturating_sub(1);
        for (i, line) in all.iter().enumerate() {
            let r =
                crate::stream::sse::restore_ndjson_line(line, sid, store, &mut stats, i == last);
            lines.push(r);
        }
        lines.join("\n")
    } else if c.contains("event-stream") {
        let mut blocks = Vec::new();
        for block in text.split("\n\n") {
            blocks.push(crate::stream::sse::restore_sse_event(
                block, sid, store, &mut stats, false,
            ));
        }
        let mut joined = blocks.join("\n\n");
        let tail = crate::stream::sse::flush_pending(sid, store, Framing::Sse, &mut stats);
        if !tail.is_empty() {
            joined = format!("{}\n\n{}", joined.trim_end_matches('\n'), tail);
        }
        joined
    } else {
        text.clone()
    };

    ResponseOutcome {
        body: Bytes::from(restored_text.into_bytes()),
        usage,
        restored: stats.restored,
        unresolved: stats.unresolved,
        degraded: stats.degraded,
        unresolved_samples: stats.samples,
        stream_actual: "whole",
        blocked,
    }
}

/// 流式处理上游响应 body（逐 chunk 还原后下发）。
///
/// 用 `Body::from_stream` 把处理后的 chunk 直接下发 —— 首字延迟不等待整段生成。
pub fn stream_response(
    body: Incoming,
    framing: Framing,
    sid: String,
    store: &'static SessionStore,
    cmdblock: std::sync::Arc<crate::cmdblock::CmdBlockEngine>,
    bus: std::sync::Arc<EventBus>,
    meta: StreamMeta,
) -> axum::body::Body {
    let mut state = StreamState::new(framing);
    // 会话释放守卫：流正常结束、客户端中途断开、body 被直接 drop、panic ——
    // 任何退出路径都会释放。`inflight=true` 会让 sweep 跳过该会话，
    // 漏释放就是**永久**内存泄漏（长会话每轮 stream:true，sessions 表无界增长）。
    struct SessionGuard {
        sid: String,
        store: &'static SessionStore,
    }
    impl Drop for SessionGuard {
        fn drop(&mut self) {
            if let Some(mut sess) = self.store.get_mut(&self.sid) {
                sess.inflight = false;
            }
            self.store.drop_session(&self.sid);
        }
    }
    let stream = async_stream::stream! {
        // ⚠️ 守卫必须**活在生成器内部**：若建在 stream_response() 的局部，
        // 函数 return 时就 drop 了 → 会话在流被消费前消失 → 流式还原全部失效
        // （占位符原样下发）。放进生成器才能覆盖「消费完 / 断连 / 被丢弃」三种结束。
        let _session_guard = SessionGuard { sid: sid.clone(), store };
        let mut stats_total = RestoreStats::default();
        let mut usage_total = crate::store::usage::Usage::default();
        let mut s = body;
        let mut blocked = false;
        while let Some(frame) = s.frame().await {
            let Ok(f) = frame else { break };
            let Some(data) = f.data_ref() else { continue };
            let (out, stats) = state.push(data, &sid, store);
            // 逐块采集 usage（流末 usage 只出现在最后几块，不受文本留存上限影响）
            if !out.is_empty() {
                let text = String::from_utf8_lossy(data);
                usage_total.merge(&crate::store::usage::extract_usage(&text));
            }
            stats_total.restored += stats.restored;
            stats_total.unresolved += stats.unresolved;
            stats_total.degraded += stats.degraded;
            // 命令拦截（流式：逐帧处理 pending 缓冲）
            let out = if !blocked {
                let (o, b) = cmdblock.process_stream_bytes(&out, &sid, store, false);
                blocked = b;
                o
            } else {
                Vec::new()
            };
            if !out.is_empty() {
                yield Ok::<Bytes, std::io::Error>(Bytes::from(out));
            }
        }
        // 流末：flush 残余
        let (tail, stats) = state.push(b"", &sid, store);
        stats_total.restored += stats.restored;
        stats_total.unresolved += stats.unresolved;
        stats_total.degraded += stats.degraded;
        if !tail.is_empty() && !blocked {
            let (o, _) = cmdblock.process_stream_bytes(&tail, &sid, store, true);
            if !o.is_empty() {
                yield Ok(Bytes::from(o));
            }
        }
        // RESTORE 事件 + 响应扫描
        // dialog 取 state.kept —— 那是**还原后**的正文（上游回的是占位符，
        // 用户看到的是原文，事件里也该记原文）。
        let mut rmeta = meta.clone();
        rmeta.resp_dialog = state.kept.clone();
        emit_restore(&bus, &sid, &rmeta, &stats_total, store, blocked, "stream");

        if let Some(hook) = USAGE_HOOK.get() {
            hook(&meta.model, &usage_total);
        }
        crate::audit::on_response(&bus, &sid, store, &state.kept, &meta);
    };
    axum::body::Body::from_stream(stream)
}

/// 流式响应元信息。
/// 派生 Default：后续新增字段时，既有构造点用 `..Default::default()` 即可，
/// 不必逐处补全（曾因新增 resp_dialog/keep_plaintext 打断所有测试构造）。
#[derive(Clone, Default)]
pub struct StreamMeta {
    pub host: String,
    pub method: String,
    pub path: String,
    pub model: String,
    pub protocol: String,
    pub status: u16,
    pub req_bytes: usize,
    pub req_dialog: String,
    /// 还原后的**助手回复**文本（RESTORE 事件的 dialog）。
    /// 与 req_dialog 区分：Python 口径是「MASK 行 dialog=用户消息，
    /// RESTORE 行 dialog=助手回复」，此前两者混用了 req_dialog。
    pub resp_dialog: String,
    /// 日志是否保留凭据类明文（构造时从配置快照，避免热路径读锁）。
    pub keep_plaintext: bool,
}

/// 发 RESTORE 事件（对齐 `_emit_restore_summary`）。
pub fn emit_restore(
    bus: &EventBus,
    sid: &str,
    meta: &StreamMeta,
    stats: &RestoreStats,
    store: &SessionStore,
    blocked: bool,
    stream_actual: &str,
) {
    let (status, restored, unresolved) = if blocked {
        ("blocked", stats.restored, stats.unresolved)
    } else if stats.unresolved > 0 {
        ("unresolved", stats.restored, stats.unresolved)
    } else if stats.restored > 0 {
        ("restored", stats.restored, 0)
    } else {
        ("no_sensitive_data", 0, 0)
    };
    let items = build_restore_items(store, sid, stats, meta.keep_plaintext);
    let ev = Event {
        id: 0,
        ts: 0.0,
        event_type: EventType::Restore,
        method: meta.method.clone(),
        path: meta.path.clone(),
        status: meta.status,
        reason: status.into(),
        protocol: meta.protocol.clone(),
        model: meta.model.clone(),
        session_id: sid.into(),
        mask_ms: store.get(sid).map(|s| s.mask_ms),
        first_byte_ms: None,
        upstream_ms: None,
        req_bytes: meta.req_bytes,
        resp_bytes: 0,
        items,
        new_count: 0,
        reused_count: 0,
        unresolved: unresolved as usize,
        unresolved_samples: stats.samples.iter().take(5).cloned().collect(),
        unknown_shape: false,
        stream_actual: stream_actual.to_string(),
        restore_status: status.to_string(),
        restored: restored as usize,
        count: restored as usize,
        dialog: meta.resp_dialog.clone(),
        message: String::new(),
        ..Default::default()
    };
    bus.emit(ev);
}

fn build_restore_items(
    store: &SessionStore,
    sid: &str,
    stats: &RestoreStats,
    keep_plaintext: bool,
) -> Vec<EventItem> {
    let Some(s) = store.get(sid) else {
        return vec![];
    };
    let mut items = Vec::new();
    let mut origs: Vec<&String> = s.fwd.keys().collect();
    origs.sort();
    for orig in origs.into_iter().take(30) {
        let Some(token) = s.fwd.get(orig) else {
            continue;
        };
        let label = s.labels.get(orig).cloned().unwrap_or_default();
        let restored = s.restored_tokens.contains(token);
        let cred = crate::config::is_credential_label(&label);
        let mut item = EventItem {
            label: label.clone(),
            token: token.clone(),
            original: String::new(),
            cred,
            digest: String::new(),
            preview: crate::mask::engine::preview(orig, &label),
            length: orig.chars().count(),
            hash: crate::mask::placeholder::token_suffix(token),
            restored: false,
        };
        if cred {
            item.digest = crate::mask::validators::cred_digest(orig);
        }
        if keep_plaintext || !cred {
            item.original = orig.clone();
        }
        if !restored {
            // 未还原项标记（供前端区分）
            item.length = item.length.max(1);
        }
        let _ = stats;
        items.push(item);
    }
    items
}

/// 整包响应处理 + RESTORE 事件（供非流式路径调用）。
#[allow(clippy::too_many_arguments)]
pub fn process_and_emit(
    body: &[u8],
    ct: &str,
    sid: &str,
    store: &'static SessionStore,
    cmdblock: &crate::cmdblock::CmdBlockEngine,
    bus: &EventBus,
    meta: &StreamMeta,
) -> ResponseOutcome {
    let outcome = process_whole(body, ct, sid, store, cmdblock);
    let mut meta = meta.clone();
    // 非流式：dialog = **还原后**的助手回复
    meta.resp_dialog = serde_json::from_slice::<serde_json::Value>(&outcome.body)
        .map(|v| crate::mask::tree::extract_dialog_text(&v))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let t = String::from_utf8_lossy(&outcome.body);
            t.chars()
                .take(crate::mask::tree::DIALOG_MAX_CHARS)
                .collect()
        });
    let meta = &meta;
    let stats = RestoreStats {
        restored: outcome.restored,
        unresolved: outcome.unresolved,
        degraded: outcome.degraded,
        samples: outcome.unresolved_samples.clone(),
    };
    emit_restore(bus, sid, meta, &stats, store, outcome.blocked, "whole");
    // 响应侧 PII 扫描 + 审计
    let text = String::from_utf8_lossy(&outcome.body).to_string();
    crate::audit::on_response(bus, sid, store, &text, meta);
    outcome
}

/// token 用量落库钩子（进程内单例，由启动流程安装）。
///
/// 响应侧只负责观测与上报，落库交给持有 `EventStore` 的启动流程，
/// 这样响应模块不必知道 SQLite 的存在（也便于测试里替换）。
pub type UsageHook = Box<dyn Fn(&str, &crate::store::usage::Usage) + Send + Sync>;
static USAGE_HOOK: std::sync::OnceLock<UsageHook> = std::sync::OnceLock::new();

/// 安装 token 用量落库钩子（只生效一次）。
pub fn set_usage_hook(hook: UsageHook) {
    let _ = USAGE_HOOK.set(hook);
}

/// 响应侧 PII 扫描（对齐 `_scan_response`：本会话未脱敏过的 PII = 模型幻觉/泄漏）。
pub fn scan_response_pii(
    text: &str,
    sid: &str,
    store: &SessionStore,
    builtin_rules: &std::collections::BTreeMap<String, bool>,
    keep_plaintext: bool,
) -> Vec<EventItem> {
    use crate::mask::rules::{self, RULES};
    let s = store.get(sid);
    let known: std::collections::HashSet<String> = s
        .as_ref()
        .map(|s| {
            let mut k: std::collections::HashSet<String> = s.fwd.keys().cloned().collect();
            k.extend(s.restored_origs.iter().cloned());
            k
        })
        .unwrap_or_default();
    drop(s);
    // 扫描前段（对齐 _SCAN_BODY_MAX = 512KB）
    let scan_text = if text.len() > 512 * 1024 {
        &text[..512 * 1024]
    } else {
        text
    };
    let mut found: Vec<EventItem> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut exempt_conn: Vec<(usize, usize)> = Vec::new();
    for rule in RULES.iter() {
        if !rules::rule_enabled(rule.label, builtin_rules) {
            continue;
        }
        if !rule.may_hit(scan_text) {
            continue;
        }
        for caps in rule.rx.captures_iter(scan_text) {
            let m0 = caps.get(0).unwrap();
            let m = caps.get(rule.value_group).unwrap_or(m0);
            let orig = m.as_str();
            if !rule.checks.iter().all(|c| c(scan_text, m0, &caps)) {
                continue;
            }
            if !rules::semantic_check(rule.label, orig, scan_text, m0, &caps) {
                if rule.exempt_on_reject && exempt_conn.len() < 512 {
                    exempt_conn.push((m0.start(), m0.end()));
                }
                continue;
            }
            if rule.avoid_exempt
                && exempt_conn
                    .iter()
                    .any(|(s2, e2)| m0.start() < *e2 && m0.end() > *s2)
            {
                continue;
            }
            if known.contains(orig) {
                continue; // 本会话已知值，不是幻觉
            }
            let key = (rule.label.to_string(), orig.to_string());
            if !seen.insert(key) {
                continue;
            }
            if found.len() >= 10 {
                break;
            }
            let cred = crate::config::is_credential_label(rule.label);
            let mut item = EventItem {
                label: rule.label.to_string(),
                token: String::new(),
                original: String::new(),
                cred,
                digest: String::new(),
                preview: crate::mask::engine::preview(orig, rule.label),
                length: orig.chars().count(),
                hash: String::new(),
                restored: false,
            };
            if cred {
                item.digest = crate::mask::validators::cred_digest(orig);
            }
            if keep_plaintext || !cred {
                item.original = orig.to_string();
            }
            found.push(item);
        }
    }
    found
}

/// 凭据清洗（对齐 `_redact_credentials`：日志 dialog/preview 落库前洗凭据）。
pub fn redact_credentials(text: &str) -> String {
    use crate::mask::rules::RULES;
    let mut out = text.to_string();
    for rule in RULES.iter() {
        if crate::config::is_credential_label(rule.label) {
            out = rule.rx.replace_all(&out, "[REDACTED]").to_string();
        }
    }
    // 前缀规则（sk-/ah-…）不在 RULES 表里，必须单独过一遍
    // （否则 `sk-…` 明文会随 dialog/preview 落库）
    let prefixes: Vec<String> = crate::mask::engine::default_secret_prefixes()
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(rx) = crate::mask::engine::prefix_regex(&prefixes) {
        out = rx.replace_all(&out, "[REDACTED]").to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::mask::engine::{CustomWords, MaskCtx};

    fn setup() -> (Config, SessionStore, CustomWords) {
        let mut cfg = Config::default();
        for k in crate::config::ALL_BUILTIN_RULES {
            cfg.mask.builtin_rules.insert(k.to_string(), true);
        }
        let store = SessionStore::new();
        store.new_session("r");
        let custom = CustomWords::build(&cfg);
        (cfg, store, custom)
    }

    fn mask_and_register(parts: &(Config, SessionStore, CustomWords), text: &str) -> String {
        let ctx = MaskCtx::new(&parts.0, &parts.1, "r".into(), &parts.2);
        ctx.mask(text)
    }

    #[test]
    fn whole_json_restores() {
        let parts = setup();
        let masked = mask_and_register(&parts, "电话13800138000");
        let body =
            serde_json::json!({"choices": [{"message": {"content": format!("好的：{masked}")}}]});
        let cmd = crate::cmdblock::CmdBlockEngine::new(&parts.0);
        let out = process_whole(
            body.to_string().as_bytes(),
            "application/json",
            "r",
            &parts.1,
            &cmd,
        );
        let v: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(
            v["choices"][0]["message"]["content"],
            "好的：电话13800138000"
        );
        assert_eq!(out.restored, 1);
    }

    #[test]
    fn whole_sse_restores() {
        let parts = setup();
        let masked = mask_and_register(&parts, "电话13800138000");
        let body = format!(
            "data: {}\n\ndata: [DONE]\n\n",
            serde_json::json!({"choices": [{"delta": {"content": masked}}]})
        );
        let cmd = crate::cmdblock::CmdBlockEngine::new(&parts.0);
        let out = process_whole(body.as_bytes(), "text/event-stream", "r", &parts.1, &cmd);
        let s = String::from_utf8_lossy(&out.body);
        assert!(s.contains("13800138000"));
        assert!(s.contains("[DONE]"));
        assert_eq!(out.restored, 1);
    }

    #[test]
    fn whole_ndjson_restores() {
        let parts = setup();
        let masked = mask_and_register(&parts, "电话13800138000");
        let body = format!(
            "{}\n{}\n",
            serde_json::json!({"message": {"content": masked}, "done": false}),
            serde_json::json!({"message": {"content": ""}, "done": true})
        );
        let cmd = crate::cmdblock::CmdBlockEngine::new(&parts.0);
        let out = process_whole(body.as_bytes(), "application/x-ndjson", "r", &parts.1, &cmd);
        let s = String::from_utf8_lossy(&out.body);
        assert!(s.contains("13800138000"));
        // 结构仍是 NDJSON：逐行可解析
        for line in s.lines().filter(|l| !l.trim().is_empty()) {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
    }

    #[test]
    fn response_scan_finds_hallucinated_pii() {
        let parts = setup();
        // 本会话只脱敏过一个号码；回复里出现另一个 → 幻觉
        mask_and_register(&parts, "电话13800138000");
        let found = scan_response_pii(
            "我查到电话13911112222",
            "r",
            &parts.1,
            &parts.0.mask.builtin_rules,
            true, // 测试里固定保留明文
        );
        assert!(found
            .iter()
            .any(|i| i.label == "PHONE" && i.original == "13911112222"));
    }

    #[test]
    fn response_scan_ignores_known_values() {
        let parts = setup();
        let masked = mask_and_register(&parts, "电话13800138000");
        // 还原后的已知值不该被报
        let restored = crate::mask::engine::restore_final(
            &masked,
            "r",
            false,
            &parts.1,
            &mut RestoreStats::default(),
        );
        let found = scan_response_pii(
            &format!("好的 {restored}"),
            "r",
            &parts.1,
            &parts.0.mask.builtin_rules,
            true, // 测试里固定保留明文
        );
        assert!(found.is_empty(), "本会话已知值不得误报：{found:?}");
    }

    #[test]
    fn credential_redaction_in_logs() {
        let out = redact_credentials(
            "token sk-abcdefghijklmnopqrstuvwxyz012345 and password=ServerPass123!",
        );
        assert!(!out.contains("sk-abcdefghijklmnopqrstuvwxyz012345"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn content_type_gates() {
        assert!(restorable("application/json", ""));
        assert!(restorable("text/event-stream", "identity"));
        assert!(
            !restorable("text/event-stream", "gzip"),
            "压缩体在解码前不可按事件切分"
        );
        assert!(!restorable("text/plain", ""));
        assert!(is_streaming_response("text/event-stream"));
        assert!(is_streaming_response("application/x-ndjson"));
        assert!(!is_streaming_response("application/json"));
    }
}
