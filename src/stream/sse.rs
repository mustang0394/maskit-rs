//! SSE 流式还原：分帧 + 槽位改写 + 跨 chunk 扣留 + 聚合（M7）。
//!
//! 对齐 Python `_sse_stream_factory` / `_restore_sse_event` / `_flush_pending`:
//! - 事件按 `\n\n` 分帧（CRLF → LF 归一）
//! - 缓冲超限（4MB）强制按最后换行切分
//! - per-channel 半截占位符扣留（`_PARTIAL_RX`，上限 48 字节）
//! - 流末补发（`_flush_pending`）
//! - **中途块无输出时绝不发空 chunk**（Python 版实测踩坑：空块 = chunked 终止块）

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::Incoming;

use crate::mask::engine::{restore_final, RestoreStats};
use crate::mask::placeholder;
use crate::mask::session::SessionStore;
use crate::stream::slots;

/// SSE 半事件缓冲上限（对齐 Python `_SSE_BUF_MAX` = 4MB）。
pub const SSE_BUF_MAX: usize = 4 * 1024 * 1024;

/// 流式还原状态。
pub struct StreamState {
    pub framing: Framing,
    /// 未凑齐分隔符的缓冲
    pub buf: String,
    /// 收集的还原后文本（供审计/响应扫描；上限 256KB）
    pub kept: String,
    pub keep_max: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Sse,
    Ndjson,
}

impl StreamState {
    pub fn new(framing: Framing) -> Self {
        Self {
            framing,
            buf: String::new(),
            kept: String::new(),
            keep_max: 256 * 1024,
        }
    }

    /// 处理一块数据，返回应当下发的字节（可能为空）。
    ///
    /// `final_chunk` = true 表示流末（对应 Python `data == b""`）。
    pub fn push(
        &mut self,
        data: &[u8],
        sid: &str,
        store: &SessionStore,
    ) -> (Vec<u8>, RestoreStats) {
        let mut stats = RestoreStats::default();
        let text = String::from_utf8_lossy(data).to_string();
        self.buf.push_str(&text.replace("\r\n", "\n"));

        let mut out = String::new();
        let delim = match self.framing {
            Framing::Sse => "\n\n",
            Framing::Ndjson => "\n",
        };
        // 提取完整帧
        while let Some(idx) = self.buf.find(delim) {
            let frame: String = self.buf[..idx].to_string();
            self.buf = self.buf[idx + delim.len()..].to_string();
            let restored = self.restore_frame(&frame, sid, store, &mut stats, false);
            out.push_str(&restored);
            out.push_str(delim);
        }
        // 缓冲超限：强制切分（对齐 Python：按最后换行切，无换行整段处理）
        if self.buf.len() > SSE_BUF_MAX {
            if let Some(idx) = self.buf.rfind('\n') {
                let frame: String = self.buf[..idx].to_string();
                self.buf = self.buf[idx + 1..].to_string();
                out.push_str(&self.restore_frame(&frame, sid, store, &mut stats, true));
                out.push_str(delim);
            } else {
                let frame = std::mem::take(&mut self.buf);
                out.push_str(&self.restore_frame(&frame, sid, store, &mut stats, true));
                out.push_str(delim);
            }
        }
        // 流末：吐出残余 + flush pending
        if data.is_empty() {
            if !self.buf.is_empty() {
                let frame = std::mem::take(&mut self.buf);
                out.push_str(&self.restore_frame(&frame, sid, store, &mut stats, true));
            }
            out.push_str(&flush_pending(sid, store, self.framing, &mut stats));
        }
        self.keep(&out);
        (out.into_bytes(), stats)
    }

    fn keep(&mut self, text: &str) {
        if self.kept.len() < self.keep_max {
            let room = self.keep_max - self.kept.len();
            let take = text.len().min(room);
            // 按字符边界截断
            let mut end = take;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            self.kept.push_str(&text[..end]);
        }
    }

    /// 还原一帧（SSE 事件块或 NDJSON 行）。
    fn restore_frame(
        &self,
        frame: &str,
        sid: &str,
        store: &SessionStore,
        stats: &mut RestoreStats,
        final_frame: bool,
    ) -> String {
        match self.framing {
            Framing::Ndjson => restore_ndjson_line(frame, sid, store, stats, final_frame),
            Framing::Sse => restore_sse_event(frame, sid, store, stats, final_frame),
        }
    }
}

/// 还原一个 SSE 事件块（可能含多行）。
pub fn restore_sse_event(
    block: &str,
    sid: &str,
    store: &SessionStore,
    stats: &mut RestoreStats,
    final_frame: bool,
) -> String {
    let mut out_lines: Vec<String> = Vec::new();
    for line in block.split('\n') {
        let stripped = line.trim_end_matches('\r');
        if let Some(payload) = stripped.strip_prefix("data:") {
            let payload = payload.strip_prefix(' ').unwrap_or(payload);
            if payload.trim() == "[DONE]" {
                let tail = flush_pending(sid, store, Framing::Sse, stats);
                if !tail.is_empty() {
                    out_lines.push(String::new());
                    out_lines.extend(tail.trim_end_matches('\n').split('\n').map(str::to_string));
                    out_lines.push(String::new());
                }
                out_lines.push(line.to_string());
                continue;
            }
            let Ok(data) = serde_json::from_str::<serde_json::Value>(payload) else {
                // 非 JSON 载荷：整段走 restore（channel=raw）
                out_lines.push(format!(
                    "data: {}",
                    restore_final(payload, sid, false, store, stats)
                ));
                continue;
            };
            if !data.is_object() {
                out_lines.push(line.to_string());
                continue;
            }
            // 槽位还原
            let terminal = slots::terminal_prefixes(&data);
            let mut restored = data.clone();
            // 收集每个槽位的置空模板（用于 flush）
            let slot_list = slots::text_slots(&restored);
            if !slot_list.is_empty() {
                for (channel, text, escape) in &slot_list {
                    let channel_final = final_frame
                        || terminal.is_none()
                        || terminal
                            .as_ref()
                            .map(|p| p.iter().any(|prefix| channel.starts_with(prefix.as_str())))
                            .unwrap_or(false);
                    let r =
                        restore_channel(text, sid, store, stats, channel, *escape, channel_final);
                    slots::set_slot(&mut restored, channel, &r);
                }
                if let Some(obj) = restored.as_object() {
                    // 记录模板（收尾补发用）
                    for (channel, _, _) in &slot_list {
                        let has_pending = store
                            .get(sid)
                            .map(|s| s.pending.contains_key(channel))
                            .unwrap_or(false);
                        if has_pending {
                            if let Some(mut s) = store.get_mut(sid) {
                                s.flush_tmpl.insert(
                                    channel.clone(),
                                    serde_json::to_string(obj).unwrap_or_default(),
                                );
                            }
                        }
                    }
                }
            } else {
                // 非增量事件：整树还原
                let mut st = RestoreStats::default();
                restored = crate::mask::tree::restore_tree(&restored, sid, store, &mut st, 0);
                stats.restored += st.restored;
                stats.unresolved += st.unresolved;
                stats.degraded += st.degraded;
            }
            out_lines.push(format!(
                "data: {}",
                serde_json::to_string(&restored).unwrap_or_else(|_| payload.to_string())
            ));
            continue;
        }
        out_lines.push(line.to_string());
    }
    out_lines.join("\n")
}

/// 还原 NDJSON 单行。
pub fn restore_ndjson_line(
    line: &str,
    sid: &str,
    store: &SessionStore,
    stats: &mut RestoreStats,
    final_frame: bool,
) -> String {
    let stripped = line.trim();
    if stripped.is_empty() {
        return line.to_string();
    }
    let Ok(obj) = serde_json::from_str::<serde_json::Value>(stripped) else {
        return line.to_string();
    };
    if !obj.is_object() {
        return line.to_string();
    }
    let mut restored = obj.clone();
    let slot_list = slots::text_slots(&restored);
    if !slot_list.is_empty() {
        for (channel, text, escape) in &slot_list {
            let r = restore_channel(text, sid, store, stats, channel, *escape, final_frame);
            slots::set_slot(&mut restored, channel, &r);
        }
        if let Some(mut s) = store.get_mut(sid) {
            for (channel, _, _) in &slot_list {
                if s.pending.contains_key(channel) {
                    s.flush_tmpl.insert(
                        channel.clone(),
                        serde_json::to_string(&restored).unwrap_or_default(),
                    );
                }
            }
        }
        return serde_json::to_string(&restored).unwrap_or_else(|_| line.to_string());
    }
    let mut st = RestoreStats::default();
    let tree_restored = crate::mask::tree::restore_tree(&restored, sid, store, &mut st, 0);
    stats.restored += st.restored;
    stats.unresolved += st.unresolved;
    stats.degraded += st.degraded;
    let _ = restored;
    let _ = &mut restored;
    serde_json::to_string(&tree_restored).unwrap_or_else(|_| line.to_string())
}

/// 单通道还原（含半截占位符扣留）。
fn restore_channel(
    text: &str,
    sid: &str,
    store: &SessionStore,
    stats: &mut RestoreStats,
    channel: &str,
    escape: bool,
    final_channel: bool,
) -> String {
    let Some(mut s) = store.get_mut(sid) else {
        return text.to_string();
    };
    let buf = format!(
        "{}{}",
        s.pending.get(channel).cloned().unwrap_or_default(),
        text
    );
    let confirmed: String = if final_channel {
        s.pending.remove(channel);
        buf
    } else {
        // 半截占位符扣留
        let rx = placeholder::partial_rx();
        match rx.find(&buf) {
            Some(m) if m.end() == buf.len() && m.len() <= placeholder::PARTIAL_MAX => {
                let keep = m.as_str().to_string();
                let confirmed = buf[..m.start()].to_string();
                s.pending.insert(channel.to_string(), keep);
                confirmed
            }
            _ => {
                s.pending.remove(channel);
                buf
            }
        }
    };
    drop(s);
    if confirmed.is_empty() {
        return String::new();
    }
    restore_final(&confirmed, sid, escape, store, stats)
}

/// 流末补发各通道滞留的半截占位符（对齐 `_flush_pending`）。
pub fn flush_pending(
    sid: &str,
    store: &SessionStore,
    framing: Framing,
    stats: &mut RestoreStats,
) -> String {
    let Some(s) = store.get(sid) else {
        return String::new();
    };
    if s.pending.is_empty() {
        return String::new();
    }
    let pending: Vec<(String, String)> = s
        .pending
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let tmpl: std::collections::HashMap<String, String> = s
        .flush_tmpl
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    drop(s);
    // block 模式已命中的会话不再补发
    if store.get(sid).map(|s| s.cmd_blocked).unwrap_or(false) {
        if let Some(mut s) = store.get_mut(sid) {
            s.pending.clear();
            s.flush_tmpl.clear();
        }
        return String::new();
    }
    let mut out = String::new();
    for (channel, leftover) in pending {
        if let Some(mut s) = store.get_mut(sid) {
            s.pending.remove(&channel);
            s.flush_tmpl.remove(&channel);
        }
        if leftover.is_empty() {
            continue;
        }
        let escape = tmpl
            .get(&channel)
            .and_then(|t| serde_json::from_str::<serde_json::Value>(t).ok())
            .map(|v| {
                slots::text_slots(&v)
                    .into_iter()
                    .find(|(c, _, _)| c == &channel)
                    .map(|(_, _, e)| e)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let restored = restore_final(&leftover, sid, escape, store, stats);
        if restored.is_empty() {
            continue;
        }
        // 用模板克隆事件（保证 SSE 结构合法）
        if let Some(tmpl_json) = tmpl.get(&channel) {
            if let Some(evt) = build_flush_frame(tmpl_json, &channel, &restored, framing) {
                out.push_str(&evt);
                continue;
            }
        }
        out.push_str(&wrap_bare_flush(&restored, framing));
    }
    out
}

/// 用最后一个同通道事件做模板补发（对齐 `_build_flush_event` / `_build_flush_line`）。
fn build_flush_frame(
    tmpl_json: &str,
    channel: &str,
    leftover: &str,
    framing: Framing,
) -> Option<String> {
    let mut data: serde_json::Value = serde_json::from_str(tmpl_json).ok()?;
    let slot_list = slots::text_slots(&data);
    let mut hit = false;
    for (ch, _t, _e) in &slot_list {
        if ch == channel {
            slots::set_slot(&mut data, channel, leftover);
            hit = true;
        } else {
            slots::set_slot(&mut data, ch, "");
        }
    }
    if !hit {
        return None;
    }
    if let Some(choices) = data.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for c in choices {
            if let Some(o) = c.as_object_mut() {
                o.insert("finish_reason".into(), serde_json::Value::Null);
            }
        }
    }
    if data.get("done").is_some() {
        if let Some(o) = data.as_object_mut() {
            o.insert("done".into(), serde_json::Value::Bool(false));
        }
    }
    let body = serde_json::to_string(&data).ok()?;
    Some(match framing {
        Framing::Ndjson => format!("{body}\n"),
        Framing::Sse => {
            let prefix = data
                .get("type")
                .and_then(|t| t.as_str())
                .map(|t| format!("event: {t}\n"))
                .unwrap_or_default();
            format!("{prefix}data: {body}\n\n")
        }
    })
}

/// 无模板时的兜底（保持帧合法，不裸拼文本）。
fn wrap_bare_flush(text: &str, framing: Framing) -> String {
    match framing {
        Framing::Ndjson => format!("{}\n", serde_json::json!({"text": text})),
        Framing::Sse => format!("data: {}\n\n", serde_json::json!({"text": text})),
    }
}

/// 内容类型判定（对齐 `_is_ndjson_ct`）。
pub fn is_ndjson_ct(ct: &str) -> bool {
    let c = ct.to_ascii_lowercase();
    c.contains("x-ndjson")
        || c.contains("ndjson")
        || c.contains("jsonl")
        || c.contains("x-jsonlines")
}

/// 聚合上游 body 为完整字节（非流式路径 + M6 转发用）。
pub async fn aggregate_stream(mut body: Incoming) -> Result<Bytes, String> {
    let mut buf = BytesMut::with_capacity(16 * 1024);
    while let Some(frame) = body.frame().await {
        let f = frame.map_err(|e| format!("读取上游响应失败: {e}"))?;
        if let Some(d) = f.data_ref() {
            // 上限 64MB（响应体防护）
            if buf.len() + d.len() > 64 * 1024 * 1024 {
                return Err("response_too_large".into());
            }
            buf.extend_from_slice(d);
        }
    }
    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::mask::engine::CustomWords;

    fn setup() -> (Config, SessionStore, CustomWords) {
        let mut cfg = Config::default();
        for k in crate::config::ALL_BUILTIN_RULES {
            cfg.mask.builtin_rules.insert(k.to_string(), true);
        }
        cfg.mask.custom_words.insert("张三".into(), "NAME".into());
        let store = SessionStore::new();
        store.new_session("s");
        let custom = CustomWords::build(&cfg);
        (cfg, store, custom)
    }

    fn mask_text(parts: &(Config, SessionStore, CustomWords), text: &str) -> String {
        let ctx = crate::mask::engine::MaskCtx::new(&parts.0, &parts.1, "s".into(), &parts.2);
        ctx.mask(text)
    }

    #[test]
    fn sse_event_restores_and_keeps_framing() {
        let parts = setup();
        let masked = mask_text(&parts, "客户张三");
        let token = placeholder::placeholder_rx()
            .find(&masked)
            .unwrap()
            .as_str()
            .to_string();
        let event = format!(
            "data: {}",
            serde_json::json!({"choices": [{"delta": {"content": format!("你好{token}")}}]})
        );
        let mut stats = RestoreStats::default();
        let out = restore_sse_event(&event, "s", &parts.1, &mut stats, false);
        assert!(out.starts_with("data: "), "SSE 帧结构保留");
        let payload = out.strip_prefix("data: ").unwrap();
        let v: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(v["choices"][0]["delta"]["content"], "你好张三");
        assert_eq!(stats.restored, 1);
    }

    #[test]
    fn sse_partial_token_held_then_flushed() {
        let parts = setup();
        let masked = mask_text(&parts, "客户张三");
        let token = placeholder::placeholder_rx()
            .find(&masked)
            .unwrap()
            .as_str()
            .to_string();
        let half = token.len() / 2;

        let mut st = StreamState::new(Framing::Sse);
        // 第一块：半截占位符
        let ev1 = format!(
            "data: {}\n\n",
            serde_json::json!({"choices": [{"delta": {"content": format!("你好{}", &token[..half])}}]})
        );
        let (out1, _) = st.push(ev1.as_bytes(), "s", &parts.1);
        let s1 = String::from_utf8_lossy(&out1);
        assert!(!s1.contains(&token[..half]), "半截占位符不得外泄");
        assert!(s1.contains("你好"));
        // 第二块：补齐
        let ev2 = format!(
            "data: {}\n\n",
            serde_json::json!({"choices": [{"delta": {"content": format!("{}在", &token[half..])}}]})
        );
        let (out2, _) = st.push(ev2.as_bytes(), "s", &parts.1);
        let s2 = String::from_utf8_lossy(&out2);
        assert!(s2.contains("张三在"), "跨 chunk 拼合还原：{s2}");
        // 流末
        let (out3, _) = st.push(b"", "s", &parts.1);
        let _ = out3;
    }

    #[test]
    fn sse_empty_midstream_produces_no_output() {
        let parts = setup();
        let mut st = StreamState::new(Framing::Sse);
        // 事件被 TCP 边界切开：前半段凑不出 \n\n → 输出必须为空
        let ev = format!(
            "data: {}\n\n",
            serde_json::json!({"choices": [{"delta": {"content": "hello"}}]})
        );
        let (a, _) = st.push(&ev.as_bytes()[..15], "s", &parts.1);
        assert!(
            a.is_empty(),
            "半个事件不得产出字节（否则会成为 chunked 终止块）"
        );
        let (b, _) = st.push(&ev.as_bytes()[15..], "s", &parts.1);
        assert!(!b.is_empty());
    }

    #[test]
    fn crlf_framing_normalized() {
        let parts = setup();
        let mut st = StreamState::new(Framing::Sse);
        let ev = format!(
            "data: {}\r\n\r\n",
            serde_json::json!({"choices": [{"delta": {"content": "第一段"}}]})
        );
        let (out, _) = st.push(ev.as_bytes(), "s", &parts.1);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("第一段"), "CRLF 首事件必须立即下发");
    }

    #[test]
    fn ndjson_line_restore() {
        let parts = setup();
        let masked = mask_text(&parts, "客户张三");
        let token = placeholder::placeholder_rx()
            .find(&masked)
            .unwrap()
            .as_str()
            .to_string();
        let line =
            serde_json::json!({"message": {"content": format!("你好{token}")}, "done": false})
                .to_string();
        let mut stats = RestoreStats::default();
        let out = restore_ndjson_line(&line, "s", &parts.1, &mut stats, false);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["message"]["content"], "你好张三");
    }

    #[test]
    fn ndjson_holds_incomplete_line() {
        let parts = setup();
        let mut st = StreamState::new(Framing::Ndjson);
        let (a, _) = st.push(br#"{"message": {"content": "half"#, "s", &parts.1);
        assert!(a.is_empty(), "整行未到齐不得产出");
        let (b, _) = st.push(b"\"}}\n", "s", &parts.1);
        assert!(String::from_utf8_lossy(&b).contains("half"));
    }

    #[test]
    fn sse_trailing_partial_flushed_with_template() {
        let parts = setup();
        // 手工放一个半截占位符 + 模板
        {
            let token = "{{NAME_bcdfgh}}";
            let mut s = parts.1.get_mut("s").unwrap();
            s.rev.insert(token.into(), "张三".into());
            s.pending.insert("c0.content".into(), "{{NAME_ab".into());
            s.flush_tmpl.insert(
                "c0.content".into(),
                serde_json::json!({"id": "c1", "choices": [{"delta": {"content": ""}}]})
                    .to_string(),
            );
        }
        let mut stats = RestoreStats::default();
        let out = flush_pending("s", &parts.1, Framing::Sse, &mut stats);
        assert!(out.contains("{{NAME_ab"), "残留必须补发");
        // 结构合法（可 JSON 解析）
        let payload = out
            .lines()
            .find(|l| l.starts_with("data: "))
            .unwrap()
            .strip_prefix("data: ")
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(v["id"], "c1", "补发沿用同通道模板");
        assert_eq!(v["choices"][0]["delta"]["content"], "{{NAME_ab");
    }

    #[test]
    fn ndjson_ct_detection() {
        for ct in [
            "application/x-ndjson",
            "application/ndjson; charset=utf-8",
            "application/jsonl",
            "application/x-jsonlines",
        ] {
            assert!(is_ndjson_ct(ct), "{ct}");
        }
        for ct in ["application/json", "text/event-stream", "text/plain", ""] {
            assert!(!is_ndjson_ct(ct), "{ct}");
        }
    }
}
