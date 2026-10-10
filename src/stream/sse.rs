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
    /// 不完整的 UTF-8 尾部字节（跨 chunk 被切开的字符）
    pub utf8_tail: Vec<u8>,
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
            utf8_tail: Vec::new(),
            kept: String::new(),
            keep_max: 256 * 1024,
        }
    }

    /// 把一块字节解码成字符串，**保留尾部不完整的 UTF-8 序列**到下一块。
    ///
    /// 回归：早期对每个 chunk 独立 `from_utf8_lossy(data)`。上游 JSON 载荷里是
    /// 原生 UTF-8（`serde_json` 不转义非 ASCII），一个 3 字节汉字被 TCP / HTTP
    /// chunk 边界劈成两半时，两半各变成一个 `U+FFFD` —— 还原后的正文出现
    /// **永久乱码**，与本网关的占位符无关，任何还原遍都救不回。
    ///
    /// 这里只拼字节、不丢字节：前缀用 `from_utf8_lossy` 解（真·非法字节仍按
    /// 替换字符处理，语义不变），尾部 1-3 字节的不完整序列留待下一块。
    fn decode_chunk(&mut self, data: &[u8]) -> String {
        let mut bytes: Vec<u8> = std::mem::take(&mut self.utf8_tail);
        bytes.extend_from_slice(data);
        let mut cut = bytes.len();
        // 从末尾回退最多 3 字节，找不完整序列的起点（UTF-8 最长 4 字节）
        for back in 1..=3usize.min(bytes.len()) {
            let i = bytes.len() - back;
            let b = bytes[i];
            if b & 0x80 == 0 {
                break; // ASCII：本字节完整，前面不会是被截断的序列
            }
            let need = if b >> 5 == 0b110 {
                2
            } else if b >> 4 == 0b1110 {
                3
            } else if b >> 3 == 0b11110 {
                4
            } else {
                continue; // 续字节（10xxxxxx）：继续向前找
            };
            if bytes.len() - i < need {
                cut = i; // 本序列还差字节 → 扣到下一块
            }
            break;
        }
        self.utf8_tail = bytes[cut..].to_vec();
        String::from_utf8_lossy(&bytes[..cut]).to_string()
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
        // 流末（`data` 空）时把残留的不完整字节按替换字符吐出去，不留挂账。
        let text = if data.is_empty() && !self.utf8_tail.is_empty() {
            let tail = std::mem::take(&mut self.utf8_tail);
            String::from_utf8_lossy(&tail).to_string()
        } else {
            self.decode_chunk(data)
        };
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
            // 终止事件之前的滞留补发（见下方 `terminal` 处理说明）：必须在
            // 本事件文本之前吐出，否则客户端在终止事件处就结束解析，残片丢失。
            if !final_frame {
                if let Some(prepend) = flush_on_terminal(&data, sid, store, Framing::Sse, stats) {
                    out_lines.push(String::new());
                    out_lines.extend(
                        prepend
                            .trim_end_matches('\n')
                            .split('\n')
                            .map(str::to_string),
                    );
                    out_lines.push(String::new());
                }
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
                // ── 槽位之外的同事件文本也必须还原 ──
                //
                // 回归（真机报告）：思考内容里的占位符原样下发给客户端。根因有两个：
                //   ① 已知增量字段写错了频道名（见 `slots::set_slot`）；
                //   ② **事件里只要有任一可识别槽位，其余字段就完全不还原** ——
                //      而各家实现的字段名远比三大协议文档多：Ollama 的
                //      `message.thinking`、OpenRouter 的 `delta.reasoning_details[]`、
                //      中转塞在事件顶层的 `system_fingerprint`/`text`/`item_id` 等。
                //      逐个字段名去列举就是打地鼠，所以这里补一道**整树兜底**。
                //
                // 为什么安全：槽位值此时已被换成还原后的文本（无可还原占位符），
                // 且被扣住的半截尾巴存在 `pending` 里而不在树上，所以这遍历对槽位
                // 是无害的空转。已知小瑕疵：若槽位里是一个**查不到映射**的幻占位符，
                // 它会同时被槽位与本次遍历各计一次 `unresolved`（计数偏高一点，
                // 不影响下发内容）。
                let mut st = RestoreStats::default();
                restored = crate::mask::tree::restore_tree(&restored, sid, store, &mut st, 0);
                stats.restored += st.restored;
                stats.degraded += st.degraded;
                stats.unresolved += st.unresolved;
                for s in st.samples {
                    if stats.samples.len() < 5 && !stats.samples.contains(&s) {
                        stats.samples.push(s);
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

/// 终止事件（message_stop / response.completed / content_block_stop / finish_reason）
/// 到达时，先把各通道滞留的半截占位符补发出去。
///
/// 为什么必须在**终止事件本身之前**吐出：`flush_pending` 早期只在 `[DONE]` 载荷与
/// 流末（`push(b"")`）触发，而客户端普遍在 `finish_reason` / `message_stop` 处就
/// 结束解析、停止读取 —— 一旦它提前断开，`push(b"")` 永不执行，被扣住的尾巴
/// **彻底丢失**（不是「晚到」，是没了）。
///
/// 只在本事件确实是终止事件时触发。返回应当插在本事件之前的补发文本。
///
/// `terminal_prefixes` 的**三态**必须严格区分(这里踩过两次坑):
///
/// * `None`         → **全部通道**收尾(`message_stop` / `message_delta` /
///   `response.completed|incomplete|failed`)
/// * `Some(vec![])` → 本事件**不终止任何通道**(普通 delta 事件)
/// * `Some([..])`   → 只终止列出的通道
///
/// 早期用 `?` 把 `None` 当「非终止」跳过,恰漏掉最常见的一类终止路径;
/// 改成 `is_empty()` 又把 `Some(vec![])` 错当「全部」,导致每个普通 delta
/// 都把残片提前吐出去。两者都错。
fn flush_on_terminal(
    data: &serde_json::Value,
    sid: &str,
    store: &SessionStore,
    framing: Framing,
    stats: &mut RestoreStats,
) -> Option<String> {
    let (prefixes, all) = match slots::terminal_prefixes(data) {
        None => (Vec::new(), true),
        Some(list) if list.is_empty() => return None,
        Some(list) => (list, false),
    };
    let matches = |ch: &str| all || prefixes.iter().any(|p| ch.starts_with(p.as_str()));
    let has_pending = store
        .get(sid)
        .map(|s| s.pending.keys().any(|ch| matches(ch)))
        .unwrap_or(false);
    if !has_pending {
        return None;
    }
    // `flush_pending_matching` 的空前缀列表语义 = 全部通道
    let scope: &[String] = if all { &[] } else { &prefixes };
    let tail = flush_pending_matching(sid, store, framing, stats, scope);
    if tail.is_empty() {
        None
    } else {
        Some(tail)
    }
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
    let mut restored_before = String::new();
    let slot_list = slots::text_slots(&restored);
    if !slot_list.is_empty() {
        for (channel, text, escape) in &slot_list {
            let r = restore_channel(text, sid, store, stats, channel, *escape, final_frame);
            slots::set_slot(&mut restored, channel, &r);
        }
        // 槽位之外的同事件文本也要还原（见 `restore_sse_event` 里的同段说明）：
        // 一条 NDJSON 里可能同时带 content + thinking + 结构化 tool_calls。
        let mut st = RestoreStats::default();
        restored = crate::mask::tree::restore_tree(&restored, sid, store, &mut st, 0);
        stats.restored += st.restored;
        stats.degraded += st.degraded;
        stats.unresolved += st.unresolved;
        for s in st.samples {
            if stats.samples.len() < 5 && !stats.samples.contains(&s) {
                stats.samples.push(s);
            }
        }
        // 终止/帧末:先把滞留的残片补发到本行之前(见 `flush_on_terminal` 说明)
        //
        // 不按 `final_frame` 门控:NDJSON 流式路径下 `final_frame` 通常为 false，
        // 而 Ollama 的 `done:true` 就是这一流的终止行 —— 漏了它就只能等
        // `push(b"")`，客户端提前断开就丢残片。非终止行会被 `flush_on_terminal`
        // 自身短路返回（`terminal_prefixes` 返回 `Some(vec![])`）。
        if let Some(pre) = flush_on_terminal(&obj, sid, store, Framing::Ndjson, stats) {
            restored_before.push_str(pre.trim_end_matches('\n'));
            restored_before.push('\n');
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
        return format!(
            "{}{}",
            restored_before,
            serde_json::to_string(&restored).unwrap_or_else(|_| line.to_string())
        );
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
    flush_pending_matching(sid, store, framing, stats, &[])
}

/// 只补发**匹配给定通道前缀**的滞留通道（`prefixes` 为空 = 全部）。
///
/// 终止事件（`content_block_stop` 等）只需收尾自己那一段，不能把其它仍在
/// 生成中的通道一起提前吐出去 —— 那会让后续事件的文本错位。
pub fn flush_pending_matching(
    sid: &str,
    store: &SessionStore,
    framing: Framing,
    stats: &mut RestoreStats,
    prefixes: &[String],
) -> String {
    let matches = |channel: &str| {
        prefixes.is_empty() || prefixes.iter().any(|p| channel.starts_with(p.as_str()))
    };
    let Some(s) = store.get(sid) else {
        return String::new();
    };
    if s.pending.is_empty() {
        return String::new();
    }
    let pending: Vec<(String, String)> = s
        .pending
        .iter()
        .filter(|(k, _)| matches(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if pending.is_empty() {
        return String::new();
    }
    let tmpl: std::collections::HashMap<String, String> = s
        .flush_tmpl
        .iter()
        .filter(|(k, _)| matches(k))
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
