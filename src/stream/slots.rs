//! 三大协议的增量文本槽位识别（对齐 Python `_sse_text_slots`）。
//!
//! 每个 delta 字段必须用**独立通道**：正文与工具参数共用缓冲会把上一个字段的
//! 尾巴吐进下一个字段（字段错位/被清空）。

use serde_json::Value;

/// 槽位：(channel, 当前文本, 是否需 JSON 转义还原)
pub type Slot = (String, String, bool);

/// OpenAI chat choice 的索引（缺失时回落位置）。
fn choice_index(choice: &Value, position: usize) -> usize {
    choice
        .get("index")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(position)
}

/// Responses API 的通道键（同一 output item 的多 content part 分开）。
fn response_channel(data: &Value, kind: &str) -> String {
    let ci = data
        .get("content_index")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let oi = data
        .get("output_index")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if ci > 0 {
        format!("r{oi}.{ci}.{kind}")
    } else {
        format!("r{oi}.{kind}")
    }
}

/// 通用增量通道前缀：`c{idx}.x{字段名}` / `a{blk}.x{字段名}` / `o.message.x{字段名}`。
///
/// 各家中转的增量字段名远比三大协议文档多（`delta.tool_input`、
/// `response.custom_tool_call_input.delta` 等）。早期实现只登记白名单字段，
/// 未登记的字段落入「逐事件整树兜底」—— 而那条路径**没有跨事件缓冲**：
/// 完整占位符能还原，被上游拆成两半的则两半都还原不了，
/// 客户端（agent）直接拿到 `{{TERM_bc` 这样的残片。
///
/// 这里给已知的增量**容器**里的每个字符串字段都发一个通用通道，
/// 于是它们都能享受 `restore_channel` 的扣留/拼接能力。
pub const GENERIC_CHANNEL_PREFIX: char = 'x';

/// 已知的 OpenAI Chat `delta` 字段（这些已有专门通道，不再发通用通道）。
const CHAT_KNOWN_DELTA_FIELDS: &[&str] = &[
    "content",
    "reasoning_content",
    "reasoning",
    "reasoning_details",
    "tool_calls",
    "function_call",
    // 非文本结构字段：不需要还原，也不该为它们建扣留通道
    "role",
    "type",
    "index",
];

/// 已知的 Anthropic `content_block_delta.delta` 字段。
const ANTHROPIC_KNOWN_DELTA_FIELDS: &[&str] = &["text", "thinking", "partial_json", "type"];

/// 已知的 Responses 增量事件类型（它们已有 `r{oi}.{ci}.{kind}` 专门通道）。
const RESPONSES_KNOWN_DELTA_TYPES: &[&str] = &[
    "response.output_text.delta",
    "response.reasoning_summary_text.delta",
    "response.reasoning_text.delta",
    "response.function_call_arguments.delta",
];

/// 通道名是否属于通用增量通道（`set_slot` 据此回写原字段名）。
pub fn is_generic_field(field: &str) -> Option<&str> {
    field.strip_prefix(GENERIC_CHANNEL_PREFIX)
}

/// 列出 SSE 事件里的增量文本槽位。
pub fn text_slots(data: &Value) -> Vec<Slot> {
    let mut slots = Vec::new();
    let Some(obj) = data.as_object() else {
        return slots;
    };
    // OpenAI Chat Completions / Completions 流
    if let Some(choices) = obj.get("choices").and_then(Value::as_array) {
        for (position, c) in choices.iter().enumerate() {
            let idx = choice_index(c, position);
            if let Some(d) = c.get("delta").and_then(Value::as_object) {
                if let Some(s) = d.get("content").and_then(Value::as_str) {
                    slots.push((format!("c{idx}.content"), s.to_string(), false));
                }
                if let Some(s) = d.get("reasoning_content").and_then(Value::as_str) {
                    slots.push((format!("c{idx}.reason"), s.to_string(), false));
                }
                if let Some(s) = d.get("reasoning").and_then(Value::as_str) {
                    slots.push((format!("c{idx}.reason2"), s.to_string(), false));
                }
                // `reasoning_details: [{type:"reasoning.text", text:"..."}]`
                // （OpenRouter 等中转的推理明细，**是增量字段**，必须走槽位才能跨
                //  chunk 扣住半截占位符）。
                if let Some(rd) = d.get("reasoning_details").and_then(Value::as_array) {
                    for (n, item) in rd.iter().enumerate() {
                        if let Some(s) = item.get("text").and_then(Value::as_str) {
                            slots.push((format!("c{idx}.rd{n}"), s.to_string(), false));
                        }
                    }
                }
                if let Some(tcs) = d.get("tool_calls").and_then(Value::as_array) {
                    for (tidx, tc) in tcs.iter().enumerate() {
                        let slot_no = tc
                            .get("index")
                            .and_then(Value::as_u64)
                            .map(|v| v as usize)
                            .unwrap_or(tidx);
                        if let Some(args) = tc
                            .get("function")
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                        {
                            slots.push((format!("c{idx}.tool{slot_no}"), args.to_string(), true));
                        }
                    }
                }
                if let Some(args) = d
                    .get("function_call")
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                {
                    slots.push((format!("c{idx}.fcall"), args.to_string(), true));
                }
                // 通用兜底：`delta` 容器里其余字符串字段也当成增量通道
                // （否则它们没有跨事件扣留能力，见 `GENERIC_CHANNEL_PREFIX`）。
                for (k, v) in d {
                    if CHAT_KNOWN_DELTA_FIELDS.contains(&k.as_str()) {
                        continue;
                    }
                    if let Some(s) = v.as_str() {
                        slots.push((
                            format!("c{idx}.{GENERIC_CHANNEL_PREFIX}{k}"),
                            s.to_string(),
                            false,
                        ));
                    }
                }
            }
            if let Some(s) = c.get("text").and_then(Value::as_str) {
                slots.push((format!("c{idx}.text"), s.to_string(), false));
            }
        }
    }
    let etype = obj.get("type").and_then(Value::as_str).unwrap_or("");
    // Anthropic Messages 流
    if etype == "content_block_delta" {
        if let Some(d) = obj.get("delta").and_then(Value::as_object) {
            let blk = obj.get("index").and_then(Value::as_u64).unwrap_or(0);
            if let Some(s) = d.get("text").and_then(Value::as_str) {
                slots.push((format!("a{blk}.text"), s.to_string(), false));
            }
            if let Some(s) = d.get("thinking").and_then(Value::as_str) {
                slots.push((format!("a{blk}.think"), s.to_string(), false));
            }
            if let Some(s) = d.get("partial_json").and_then(Value::as_str) {
                slots.push((format!("a{blk}.pj"), s.to_string(), true));
            }
            // 通用兜底：其余字符串字段（如中转自创的 `input_json`/`tool_input`）。
            for (k, v) in d {
                if ANTHROPIC_KNOWN_DELTA_FIELDS.contains(&k.as_str()) {
                    continue;
                }
                if let Some(s) = v.as_str() {
                    slots.push((
                        format!("a{blk}.{GENERIC_CHANNEL_PREFIX}{k}"),
                        s.to_string(),
                        false,
                    ));
                }
            }
        }
    }
    // OpenAI Responses API 流
    if etype == "response.output_text.delta" {
        if let Some(s) = obj.get("delta").and_then(Value::as_str) {
            slots.push((response_channel(data, "text"), s.to_string(), false));
        }
    } else if etype == "response.reasoning_summary_text.delta"
        || etype == "response.reasoning_text.delta"
    {
        // Responses API 的两类思考事件：
        //   - `reasoning_summary_text.delta`：OpenAI **官方**的推理摘要流
        //   - `reasoning_text.delta`：部分中转/自建实现
        // 两者都要还原：漏掉会让占位符原样下发到客户端。
        if let Some(s) = obj.get("delta").and_then(Value::as_str) {
            slots.push((response_channel(data, "reason"), s.to_string(), false));
        }
    } else if etype == "response.function_call_arguments.delta" {
        if let Some(s) = obj.get("delta").and_then(Value::as_str) {
            slots.push((response_channel(data, "args"), s.to_string(), true));
        }
    } else if !etype.is_empty()
        && etype.ends_with(".delta")
        && !RESPONSES_KNOWN_DELTA_TYPES.contains(&etype)
    {
        // 未登记但形状相同的 Responses 增量事件（如
        // `response.custom_tool_call_input.delta`、`response.tool_input.delta`）：
        // 载荷同样是顶层 `delta` 字符串，给它发一个通用通道。
        // 通道名带上事件类型，避免不同事件的残片互相拼接。
        if let Some(s) = obj.get("delta").and_then(Value::as_str) {
            slots.push((
                format!(
                    "{}.{GENERIC_CHANNEL_PREFIX}{etype}",
                    response_channel(data, "gen")
                ),
                s.to_string(),
                etype.contains("arguments") || etype.contains("tool"),
            ));
        }
    }
    // Ollama NDJSON 增量（用 "done" 判别）
    if obj.contains_key("done") {
        if let Some(msg) = obj.get("message").and_then(Value::as_object) {
            if let Some(s) = msg.get("content").and_then(Value::as_str) {
                slots.push(("o.message.content".into(), s.to_string(), false));
            }
            // 思考内容也是**增量**字段（deepseek-r1 这类模型逐块吐 thinking），
            // 必须走槽位，否则跨 chunk 的半截占位符会原样下发。
            if let Some(s) = msg.get("thinking").and_then(Value::as_str) {
                slots.push(("o.message.thinking".into(), s.to_string(), false));
            }
            for (k, v) in msg {
                if k == "content" || k == "thinking" || k == "role" || k == "tool_calls" {
                    continue;
                }
                if let Some(s) = v.as_str() {
                    slots.push((
                        format!("o.message.{GENERIC_CHANNEL_PREFIX}{k}"),
                        s.to_string(),
                        false,
                    ));
                }
            }
        }
        if let Some(s) = obj.get("response").and_then(Value::as_str) {
            slots.push(("o.response".into(), s.to_string(), false));
        }
        // `/api/generate` 的思考字段（部分实现用 thinking 而非 response）
        if let Some(s) = obj.get("thinking").and_then(Value::as_str) {
            slots.push(("o.thinking".into(), s.to_string(), false));
        }
    }
    slots
}

/// 本事件后应结束（flush）的通道前缀。None = 全部，空 = 无。
pub fn terminal_prefixes(data: &Value) -> Option<Vec<String>> {
    let Some(obj) = data.as_object() else {
        return Some(vec![]);
    };
    let t = obj.get("type").and_then(Value::as_str).unwrap_or("");
    // Ollama NDJSON：`done: true` 是本流唯一的终止信号，全部通道收尾。
    // 缺这条时 pending 只能等流末 `push(b"")`，客户端提前断开就会丢残片。
    if obj.get("done").and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    match t {
        "message_stop"
        | "message_delta"
        | "response.completed"
        | "response.incomplete"
        | "response.failed" => return None,
        "content_block_stop" => {
            let blk = obj.get("index").and_then(Value::as_u64).unwrap_or(0);
            return Some(vec![format!("a{blk}.")]);
        }
        "response.output_text.done" => return Some(vec![response_channel(data, "text")]),
        "response.reasoning_text.done" | "response.reasoning_summary_text.done" => {
            return Some(vec![response_channel(data, "reason")]);
        }
        "response.function_call_arguments.done" => {
            return Some(vec![response_channel(data, "args")])
        }
        _ => {}
    }
    // choices[].finish_reason 存在 → 该 choice 的全部通道结束
    let mut prefixes = Vec::new();
    if let Some(choices) = obj.get("choices").and_then(Value::as_array) {
        for (position, c) in choices.iter().enumerate() {
            if c.get("finish_reason")
                .map(|f| !f.is_null())
                .unwrap_or(false)
            {
                prefixes.push(format!("c{}.", choice_index(c, position)));
            }
        }
    }
    Some(prefixes)
}

/// 按通道键写回槽位文本。
pub fn set_slot(data: &mut Value, channel: &str, text: &str) {
    // c{idx}.content / reason / reason2 / tool{n} / fcall / text
    if let Some(rest) = channel.strip_prefix('c') {
        if let Some((idx_s, field)) = rest.split_once('.') {
            let Ok(idx) = idx_s.parse::<usize>() else {
                return;
            };
            let Some(choices) = data.get_mut("choices").and_then(Value::as_array_mut) else {
                return;
            };
            for (position, c) in choices.iter_mut().enumerate() {
                let ci = c
                    .get("index")
                    .and_then(Value::as_u64)
                    .map(|v| v as usize)
                    .unwrap_or(position);
                if ci != idx {
                    continue;
                }
                match field {
                    // ⚠️ 这里必须写**槽位名**（`content`/`reason`/`reason2`），
                    // 不是 JSON 字段名。早期写的是 `reasoning_content`/`reasoning`
                    // —— 与 `text_slots` 产生的频道名对不上，于是思考内容走进 `_`
                    // 分支被静默丢弃：**还原后的文本写不回去，占位符原样下发给客户端**。
                    "content" => {
                        if let Some(d) = c.get_mut("delta").and_then(Value::as_object_mut) {
                            d.insert("content".into(), Value::String(text.into()));
                        }
                    }
                    "reason" => {
                        if let Some(d) = c.get_mut("delta").and_then(Value::as_object_mut) {
                            d.insert("reasoning_content".into(), Value::String(text.into()));
                        }
                    }
                    "reason2" => {
                        if let Some(d) = c.get_mut("delta").and_then(Value::as_object_mut) {
                            d.insert("reasoning".into(), Value::String(text.into()));
                        }
                    }
                    f if f.starts_with("rd") => {
                        let Ok(n) = f[2..].parse::<usize>() else {
                            return;
                        };
                        if let Some(rd) = c
                            .get_mut("delta")
                            .and_then(|d| d.get_mut("reasoning_details"))
                            .and_then(Value::as_array_mut)
                        {
                            if let Some(item) = rd.get_mut(n).and_then(Value::as_object_mut) {
                                item.insert("text".into(), Value::String(text.into()));
                            }
                        }
                    }
                    "text" => {
                        if let Some(o) = c.as_object_mut() {
                            o.insert("text".into(), Value::String(text.into()));
                        }
                    }
                    "fcall" => {
                        if let Some(fc) = c
                            .get_mut("delta")
                            .and_then(|d| d.get_mut("function_call"))
                            .and_then(Value::as_object_mut)
                        {
                            fc.insert("arguments".into(), Value::String(text.into()));
                        }
                    }
                    f if f.starts_with("tool") => {
                        let Ok(n) = f[4..].parse::<usize>() else {
                            return;
                        };
                        if let Some(tcs) = c
                            .get_mut("delta")
                            .and_then(|d| d.get_mut("tool_calls"))
                            .and_then(Value::as_array_mut)
                        {
                            for (tidx, tc) in tcs.iter_mut().enumerate() {
                                let slot_no = tc
                                    .get("index")
                                    .and_then(Value::as_u64)
                                    .map(|v| v as usize)
                                    .unwrap_or(tidx);
                                if slot_no == n {
                                    if let Some(f) =
                                        tc.get_mut("function").and_then(Value::as_object_mut)
                                    {
                                        f.insert("arguments".into(), Value::String(text.into()));
                                    }
                                }
                            }
                        }
                    }
                    // 通用增量通道：`x{原字段名}` → 按原字段名回写（见 `GENERIC_CHANNEL_PREFIX`）。
                    // 必须排在 `rd`/`tool` 前缀分支之后（它们更具体）。
                    f if is_generic_field(f).is_some() => {
                        let Some(name) = is_generic_field(f) else {
                            return;
                        };
                        if let Some(d) = c.get_mut("delta").and_then(Value::as_object_mut) {
                            d.insert(name.into(), Value::String(text.into()));
                        }
                    }
                    _ => {}
                }
                return;
            }
        }
        return;
    }
    // a{blk}.text / think / pj（以及通用通道 `x{原字段名}`）
    if let Some(rest) = channel.strip_prefix('a') {
        if let Some((_blk, field)) = rest.split_once('.') {
            if let Some(d) = data.get_mut("delta").and_then(Value::as_object_mut) {
                // 通用通道：`xfoo` → 原字段名 `foo`
                if let Some(name) = is_generic_field(field) {
                    d.insert(name.into(), Value::String(text.into()));
                    return;
                }
                let key = match field {
                    "think" => "thinking",
                    "pj" => "partial_json",
                    other => other,
                };
                d.insert(key.into(), Value::String(text.into()));
            }
        }
        return;
    }
    // r{oi}[.{ci}].text / reason / args
    if let Some(rest) = channel.strip_prefix('r') {
        let field = rest.rsplit('.').next().unwrap_or("");
        if let Some(o) = data.as_object_mut() {
            o.insert("delta".into(), Value::String(text.into()));
            let _ = field;
        }
        return;
    }
    // o.message.content / o.message.thinking / o.message.x{字段} / o.response / o.thinking
    if let Some(rest) = channel.strip_prefix("o.message.") {
        if let Some(msg) = data.get_mut("message").and_then(Value::as_object_mut) {
            let key = is_generic_field(rest).unwrap_or(rest);
            msg.insert(key.into(), Value::String(text.into()));
        }
    } else if channel == "o.response" {
        if let Some(o) = data.as_object_mut() {
            o.insert("response".into(), Value::String(text.into()));
        }
    } else if channel == "o.thinking" {
        if let Some(o) = data.as_object_mut() {
            o.insert("thinking".into(), Value::String(text.into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unregistered_delta_fields_get_generic_channels() {
        // D3/C6：未登记的增量字段也必须拿到独立通道，
        // 否则它们落入无跨事件缓冲的整树兜底，拆两半就永远拼不回。
        let chat = json!({"choices": [{"index": 0, "delta": {"tool_input": "abc"}}]});
        let slots = text_slots(&chat);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, "c0.xtool_input");
        // 能回写到原字段
        let mut d = chat.clone();
        set_slot(&mut d, &slots[0].0, "xyz");
        assert_eq!(d["choices"][0]["delta"]["tool_input"], "xyz");
        // 非文本结构字段不建通道
        let clean = json!({"choices": [{"index": 0, "delta": {"role": "assistant"}}]});
        assert!(text_slots(&clean).is_empty());
    }

    #[test]
    fn unregistered_responses_delta_type_gets_generic_channel() {
        let ev = json!({
            "type": "response.custom_tool_call_input.delta",
            "output_index": 0,
            "delta": "{\"p\""
        });
        let slots = text_slots(&ev);
        assert_eq!(slots.len(), 1);
        assert!(slots[0]
            .0
            .contains("xresponse.custom_tool_call_input.delta"));
        assert!(slots[0].2, "tool/arguments 类增量应按 JSON 转义还原");
        let mut d = ev.clone();
        set_slot(&mut d, &slots[0].0, "restored");
        assert_eq!(d["delta"], "restored");
    }

    #[test]
    fn ollama_done_true_is_terminal() {
        let done = json!({"message": {"content": "x"}, "done": true});
        assert!(
            terminal_prefixes(&done).is_none(),
            "done:true 应收尾全部通道"
        );
        let more = json!({"message": {"content": "x"}, "done": false});
        assert_eq!(terminal_prefixes(&more), Some(vec![]));
    }

    #[test]
    fn openai_chat_slots() {
        let d = json!({
            "choices": [{"index": 0, "delta": {
                "content": "hi", "reasoning_content": "think",
                "tool_calls": [{"index": 1, "function": {"arguments": "{\"a\""}}]
            }}]
        });
        let slots = text_slots(&d);
        let chans: Vec<&str> = slots.iter().map(|(c, _, _)| c.as_str()).collect();
        assert!(chans.contains(&"c0.content"));
        assert!(chans.contains(&"c0.reason"));
        assert!(
            chans.contains(&"c0.tool1"),
            "槽位用 tool_calls[].index 而非数组下标"
        );
        // 工具参数需转义
        let tool = slots.iter().find(|(c, _, _)| c == "c0.tool1").unwrap();
        assert!(tool.2, "tool arguments 必须走 JSON 转义还原");
    }

    #[test]
    fn anthropic_slots() {
        let d = json!({"type": "content_block_delta", "index": 1,
                       "delta": {"type": "text_delta", "text": "hi"}});
        let slots = text_slots(&d);
        assert_eq!(slots[0].0, "a1.text");
        let d2 = json!({"type": "content_block_delta", "index": 0,
                        "delta": {"partial_json": "{\"x\""}});
        let slots2 = text_slots(&d2);
        assert_eq!(slots2[0].0, "a0.pj");
        assert!(slots2[0].2);
    }

    /// 回归：OpenAI Responses API **官方**的推理摘要事件
    /// `response.reasoning_summary_text.delta` 曾完全没被识别（0 槽位），
    /// 导致该段思考内容不还原，占位符原样下发给客户端。
    #[test]
    fn responses_reasoning_summary_slots() {
        let d = json!({"type": "response.reasoning_summary_text.delta",
                       "output_index": 0, "delta": "思考中客户张三"});
        let slots = text_slots(&d);
        assert_eq!(slots.len(), 1, "官方推理摘要事件必须被识别");
        assert_eq!(slots[0].0, "r0.reason");
        assert!(!slots[0].2, "思考文本不做 JSON 转义");
        // 收尾事件也要能定位到同一通道
        let done = json!({"type": "response.reasoning_summary_text.done", "output_index": 0});
        assert_eq!(
            terminal_prefixes(&done),
            Some(vec!["r0.reason".to_string()])
        );
        // content_index 存在时仍分通道
        let d2 = json!({"type": "response.reasoning_summary_text.delta",
                        "output_index": 1, "content_index": 2, "delta": "x"});
        assert_eq!(text_slots(&d2)[0].0, "r1.2.reason");
    }

    /// 三大协议的思考 + 工具参数槽位必须全覆盖（防止后续新增字段时静默遗漏）。
    #[test]
    fn thinking_and_tool_slots_complete_coverage() {
        // Chat：reasoning_content / reasoning / tool_calls.arguments
        for (field, want) in [
            ("reasoning_content", "c0.reason"),
            ("reasoning", "c0.reason2"),
        ] {
            let d = json!({"choices": [{"delta": {field: "张三"}}]});
            assert_eq!(text_slots(&d)[0].0, want, "Chat {field} 未识别");
        }
        let tc = json!({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": "{\"name\":\"张三\"}"}}]}}]});
        let s = text_slots(&tc);
        assert_eq!(s[0].0, "c0.tool0");
        assert!(s[0].2, "工具参数必须走 JSON 转义还原");
        // Responses：output_text / reasoning_text / reasoning_summary_text / fn args
        for (t, want, esc) in [
            ("response.output_text.delta", "r0.text", false),
            ("response.reasoning_text.delta", "r0.reason", false),
            ("response.reasoning_summary_text.delta", "r0.reason", false),
            ("response.function_call_arguments.delta", "r0.args", true),
        ] {
            let d = json!({"type": t, "output_index": 0, "delta": "x"});
            let got = text_slots(&d);
            assert_eq!(got[0].0, want, "{t} 未识别");
            assert_eq!(got[0].2, esc, "{t} 转义标志不对");
        }
        // Anthropic：thinking / partial_json
        let th = json!({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "thinking_delta", "thinking": "张三"}});
        assert_eq!(text_slots(&th)[0].0, "a0.think");
        let pj = json!({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "input_json_delta", "partial_json": "{}"}});
        let s2 = text_slots(&pj);
        assert_eq!(s2[0].0, "a0.pj");
        assert!(s2[0].2, "partial_json 必须转义还原");
    }

    #[test]
    fn responses_slots_with_content_index() {
        let d = json!({"type": "response.output_text.delta", "output_index": 0,
                       "content_index": 1, "delta": "hi"});
        let slots = text_slots(&d);
        assert_eq!(slots[0].0, "r0.1.text", "多 content part 必须分开通道");
    }

    #[test]
    fn ollama_slots() {
        let d = json!({"done": false, "message": {"content": "hi"}});
        let slots = text_slots(&d);
        assert_eq!(slots[0].0, "o.message.content");
    }

    #[test]
    fn terminal_prefixes_rules() {
        assert!(terminal_prefixes(&json!({"type": "message_stop"})).is_none());
        assert_eq!(
            terminal_prefixes(&json!({"type": "content_block_stop", "index": 2})),
            Some(vec!["a2.".to_string()])
        );
        assert_eq!(
            terminal_prefixes(&json!({"choices": [{"index": 0, "finish_reason": "stop"}]})),
            Some(vec!["c0.".to_string()])
        );
        assert_eq!(
            terminal_prefixes(&json!({"choices": [{"delta": {}}]})),
            Some(vec![])
        );
    }

    #[test]
    fn set_slot_writes_back() {
        let mut d = json!({"choices": [{"index": 0, "delta": {"content": "old"}}]});
        set_slot(&mut d, "c0.content", "new");
        assert_eq!(d["choices"][0]["delta"]["content"], "new");
        let mut d2 =
            json!({"type": "content_block_delta", "index": 0, "delta": {"partial_json": "x"}});
        set_slot(&mut d2, "a0.pj", "y");
        assert_eq!(d2["delta"]["partial_json"], "y");
        let mut d3 = json!({"type": "response.output_text.delta", "delta": "a"});
        set_slot(&mut d3, "r0.text", "b");
        assert_eq!(d3["delta"], "b");
    }
}
