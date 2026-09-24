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
                    _ => {}
                }
                return;
            }
        }
        return;
    }
    // a{blk}.text / think / pj
    if let Some(rest) = channel.strip_prefix('a') {
        if let Some((_blk, field)) = rest.split_once('.') {
            if let Some(d) = data.get_mut("delta").and_then(Value::as_object_mut) {
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
    // o.message.content / o.message.thinking / o.response / o.thinking
    if channel == "o.message.content" {
        if let Some(msg) = data.get_mut("message").and_then(Value::as_object_mut) {
            msg.insert("content".into(), Value::String(text.into()));
        }
    } else if channel == "o.message.thinking" {
        if let Some(msg) = data.get_mut("message").and_then(Value::as_object_mut) {
            msg.insert("thinking".into(), Value::String(text.into()));
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
