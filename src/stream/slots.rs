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
    let base = if ci > 0 {
        format!("r{oi}.{ci}.{kind}")
    } else {
        format!("r{oi}.{kind}")
    };
    // 部分中转不发 output_index，多个工具调用会全部落到 r0.args 互相串流。
    // item_id 是同一事件的稳定标识；有它时并入通道，至少不会把两个工具的
    // 半截占位符拼到一起（缺失 output_index 时 r0 仍只是兜底）。
    match data
        .get("item_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        Some(id) => {
            let id: String = id.chars().take(64).collect();
            format!("{base}@{id}")
        }
        None => base,
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

/// 合并同一 delta 内 **相同 index** 的 tool_calls。
///
/// 部分中转把 id/name 与 arguments 拆成两条 `index: 0` 的条目（trace 7544），
/// 若原样下发，客户端按 index 合并时会得到 `{...}{...}`；若只修通道，跨 delta
/// 的条目数变化又会让半截占位符换通道。这里先按 index 归一化成一条逻辑条目：
/// id/name 取首个非空值，arguments 按数组顺序拼接。客户端视角等价（它本来
/// 也要按 index 拼接），但后续槽位与 pending 都变得稳定。
pub fn merge_duplicate_tool_calls(data: &mut Value) {
    let Some(choices) = data.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };
    for c in choices.iter_mut() {
        let Some(delta) = c.get_mut("delta").and_then(Value::as_object_mut) else {
            continue;
        };
        let Some(tcs) = delta.get_mut("tool_calls").and_then(Value::as_array_mut) else {
            continue;
        };
        let old = std::mem::take(tcs);
        let mut merged: Vec<Value> = Vec::new();
        let mut pos_by_index: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::new();
        for (array_pos, tc) in old.into_iter().enumerate() {
            let key = tc
                .get("index")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(array_pos);
            if let Some(&mi) = pos_by_index.get(&key) {
                merge_tool_call(&mut merged[mi], tc);
            } else {
                pos_by_index.insert(key, merged.len());
                merged.push(tc);
            }
        }
        *tcs = merged;
    }
}

fn blank_value(v: Option<&Value>) -> bool {
    match v {
        None => true,
        Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        _ => false,
    }
}

fn merge_tool_call(dst: &mut Value, src: Value) {
    let (Some(d), Some(s)) = (dst.as_object_mut(), src.as_object()) else {
        return;
    };
    for (k, v) in s {
        if k == "function" {
            let Some(sf) = v.as_object() else { continue };
            match d.get_mut("function").and_then(Value::as_object_mut) {
                Some(df) => {
                    for (fk, fv) in sf {
                        if fk == "arguments" {
                            let old = df
                                .get("arguments")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            let add = fv.as_str().unwrap_or("");
                            if !old.is_empty() || add.is_empty() {
                                df.insert("arguments".into(), Value::String(format!("{old}{add}")));
                            } else {
                                df.insert("arguments".into(), fv.clone());
                            }
                        } else if blank_value(df.get(fk)) {
                            // 首个非空值：首条 id/name 为空串时不能挡住后续有效值。
                            df.insert(fk.clone(), fv.clone());
                        }
                    }
                }
                None => {
                    d.insert("function".into(), Value::Object(sf.clone()));
                }
            }
        } else if blank_value(d.get(k)) {
            d.insert(k.clone(), v.clone());
        }
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
                    // 同一 delta 里可能有多条 **相同 index** 的 tool_calls（中转把
                    // id/name 与 arguments 拆成两条，各自 index=0）。通道必须带
                    // 数组位置，否则 set_slot 会把还原结果写进所有同 index 条目，
                    // 客户端按 index 合并后得到 `{...}{...}` 重复 JSON。
                    let mut seen: std::collections::HashMap<usize, usize> =
                        std::collections::HashMap::new();
                    for (tidx, tc) in tcs.iter().enumerate() {
                        let slot_no = tc
                            .get("index")
                            .and_then(Value::as_u64)
                            .map(|v| v as usize)
                            .unwrap_or(tidx);
                        // 无论本条是否带 arguments 都要占位：首条可能是纯
                        // id/name（无 arguments 键），否则第二条会被错当成
                        // 「第一条」，还原结果写进元数据条目、参数条目漏还原。
                        let n = seen.entry(slot_no).or_insert(0);
                        let occurrence = *n;
                        *n += 1;
                        if let Some(args) = tc
                            .get("function")
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                        {
                            let channel = if occurrence == 0 {
                                format!("c{idx}.tool{slot_no}")
                            } else {
                                format!("c{idx}.tool{slot_no}@{tidx}")
                            };
                            slots.push((channel, args.to_string(), true));
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
    // Ollama NDJSON 增量。
    //
    // 不能只用 `done` 判别：部分实现只在最后一行带 `done`，前面的增量行只有
    // `message`，漏判会让工具参数完全不走槽位（跨行拆开的参数既拦不住也写不回）。
    if obj.contains_key("done") || obj.get("message").is_some_and(Value::is_object) {
        if let Some(msg) = obj.get("message").and_then(Value::as_object) {
            if let Some(s) = msg.get("content").and_then(Value::as_str) {
                slots.push(("o.message.content".into(), s.to_string(), false));
            }
            // 思考内容也是**增量**字段（deepseek-r1 这类模型逐块吐 thinking），
            // 必须走槽位，否则跨 chunk 的半截占位符会原样下发。
            if let Some(s) = msg.get("thinking").and_then(Value::as_str) {
                slots.push(("o.message.thinking".into(), s.to_string(), false));
            }
            // Ollama/自建 NDJSON 的 `message.tool_calls[].function.arguments`
            // 同样是**增量**参数，必须走槽位：否则跨行拆开的命令既拦不住，
            // 整包 rewrite 也写不回去。
            if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
                for (n, tc) in tcs.iter().enumerate() {
                    let slot_no = tc
                        .get("index")
                        .and_then(Value::as_u64)
                        .map(|v| v as usize)
                        .unwrap_or(n);
                    if let Some(args) = tc
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(Value::as_str)
                    {
                        slots.push((format!("o.message.tool{slot_no}"), args.to_string(), true));
                    }
                }
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

/// **完成快照**里的工具参数（完整值，不是增量片段）。
///
/// 为什么必须单独识别：Responses 的 `response.function_call_arguments.done`、
/// `response.output_item.done`、`response.completed` 以及 Chat 的整包工具调用
/// 都会带上**完整** `arguments`。聚合器只接管 `.delta` 片段，快照若不走这里，
/// rewrite/block 就完全看不见它们 —— 客户端从完成事件取参数，仍拿到原值。
///
/// 返回 `(channel, 完整参数文本, 是否需转义还原)`。
pub fn snapshot_tool_slots(data: &Value) -> Vec<Slot> {
    let mut slots = Vec::new();
    let Some(obj) = data.as_object() else {
        return slots;
    };
    // Responses：`arguments` / `response.output[].arguments` / `item.arguments`
    let etype = obj.get("type").and_then(Value::as_str).unwrap_or("");
    let mut push_args = |holder: &Value, tag: &str| {
        if let Some(s) = holder.get("arguments").and_then(Value::as_str) {
            if !s.is_empty() {
                slots.push((format!("s.{tag}.arguments"), s.to_string(), true));
            }
        }
    };
    push_args(data, etype);
    if let Some(resp) = obj.get("response") {
        push_args(resp, "response");
        if let Some(out) = resp.get("output").and_then(Value::as_array) {
            for (n, item) in out.iter().enumerate() {
                push_args(item, &format!("response.output{n}"));
            }
        }
    }
    if let Some(items) = obj.get("output").and_then(Value::as_array) {
        for (n, item) in items.iter().enumerate() {
            push_args(item, &format!("output{n}"));
        }
    }
    if let Some(item) = obj.get("item") {
        push_args(item, "item");
        if let Some(fc) = item.get("function_call") {
            push_args(fc, "item.function_call");
        }
    }
    // Chat：`choices[].message.tool_calls[].function.arguments`（整包快照）
    if let Some(choices) = obj.get("choices").and_then(Value::as_array) {
        for (position, c) in choices.iter().enumerate() {
            let idx = choice_index(c, position);
            // 只认 `message`（整包快照）。`delta` 是增量片段，由 `text_slots`
            // 按通道聚合后判定 —— 在这里当快照会把半截片段（`rm -rf /`）
            // 误判成完整命令。
            let Some(msg) = c.get("message") else {
                continue;
            };
            if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
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
                        slots.push((format!("s.c{idx}.tool{slot_no}"), args.to_string(), true));
                    }
                }
            }
        }
    }
    // Ollama：`message.tool_calls[].function.arguments`
    if let Some(msg) = obj.get("message") {
        if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
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
                    slots.push((format!("s.o.tool{slot_no}"), args.to_string(), true));
                }
            }
        }
    }
    slots
}

/// 把 `snapshot_tool_slots` 的改写结果写回原位置。
pub fn set_snapshot_tool(data: &mut Value, channel: &str, text: &str) {
    let Some(tag) = channel.strip_prefix("s.") else {
        return;
    };
    // 尾部统一是 `.arguments` / `.tool{n}`
    if let Some(holder_tag) = tag.strip_suffix(".arguments") {
        let mut targets: Vec<&mut Value> = Vec::new();
        match holder_tag {
            "response" => {
                if let Some(v) = data.get_mut("response") {
                    targets.push(v);
                }
            }
            "item" => {
                if let Some(v) = data.get_mut("item") {
                    targets.push(v);
                }
            }
            "item.function_call" => {
                if let Some(v) = data
                    .get_mut("item")
                    .and_then(|i| i.get_mut("function_call"))
                {
                    targets.push(v);
                }
            }
            t if t.starts_with("response.output") => {
                if let Ok(n) = t["response.output".len()..].parse::<usize>() {
                    if let Some(v) = data
                        .get_mut("response")
                        .and_then(|r| r.get_mut("output"))
                        .and_then(|o| o.get_mut(n))
                    {
                        targets.push(v);
                    }
                }
            }
            t if t.starts_with("output") => {
                if let Ok(n) = t["output".len()..].parse::<usize>() {
                    if let Some(v) = data.get_mut("output").and_then(|o| o.get_mut(n)) {
                        targets.push(v);
                    }
                }
            }
            _ => {
                // 事件类型本身（`response.function_call_arguments.done` 等）：
                // 参数就在载荷顶层。
                if let Some(o) = data.as_object_mut() {
                    o.insert("arguments".into(), Value::String(text.into()));
                }
                return;
            }
        }
        for holder in targets {
            if let Some(o) = holder.as_object_mut() {
                o.insert("arguments".into(), Value::String(text.into()));
            }
        }
        return;
    }
    // Chat 快照：`c{idx}.tool{n}`
    if let Some(rest) = tag.strip_prefix('c') {
        if let Some((idx_s, field)) = rest.split_once('.') {
            let (Ok(idx), Some(n_s)) = (idx_s.parse::<usize>(), field.strip_prefix("tool")) else {
                return;
            };
            let Ok(n) = n_s.parse::<usize>() else { return };
            if let Some(choices) = data.get_mut("choices").and_then(Value::as_array_mut) {
                for (position, c) in choices.iter_mut().enumerate() {
                    let ci = c
                        .get("index")
                        .and_then(Value::as_u64)
                        .map(|v| v as usize)
                        .unwrap_or(position);
                    if ci != idx {
                        continue;
                    }
                    let Some(msg) = c.get_mut("message") else {
                        continue;
                    };
                    if let Some(tcs) = msg.get_mut("tool_calls").and_then(Value::as_array_mut) {
                        for (tidx, tc) in tcs.iter_mut().enumerate() {
                            let slot_no = tc
                                .get("index")
                                .and_then(Value::as_u64)
                                .map(|v| v as usize)
                                .unwrap_or(tidx);
                            if slot_no != n {
                                continue;
                            }
                            if let Some(f) = tc.get_mut("function").and_then(Value::as_object_mut) {
                                f.insert("arguments".into(), Value::String(text.into()));
                            }
                        }
                    }
                }
            }
        }
        return;
    }
    // Ollama 快照：`o.tool{n}`
    if let Some(n_s) = tag.strip_prefix("o.tool") {
        let Ok(n) = n_s.parse::<usize>() else { return };
        if let Some(tcs) = data
            .get_mut("message")
            .and_then(|m| m.get_mut("tool_calls"))
            .and_then(Value::as_array_mut)
        {
            for (tidx, tc) in tcs.iter_mut().enumerate() {
                let slot_no = tc
                    .get("index")
                    .and_then(Value::as_u64)
                    .map(|v| v as usize)
                    .unwrap_or(tidx);
                if slot_no != n {
                    continue;
                }
                if let Some(f) = tc.get_mut("function").and_then(Value::as_object_mut) {
                    f.insert("arguments".into(), Value::String(text.into()));
                }
            }
        }
    }
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
    // choices[].finish_reason 存在且**非空** → 该 choice 的全部通道结束。
    //
    // ⚠️ 空串 `""` 必须当作「尚未结束」，不能只看 `!is_null()`。
    //
    // 回归（真机 trace 定位）：部分中转 / 自建实现（vLLM、one-api 系）在**每个**
    // delta 事件里都发 `"finish_reason":""`（而不是 `null`），真正的结束信号只出现在
    // 最后一帧（`"stop"` / `"tool_calls"`）。旧实现把 `""` 当成终止，于是**每个**
    // delta 事件都让本 choice 的全部通道进入收尾态 → `restore_channel` 的
    // `final_channel=true` 分支直接 `pending.remove()`，**跨事件扣留整体失效**：
    // 被上游切成两/三截的占位符（`" IP {{"` + `"IPPUBLIC_rnjn"` + `"vs}} port 222"`）
    // 每一截都过 `restore_final`、每一截都不完整 → 一个都拼不回，残片原样下发给
    // 客户端，且 `restored/unresolved` 全 0（控制台显示 `no_sensitive_data`，静默泄漏）。
    let mut prefixes = Vec::new();
    if let Some(choices) = obj.get("choices").and_then(Value::as_array) {
        for (position, c) in choices.iter().enumerate() {
            let finished = match c.get("finish_reason") {
                None | Some(Value::Null) => false,
                Some(Value::String(s)) => !s.trim().is_empty(),
                Some(_) => true,
            };
            if finished {
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
                        // `tool{n}`：写第一条同 index 的条目；
                        // `tool{n}@{pos}`：只写数组第 pos 条（同一 delta 内重复 index）。
                        let (n_s, only_pos) = match f[4..].split_once('@') {
                            Some((a, b)) => (a, b.parse::<usize>().ok()),
                            None => (&f[4..], None),
                        };
                        let Ok(n) = n_s.parse::<usize>() else {
                            return;
                        };
                        if let Some(tcs) = c
                            .get_mut("delta")
                            .and_then(|d| d.get_mut("tool_calls"))
                            .and_then(Value::as_array_mut)
                        {
                            let mut written = false;
                            let mut fallback: Option<usize> = None;
                            for (tidx, tc) in tcs.iter_mut().enumerate() {
                                if let Some(pos) = only_pos {
                                    if tidx != pos {
                                        continue;
                                    }
                                }
                                let slot_no = tc
                                    .get("index")
                                    .and_then(Value::as_u64)
                                    .map(|v| v as usize)
                                    .unwrap_or(tidx);
                                if slot_no != n {
                                    continue;
                                }
                                // 无后缀时优先写「带 arguments 字段」的条目；
                                // 首条可能只是 id/name，不能把参数塞进去。
                                let has_args = tc
                                    .get("function")
                                    .and_then(|f| f.get("arguments"))
                                    .and_then(Value::as_str)
                                    .is_some();
                                if only_pos.is_none() && !has_args {
                                    fallback.get_or_insert(tidx);
                                    continue;
                                }
                                if let Some(f) =
                                    tc.get_mut("function").and_then(Value::as_object_mut)
                                {
                                    f.insert("arguments".into(), Value::String(text.into()));
                                }
                                written = true;
                                if only_pos.is_none() {
                                    break;
                                }
                            }
                            if !written {
                                if let Some(tidx) = fallback {
                                    if let Some(tc) = tcs.get_mut(tidx) {
                                        if let Some(f) =
                                            tc.get_mut("function").and_then(Value::as_object_mut)
                                        {
                                            f.insert(
                                                "arguments".into(),
                                                Value::String(text.into()),
                                            );
                                        }
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
        // `o.message.tool{n}`：写回 `message.tool_calls[n].function.arguments`
        if let Some(n_s) = rest.strip_prefix("tool") {
            if let Ok(n) = n_s.parse::<usize>() {
                if let Some(tcs) = data
                    .get_mut("message")
                    .and_then(|m| m.get_mut("tool_calls"))
                    .and_then(Value::as_array_mut)
                {
                    for (i, tc) in tcs.iter_mut().enumerate() {
                        let slot_no = tc
                            .get("index")
                            .and_then(Value::as_u64)
                            .map(|v| v as usize)
                            .unwrap_or(i);
                        if slot_no != n {
                            continue;
                        }
                        if let Some(f) = tc.get_mut("function").and_then(Value::as_object_mut) {
                            f.insert("arguments".into(), Value::String(text.into()));
                        }
                    }
                }
                return;
            }
        }
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
    fn duplicate_tool_call_index_does_not_duplicate_arguments() {
        // 中转把 id/name 与 arguments 拆成两条 index=0 的 tool_calls；
        // 先合并成一条逻辑条目，再按单通道还原。
        let mut v = json!({"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "call_1", "function": {"name": "glob", "arguments": ""}},
            {"index": 0, "function": {"arguments": "{\"pattern\":\"x\"}"}}
        ]}}]});
        merge_duplicate_tool_calls(&mut v);
        let tcs = v["choices"][0]["delta"]["tool_calls"].as_array().unwrap();
        assert_eq!(tcs.len(), 1, "重复 index 必须合并为一条: {v}");
        assert_eq!(tcs[0]["function"]["arguments"], "{\"pattern\":\"x\"}");
        let slots = text_slots(&v);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, "c0.tool0");
        set_slot(&mut v, &slots[0].0, "RESTORED");
        assert_eq!(
            v["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "RESTORED"
        );
    }

    #[test]
    fn merge_handles_first_entry_without_arguments_field() {
        // A1：首条只有 id/name（无 arguments 键）时，第二条才是参数。
        let mut v = json!({"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "", "function": {"name": ""}},
            {"index": 0, "id": "call_B", "function": {"name": "glob", "arguments": "{\"pattern\":\"y\"}"}}
        ]}}]});
        merge_duplicate_tool_calls(&mut v);
        let tcs = v["choices"][0]["delta"]["tool_calls"].as_array().unwrap();
        assert_eq!(tcs.len(), 1);
        // 首个非空值：空 id/name 不得挡住第二条有效值
        assert_eq!(tcs[0]["id"], "call_B");
        assert_eq!(tcs[0]["function"]["name"], "glob");
        assert_eq!(tcs[0]["function"]["arguments"], "{\"pattern\":\"y\"}");
        let slots = text_slots(&v);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, "c0.tool0");
    }

    #[test]
    fn responses_channels_use_item_id_when_output_index_missing() {
        let a = json!({"type": "response.function_call_arguments.delta", "item_id": "item_a", "delta": "x"});
        let b = json!({"type": "response.function_call_arguments.delta", "item_id": "item_b", "delta": "y"});
        let sa = text_slots(&a);
        let sb = text_slots(&b);
        assert_eq!(sa.len(), 1);
        assert_eq!(sb.len(), 1);
        assert_ne!(sa[0].0, sb[0].0, "不同 item_id 不得共用 r0.args 通道");
        assert!(sa[0].0.starts_with("r0.args@"));
    }

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

    /// 回归（真机 trace 定位）：`"finish_reason":""` 不是终止信号。
    ///
    /// 部分中转 / 自建实现（vLLM、one-api 系）在**每个** delta 事件里都用空串占位，
    /// 只有最后一帧才是 `"stop"` / `"tool_calls"`。旧实现 `!is_null()` 把 `""` 判成
    /// 终止，导致每个 delta 都让通道进入收尾态 → 半截占位符不再扣留（`pending`
    /// 永不写入）→ 被拆开的占位符永久拼不回、残片直出客户端。
    #[test]
    fn empty_finish_reason_is_not_terminal() {
        let delta = json!({"choices": [{"index": 0, "delta": {"reasoning_content": "x"},
                                        "finish_reason": ""}]});
        assert_eq!(
            terminal_prefixes(&delta),
            Some(vec![]),
            "空串 finish_reason 是「尚未结束」，不得让通道提前收尾"
        );
        // 真正的终止帧（非空）仍必须收尾
        for fr in ["stop", "tool_calls", "length"] {
            let done = json!({"choices": [{"index": 0, "delta": {}, "finish_reason": fr}]});
            assert_eq!(
                terminal_prefixes(&done),
                Some(vec!["c0.".to_string()]),
                "{fr}"
            );
        }
        // 空白串同样不算终止；null / 键缺失同理
        for v in [json!(""), json!("  "), json!(null)] {
            let ev = json!({"choices": [{"index": 0, "delta": {}, "finish_reason": v}]});
            assert_eq!(terminal_prefixes(&ev), Some(vec![]), "{v}");
        }
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
