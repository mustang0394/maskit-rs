//! 流式 / 非流式还原覆盖：**逐事件形态枚举**，防止占位符漏还原后下发到客户端。
//!
//! 真机报告过「思考内容里的占位符原样返回给客户端」。根因是三类，都在这里守：
//!   1. `slots::set_slot` 里思考频道的 match 分支写的是 JSON 字段名而不是槽位名，
//!      于是 `reason` / `reason2` 落进 `_` 分支被静默丢弃（还原结果写不回去）；
//!   2. 事件里只要有任一可识别槽位，**其余字段就完全不还原** —— 而各家实现的
//!      字段名远比协议文档多（Ollama `message.thinking`、OpenRouter
//!      `delta.reasoning_details[]`、中转塞在顶层的字段…）；
//!   3. 增量字段没登记成槽位 → 跨 chunk 的半截占位符拼不回来。
//!
//! 用枚举而不是逐条 if：新增协议字段时，这里会直接失败。

use maskit_rs::mask::session::{token_taken, Session, SessionStore};
use maskit_rs::stream::sse::{Framing, StreamState};

fn setup() -> (SessionStore, String) {
    let store = SessionStore::new();
    store.new_session("s");
    let taken = token_taken();
    let mut sess = Session::default();
    store.remember(&mut sess, "13800138000", "PHONE", &taken);
    if let Some(mut s) = store.get_mut("s") {
        s.fwd = sess.fwd.clone();
        s.rev = sess.rev.clone();
        s.labels = sess.labels.clone();
    }
    let tok = store.get("s").unwrap().fwd["13800138000"].clone();
    (store, tok)
}

/// 把一组事件喂进流式状态机，返回下发字节。
fn run_stream(store: &SessionStore, framing: Framing, events: &[&str]) -> String {
    let mut st = StreamState::new(framing);
    let mut out = Vec::new();
    for e in events {
        let (o, _) = st.push(e.as_bytes(), "s", store);
        out.extend_from_slice(&o);
    }
    let (o, _) = st.push(b"", "s", store);
    out.extend_from_slice(&o);
    String::from_utf8_lossy(&out).to_string()
}

#[test]
fn every_streaming_event_shape_restores() {
    let (store, tok) = setup();
    let p = |tpl: &str| tpl.replace("TOK", &tok);

    // 每条用例：(名字, framing, 事件列表)
    let cases: Vec<(&str, Framing, Vec<String>)> = vec![
        // ── OpenAI Chat Completions 流 ──
        (
            "openai delta.content",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"电话 TOK\"}}]}\n\n")],
        ),
        (
            "openai delta.reasoning_content",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"电话 TOK\"}}]}\n\n")],
        ),
        (
            "openai delta.reasoning",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning\":\"电话 TOK\"}}]}\n\n")],
        ),
        (
            "openai content + reasoning 同事件",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"正文\",\"reasoning_content\":\"电话 TOK\"}}]}\n\n")],
        ),
        (
            "openai delta.reasoning_details（OpenRouter 风格）",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"正文\",\"reasoning_details\":[{\"type\":\"reasoning.text\",\"text\":\"电话 TOK\"}]}}]}\n\n")],
        ),
        (
            "openai delta.tool_calls.arguments",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"p\\\":\\\"TOK\\\"}\"}}]}}]}\n\n")],
        ),
        (
            "openai delta.content + tool_calls.arguments 同事件",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"好\",\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"p\\\":\\\"TOK\\\"}\"}}]}}]}\n\n")],
        ),
        (
            "openai delta.function_call.arguments",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"function_call\":{\"arguments\":\"{\\\"p\\\":\\\"TOK\\\"}\"}}}]}\n\n")],
        ),
        (
            "openai choices[].message（非 delta，部分中转这样发）",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"message\":{\"content\":\"电话 TOK\"}}]}\n\n")],
        ),
        (
            "openai delta.content + 顶层额外文本字段",
            Framing::Sse,
            vec![p("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"正文\"}}],\"system_fingerprint\":\"TOK\"}\n\n")],
        ),
        // ── Anthropic ──
        (
            "anthropic content_block_delta.text",
            Framing::Sse,
            vec![p("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"电话 TOK\"}}\n\n")],
        ),
        (
            "anthropic content_block_delta.thinking",
            Framing::Sse,
            vec![p("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"电话 TOK\"}}\n\n")],
        ),
        (
            "anthropic content_block_delta.partial_json",
            Framing::Sse,
            vec![p("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"p\\\":\\\"TOK\\\"}\"}}\n\n")],
        ),
        (
            "anthropic content_block_start（带初始 text）",
            Framing::Sse,
            vec![p("data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"电话 TOK\"}}\n\n")],
        ),
        (
            "anthropic content_block_start（tool_use 带完整 input）",
            Framing::Sse,
            vec![p("data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"f\",\"input\":{\"p\":\"TOK\"}}}\n\n")],
        ),
        (
            "anthropic message_start（带初始 content）",
            Framing::Sse,
            vec![p("data: {\"type\":\"message_start\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"电话 TOK\"}]}}\n\n")],
        ),
        (
            "anthropic text + thinking 同事件",
            Framing::Sse,
            vec![p("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"正文\",\"thinking\":\"电话 TOK\"}}\n\n")],
        ),
        // ── Responses API ──
        (
            "responses output_text.delta",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"电话 TOK\"}\n\n")],
        ),
        (
            "responses reasoning_summary_text.delta",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.reasoning_summary_text.delta\",\"output_index\":0,\"delta\":\"电话 TOK\"}\n\n")],
        ),
        (
            "responses reasoning_text.delta",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.reasoning_text.delta\",\"output_index\":0,\"delta\":\"电话 TOK\"}\n\n")],
        ),
        (
            "responses function_call_arguments.delta",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"{\\\"p\\\":\\\"TOK\\\"}\"}\n\n")],
        ),
        (
            "responses output_text.done（带全文 text）",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.output_text.done\",\"output_index\":0,\"text\":\"电话 TOK\"}\n\n")],
        ),
        (
            "responses function_call_arguments.done（带全文 arguments）",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"arguments\":\"{\\\"p\\\":\\\"TOK\\\"}\"}\n\n")],
        ),
        (
            "responses reasoning_summary_text.done（带全文 text）",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.reasoning_summary_text.done\",\"output_index\":0,\"text\":\"电话 TOK\"}\n\n")],
        ),
        (
            "responses output_item.added（function_call 带 arguments）",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"c\",\"name\":\"f\",\"arguments\":\"{\\\"p\\\":\\\"TOK\\\"}\"}}\n\n")],
        ),
        (
            "responses output_item.added（reasoning 带 summary）",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"reasoning\",\"summary\":[{\"type\":\"summary_text\",\"text\":\"电话 TOK\"}]}}\n\n")],
        ),
        (
            "responses completed（含完整 output）",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"电话 TOK\"}]}]}}\n\n")],
        ),
        (
            "responses output_text.delta + 同事件额外文本",
            Framing::Sse,
            vec![p("data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"正文\",\"item_id\":\"TOK\"}\n\n")],
        ),
        // ── Ollama NDJSON ──
        (
            "ollama message.content",
            Framing::Ndjson,
            vec![p("{\"message\":{\"role\":\"assistant\",\"content\":\"电话 TOK\"},\"done\":false}\n")],
        ),
        (
            "ollama message.thinking",
            Framing::Ndjson,
            vec![p("{\"message\":{\"role\":\"assistant\",\"thinking\":\"电话 TOK\"},\"done\":false}\n")],
        ),
        (
            "ollama content + thinking 同消息",
            Framing::Ndjson,
            vec![p("{\"message\":{\"role\":\"assistant\",\"content\":\"正文\",\"thinking\":\"电话 TOK\"},\"done\":false}\n")],
        ),
        (
            "ollama message.tool_calls",
            Framing::Ndjson,
            vec![p("{\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"f\",\"arguments\":{\"p\":\"TOK\"}}}]},\"done\":false}\n")],
        ),
        (
            "ollama response（/api/generate）",
            Framing::Ndjson,
            vec![p("{\"response\":\"电话 TOK\",\"done\":false}\n")],
        ),
    ];

    let mut leaks = Vec::new();
    for (name, framing, events) in &cases {
        let refs: Vec<&str> = events.iter().map(String::as_str).collect();
        let out = run_stream(&store, *framing, &refs);
        let leaked = out.contains(&tok);
        let restored = out.contains("13800138000");
        println!(
            "{} {name}\n     输出: {}",
            if leaked {
                "❌ 泄漏"
            } else if restored {
                "✅ 已还原"
            } else {
                "⚠ 无占位符?"
            },
            out.replace('\n', "⏎").chars().take(150).collect::<String>()
        );
        if leaked {
            leaks.push(*name);
        }
    }
    println!("\n==== 共 {} 条泄漏 ====", leaks.len());
    for l in &leaks {
        println!("  - {l}");
    }
    assert!(
        leaks.is_empty(),
        "有 {} 条事件形态泄漏占位符（见上方 ❌ 列表）",
        leaks.len()
    );
}

#[test]
fn every_non_stream_shape_restores() {
    let (store, tok) = setup();
    let shapes: Vec<(&str, String)> = vec![
        (
            "openai message.reasoning_content",
            format!(
                r#"{{"choices":[{{"message":{{"content":"正文","reasoning_content":"电话 {tok}"}}}}]}}"#
            ),
        ),
        (
            "openai message.reasoning",
            format!(r#"{{"choices":[{{"message":{{"reasoning":"电话 {tok}"}}}}]}}"#),
        ),
        (
            "openai message.reasoning_details",
            format!(
                r#"{{"choices":[{{"message":{{"reasoning_details":[{{"type":"reasoning.text","text":"电话 {tok}"}}]}}}}]}}"#
            ),
        ),
        (
            "openai tool_calls.arguments",
            format!(
                r#"{{"choices":[{{"message":{{"tool_calls":[{{"function":{{"name":"f","arguments":"{{\"p\":\"{tok}\"}}"}}}}]}}}}]}}"#
            ),
        ),
        (
            "anthropic content[].thinking",
            format!(r#"{{"content":[{{"type":"thinking","thinking":"电话 {tok}"}}]}}"#),
        ),
        (
            "anthropic tool_use.input",
            format!(r#"{{"content":[{{"type":"tool_use","name":"f","input":{{"p":"{tok}"}}}}]}}"#),
        ),
        (
            "anthropic content[].signature（不期望还原，仅看不报错）",
            format!(r#"{{"content":[{{"type":"thinking","signature":"{tok}"}}]}}"#),
        ),
        (
            "responses output[].summary[].text",
            format!(
                r#"{{"output":[{{"type":"reasoning","summary":[{{"type":"summary_text","text":"电话 {tok}"}}]}}]}}"#
            ),
        ),
        (
            "responses output[].content[].text",
            format!(
                r#"{{"output":[{{"type":"message","content":[{{"type":"output_text","text":"电话 {tok}"}}]}}]}}"#
            ),
        ),
        (
            "responses function_call.arguments",
            format!(
                r#"{{"output":[{{"type":"function_call","name":"f","arguments":"{{\"p\":\"{tok}\"}}"}}]}}"#
            ),
        ),
        (
            "responses 顶层 output_text",
            format!(r#"{{"output_text":"电话 {tok}"}}"#),
        ),
        (
            "ollama message.thinking",
            format!(
                r#"{{"message":{{"role":"assistant","content":"正文","thinking":"电话 {tok}"}},"done":true}}"#
            ),
        ),
        (
            "ollama message.tool_calls（结构化 arguments）",
            format!(
                r#"{{"message":{{"tool_calls":[{{"function":{{"name":"f","arguments":{{"p":"{tok}"}}}}}}]}},"done":true}}"#
            ),
        ),
        (
            "gemini parts[].functionCall.args",
            format!(
                r#"{{"candidates":[{{"content":{{"parts":[{{"functionCall":{{"name":"f","args":{{"p":"{tok}"}}}}}}]}}}}]}}"#
            ),
        ),
    ];
    let mut leaks = Vec::new();
    for (name, raw) in &shapes {
        let v: serde_json::Value = serde_json::from_str(raw).expect("fixture 必须是合法 JSON");
        let mut st = Default::default();
        let out = maskit_rs::mask::tree::restore_tree(&v, "s", &store, &mut st, 0);
        let s = serde_json::to_string(&out).unwrap();
        let leaked = s.contains(&tok);
        println!(
            "{} {name}\n     {s}",
            if leaked {
                "❌ 泄漏"
            } else {
                "✅ 已还原"
            }
        );
        if leaked {
            leaks.push(*name);
        }
    }
    println!("\n==== 非流式泄漏 {} 条 ====", leaks.len());
    for l in &leaks {
        println!("  - {l}");
    }
    assert!(leaks.is_empty(), "非流式有 {} 条泄漏", leaks.len());
}

/// 跨 chunk 拆分：占位符被切成两半，必须扣住后拼合（新增的增量字段尤其重要）。
#[test]
fn split_placeholder_across_chunks_restores() {
    let (store, tok) = setup();
    let half = tok.len() / 2;
    let (a, b) = tok.split_at(half);
    let cases: Vec<(&str, Framing, String, String)> = vec![
        (
            "openai reasoning_content 拆两半",
            Framing::Sse,
            format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\"电话 {a}\"}}}}]}}\n\n"),
            format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_content\":\"{b}\"}}}}]}}\n\n"),
        ),
        (
            "openai reasoning_details 拆两半",
            Framing::Sse,
            format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_details\":[{{\"text\":\"电话 {a}\"}}]}}}}]}}\n\n"),
            format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"reasoning_details\":[{{\"text\":\"{b}\"}}]}}}}]}}\n\n"),
        ),
        (
            "ollama thinking 拆两半",
            Framing::Ndjson,
            format!("{{\"message\":{{\"thinking\":\"电话 {a}\"}},\"done\":false}}\n"),
            format!("{{\"message\":{{\"thinking\":\"{b}\"}},\"done\":false}}\n"),
        ),
        (
            "anthropic thinking 拆两半",
            Framing::Sse,
            format!("data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"thinking\":\"电话 {a}\"}}}}\n\n"),
            format!("data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"thinking\":\"{b}\"}}}}\n\n"),
        ),
        (
            "responses reasoning_summary 拆两半",
            Framing::Sse,
            format!("data: {{\"type\":\"response.reasoning_summary_text.delta\",\"output_index\":0,\"delta\":\"电话 {a}\"}}\n\n"),
            format!("data: {{\"type\":\"response.reasoning_summary_text.delta\",\"output_index\":0,\"delta\":\"{b}\"}}\n\n"),
        ),
    ];
    let mut leaks = Vec::new();
    for (name, framing, c1, c2) in &cases {
        let mut st = StreamState::new(*framing);
        let mut out = Vec::new();
        let (o, _) = st.push(c1.as_bytes(), "s", &store);
        out.extend_from_slice(&o);
        let (o, _) = st.push(c2.as_bytes(), "s", &store);
        out.extend_from_slice(&o);
        let (o, _) = st.push(b"", "s", &store);
        out.extend_from_slice(&o);
        let s = String::from_utf8_lossy(&out).to_string();
        let leaked = s.contains(a) || s.contains(&tok);
        let restored = s.contains("13800138000");
        println!(
            "{} {name}\n     {}",
            if leaked {
                "❌ 泄漏半截/整串"
            } else if restored {
                "✅ 已还原"
            } else {
                "⚠ 无"
            },
            s.replace('\n', "⏎")
        );
        if leaked {
            leaks.push(*name);
        }
    }
    println!("\n==== 拆分泄漏 {} 条 ====", leaks.len());
    for l in &leaks {
        println!("  - {l}");
    }
    assert!(leaks.is_empty(), "拆分场景有 {} 条泄漏", leaks.len());
}

// ---------------------------------------------------------------------------
// 回归：本轮修复的 8 类「脱敏正常但还原有缺漏」缺陷
// ---------------------------------------------------------------------------

/// D3/C6：未登记的增量字段（中转自创字段名）也必须能跨事件扣留半截占位符。
///
/// 回归：`text_slots` 早期只登记白名单字段，未登记字段落入「逐事件整树兜底」，
/// 而那条路径**没有跨事件缓冲** —— 占位符被上游拆成两半时两半都还原不了，
/// agent 直接拿到 `{{TERM_bc` 这样的残片。
#[test]
fn unregistered_incremental_fields_hold_split_placeholder() {
    let (store, tok) = setup();
    let half = tok.len() / 2;
    let (a, b) = tok.split_at(half);

    // (名字, framing, 事件1, 事件2) —— 字段名全是不在白名单里的“中转自创”字段
    let cases: Vec<(&str, Framing, String, String)> = vec![
        (
            "responses 自定义 tool 输入增量事件",
            Framing::Sse,
            format!("data: {{\"type\":\"response.custom_tool_call_input.delta\",\"output_index\":0,\"delta\":\"{a}\"}}\n\n"),
            format!("data: {{\"type\":\"response.custom_tool_call_input.delta\",\"output_index\":0,\"delta\":\"{b}\"}}\n\n"),
        ),
        (
            "chat delta.tool_input",
            Framing::Sse,
            format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_input\":\"{a}\"}}}}]}}\n\n"),
            format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_input\":\"{b}\"}}}}]}}\n\n"),
        ),
        (
            "anthropic delta.input_json",
            Framing::Sse,
            format!("data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"input_json\":\"{a}\"}}}}\n\n"),
            format!("data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"input_json\":\"{b}\"}}}}\n\n"),
        ),
        (
            "ollama 自创增量字段",
            Framing::Ndjson,
            format!("{{\"message\":{{\"explain\":\"{a}\"}},\"done\":false}}\n"),
            format!("{{\"message\":{{\"explain\":\"{b}\"}},\"done\":false}}\n"),
        ),
    ];
    let mut leaks = Vec::new();
    for (name, framing, c1, c2) in &cases {
        let mut st = StreamState::new(*framing);
        let mut out = Vec::new();
        for chunk in [c1, c2] {
            let (o, _) = st.push(chunk.as_bytes(), "s", &store);
            out.extend_from_slice(&o);
        }
        let (o, _) = st.push(b"", "s", &store);
        out.extend_from_slice(&o);
        let s = String::from_utf8_lossy(&out).to_string();
        if s.contains(a) || s.contains(b) || s.contains(&tok) {
            leaks.push(*name);
            println!("❌ {name}\n     {}", s.replace('\n', "⏎"));
        } else {
            println!("✅ {name}\n     {}", s.replace('\n', "⏎"));
        }
    }
    assert!(leaks.is_empty(), "未登记增量字段泄漏半截占位符: {leaks:?}");
}

/// D4：终止事件（`finish_reason` / `message_stop` 等）必须**在终止帧之前**
/// 把滞留的残片补发出去。
///
/// 回归：`terminal_prefixes` 早期只用于给 `restore_channel` 传 `final_channel`，
/// 补发只在 `[DONE]` 与流末触发 —— 而客户端普遍在 `finish_reason` 处就结束解析、
/// 停止读取，一旦提前断开，`push(b"")` 永不执行，被扣住的尾巴**彻底丢失**。
#[test]
fn terminal_event_flushes_pending_before_finish_reason() {
    let (store, tok) = setup();
    // `{}` 的结尾 `}` 会被 partial_rx 当作可能的残片扣留 → arguments 先被置空
    let start = format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{{\"name\":\"f\",\"arguments\":\"{}\"}}}}]}}}}]}}\n\n",
        "{}"
    );
    let finish =
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n";

    let mut st = StreamState::new(Framing::Sse);
    let mut out = String::new();
    for chunk in [start.as_str(), finish] {
        let (o, _) = st.push(chunk.as_bytes(), "s", &store);
        out.push_str(&String::from_utf8_lossy(&o));
    }
    println!("{}", out.replace('\n', "⏎"));

    let finish_pos = out
        .find("\"finish_reason\":\"tool_calls\"")
        .expect("应有终止帧");
    let args_pos = out
        .find("\"arguments\":\"{}\"")
        .expect("参数必须在终止帧之前下发");
    assert!(
        args_pos < finish_pos,
        "半截参数补发必须排在终止帧之前，否则 agent 在 finish_reason 处组装 tool_call 时拿到空参数:\n{out}"
    );
    assert!(!out.contains(&tok));
}

/// D5/C1：裸形态（无花括号）残片也必须扣留。
///
/// 回归：`partial_rx` 早期只认以花括号开头的残片，而宽松遍是认 `LABEL_suffix`
/// 裸形态的 —— 拆两半时两半都被直接下发，且永远拼不回。
#[test]
fn braceless_partial_token_is_held_and_restored() {
    let (store, tok) = setup();
    let bare = tok.trim_matches('{').trim_matches('}'); // TERM_xxxxxx
    let (a, b) = bare.split_at(bare.len() - 3);
    let ev1 = format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"电话 {a}\"}}}}]}}\n\n"
    );
    let ev2 =
        format!("data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{b}\"}}}}]}}\n\n");

    let mut st = StreamState::new(Framing::Sse);
    let mut out = String::new();
    for chunk in [ev1.as_str(), ev2.as_str()] {
        let (o, _) = st.push(chunk.as_bytes(), "s", &store);
        out.push_str(&String::from_utf8_lossy(&o));
    }
    let (o, _) = st.push(b"", "s", &store);
    out.push_str(&String::from_utf8_lossy(&o));
    println!("{}", out.replace('\n', "⏎"));
    assert!(!out.contains(a), "裸形态前半截泄漏: {out}");
    assert!(out.contains("13800138000"), "裸形态占位符必须还原: {out}");
}

/// R2：跨 chunk 被切开的 UTF-8 多字节字符不能被替换字符打坏。
///
/// 回归：早期对每个 chunk 独立 `from_utf8_lossy`，3 字节汉字被切开时两半各变成
/// 一个 U+FFFD，正文出现**永久乱码**。
#[test]
fn split_multibyte_utf8_survives_chunk_boundary() {
    let (store, _tok) = setup();
    // 事件里含中文（原生 UTF-8，serde_json 不转义），在“中”字中间切开
    let text =
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"汉字测试\"}}]}\n\n".to_string();
    let bytes = text.as_bytes();
    let mid = bytes
        .windows(3)
        .position(|w| w == "汉".as_bytes())
        .expect("fixture 应含中文字符")
        + 1; // 汉字中间

    let mut st = StreamState::new(Framing::Sse);
    let mut out = Vec::new();
    for part in [&bytes[..mid], &bytes[mid..]] {
        let (o, _) = st.push(part, "s", &store);
        out.extend_from_slice(&o);
    }
    let (o, _) = st.push(b"", "s", &store);
    out.extend_from_slice(&o);
    let s = String::from_utf8_lossy(&out).to_string();
    println!("{}", s.replace('\n', "⏎"));
    assert!(!s.contains('\u{FFFD}'), "跨 chunk 汉字被打成替换字符: {s}");
    assert!(s.contains("汉字测试"), "正文必须完整保留: {s}");
}

/// D4 补遗：`terminal_prefixes` 返回 `None` 的终止事件
///（`message_stop` / `response.completed` 等）必须收尾**全部**通道。
///
/// 回归：初版 `flush_on_terminal` 用 `?` 把 `None` 当“非终止事件”直接
/// 跳过，恰好漏掉最常见的一类终止路径（客户端在
/// response.completed 处就停止读取 → `push(b"")` 永不执行 → 残片彻底丢失）。
#[test]
fn terminal_event_flushes_held_fragment_without_stream_end() {
    let (store, tok) = setup();
    let half = tok.len() / 2;
    let a = &tok[..half];
    // 只喂到 response.completed。**不**调 `push(b"")`，
    // 模拟客户端在终止事件后立即停止读取。
    let events = [
        format!("data: {{\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"电话 {a}\"}}\n\n"),
        "data: {\"type\":\"response.completed\",\"response\":{\"output\":[]}}\n\n".to_string(),
    ];
    let mut st = StreamState::new(Framing::Sse);
    let mut out = String::new();
    for e in &events {
        let (o, _) = st.push(e.as_bytes(), "s", &store);
        out.push_str(&String::from_utf8_lossy(&o));
    }
    println!("{}", out.replace('\n', "⏎"));
    // 半截 token 无法还原，但**必须被补发**（而不是等流末）。
    assert!(
        out.contains(a),
        "终止事件必须把滞留残片补发出去，否则客户端提前断开就永久丢失: {out}"
    );
    // 且不得残留 pending（避免流末再补一次，造成重复）
    let left = store.get("s").map(|s| s.pending.len()).unwrap_or(0);
    assert_eq!(left, 0, "补发后 pending 应为空");
}

/// NDJSON 流式的 `done:true` 必须当场收尾全部通道（不能等流末 `push(b"")`）。
#[test]
fn ndjson_done_true_flushes_without_stream_end() {
    let (store, tok) = setup();
    let a = &tok[..tok.len() / 2];
    let lines = [
        format!("{{\"message\":{{\"content\":\"电话 {a}\"}},\"done\":false}}\n"),
        "{\"message\":{\"content\":\"\"},\"done\":true}\n".to_string(),
    ];
    let mut st = StreamState::new(Framing::Ndjson);
    let mut out = String::new();
    for l in &lines {
        let (o, _) = st.push(l.as_bytes(), "s", &store);
        out.push_str(&String::from_utf8_lossy(&o));
    }
    println!("{}", out.replace('\n', "⏎"));
    assert!(out.contains(a), "done:true 必须补发残片: {out}");
    assert_eq!(
        store.get("s").map(|s| s.pending.len()).unwrap_or(0),
        0,
        "补发后 pending 应为空"
    );
}
