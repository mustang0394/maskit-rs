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
