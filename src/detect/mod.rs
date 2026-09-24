//! 协议识别：三大 LLM 请求协议 + Unknown。
//!
//! **职责边界（PLAN D6）**：detect_protocol 只决定「用哪套脱敏/还原通道 + 哪套
//! 路径感知豁免表」，**不决定是否脱敏**。Unknown 形态在 fail_closed=true 时
//! 走整棵脱敏（豁免表退化为「无协议容器」模式），fail_closed=false 时才透传。

#![allow(dead_code)] // M6 管线接线后全部启用

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// OpenAI Chat Completions / DeepSeek / 兼容形态（顶层 messages[] + model）
    ChatCompletions,
    /// OpenAI Responses API（顶层 input / instructions）
    Responses,
    /// Anthropic Messages API（/v1/messages 形态）
    Anthropic,
    /// 无法识别（fail_closed=true 时仍整棵脱敏）
    Unknown,
}

impl Protocol {
    /// 事件字段用的小写标识。
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::ChatCompletions => "chat_completions",
            Protocol::Responses => "responses",
            Protocol::Anthropic => "anthropic",
            Protocol::Unknown => "unknown",
        }
    }
}

/// 协议探测。body_json 为解析后的 JSON（解析失败由调用方按 fail-closed 处理）。
///
/// 优先级（PLAN §3）：Anthropic > Responses > ChatCompletions > Unknown。
/// path 仅作辅助信号，body 形态是主判据。
pub fn detect_protocol(path: &str, body: Option<&Value>) -> Protocol {
    let path_lower = path.to_ascii_lowercase();
    let path_is = |needle: &str| path_lower.contains(needle);

    let Some(body) = body else {
        // 无 body / 非 JSON：仅凭路径（GET /v1/models 这类不识别为 LLM 协议）
        return Protocol::Unknown;
    };

    let obj = match body.as_object() {
        Some(o) => o,
        None => return Protocol::Unknown, // 非对象根：Unknown（fail-closed 时整棵脱敏）
    };

    let has_messages = matches!(obj.get("messages"), Some(Value::Array(m)) if !m.is_empty());
    let has_input = obj.get("input").is_some();
    let has_anthropic_version = obj
        .get("anthropic_version")
        .map(|v| v.is_string())
        .unwrap_or(false);
    let has_system_or_max_tokens = obj.contains_key("system") || obj.contains_key("max_tokens");

    // ── Anthropic 判据 ──
    // 1) body 含 anthropic_version（最可靠信号，x-api-key 客户端通常携带）
    // 2) path 含 /messages 且 body 形态吻合：messages 数组 + (system 或 max_tokens)
    //    且首条 message.role ∈ {user, assistant}
    if has_anthropic_version {
        return Protocol::Anthropic;
    }
    if path_is("/messages") && has_messages && has_system_or_max_tokens && first_role_valid(obj) {
        return Protocol::Anthropic;
    }

    // ── Responses 判据 ──
    // 顶层 input（string 或数组）且不含 messages；或 path 含 /responses
    if has_input && !has_messages {
        return Protocol::Responses;
    }
    if path_is("/responses") && (has_input || obj.contains_key("instructions")) {
        return Protocol::Responses;
    }

    // ── ChatCompletions 判据 ──
    // 顶层 messages 数组（元素含 role）且不含 input
    if has_messages && !has_input && first_role_valid(obj) {
        return Protocol::ChatCompletions;
    }
    if path_is("chat/completions") || path_is("/completions") {
        // path 辅助：body 里有任意已知字段即认可
        if obj.contains_key("model") || obj.contains_key("prompt") {
            return Protocol::ChatCompletions;
        }
    }

    Protocol::Unknown
}

/// 首条 message.role ∈ {user, assistant, system, tool}（合理的会话形态）。
fn first_role_valid(obj: &serde_json::Map<String, Value>) -> bool {
    let Some(Value::Array(msgs)) = obj.get("messages") else {
        return false;
    };
    let Some(first) = msgs.first() else {
        return false;
    };
    match first.get("role").and_then(Value::as_str) {
        Some(r) => matches!(
            r,
            "user" | "assistant" | "system" | "tool" | "function" | "developer"
        ),
        None => false,
    }
}

/// 请求是否声明流式（body.stream == true）。
pub fn is_stream_request(body: Option<&Value>) -> bool {
    body.and_then(|b| b.get("stream"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_completions_by_body() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true
        });
        assert_eq!(
            detect_protocol("/anything/at/all", Some(&body)),
            Protocol::ChatCompletions
        );
        assert!(is_stream_request(Some(&body)));
    }

    #[test]
    fn chat_completions_by_path_fallback() {
        let body = json!({"model": "gpt-4o", "prompt": "hi"});
        assert_eq!(
            detect_protocol("/v1/chat/completions", Some(&body)),
            Protocol::ChatCompletions
        );
        // 老式 completions
        let body2 = json!({"prompt": "hi"});
        assert_eq!(
            detect_protocol("/v1/completions", Some(&body2)),
            Protocol::ChatCompletions
        );
    }

    #[test]
    fn anthropic_by_version_key() {
        let body = json!({
            "anthropic_version": "2023-06-01",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100
        });
        assert_eq!(
            detect_protocol("/v1/messages", Some(&body)),
            Protocol::Anthropic
        );
        // anthropic_version 是最强信号：即使 path 不含 /messages
        assert_eq!(
            detect_protocol("/v1/anything", Some(&body)),
            Protocol::Anthropic
        );
    }

    #[test]
    fn anthropic_by_path_and_shape() {
        let body = json!({
            "model": "claude-sonnet-4-5",
            "system": "You are helpful.",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 100
        });
        assert_eq!(
            detect_protocol("/v1/messages", Some(&body)),
            Protocol::Anthropic
        );
        // path 不含 /messages → 不识别（body 形态与 ChatCompletions 太像，靠 path 区分）
        assert_eq!(
            detect_protocol("/v1/chat/completions", Some(&body)),
            Protocol::ChatCompletions
        );
    }

    #[test]
    fn anthropic_rejected_when_first_role_invalid() {
        let body = json!({
            "system": "x",
            "messages": [{"role": "weird", "content": "hi"}],
            "max_tokens": 1
        });
        assert_eq!(
            detect_protocol("/v1/messages", Some(&body)),
            Protocol::Unknown
        );
    }

    #[test]
    fn responses_by_input() {
        let body = json!({
            "model": "gpt-4o",
            "input": "tell me a joke",
            "stream": false
        });
        assert_eq!(
            detect_protocol("/v1/responses", Some(&body)),
            Protocol::Responses
        );
        // input 数组形态
        let body2 = json!({
            "model": "gpt-4o",
            "input": [{"type": "message", "role": "user", "content": "hi"}]
        });
        assert_eq!(
            detect_protocol("/weird/path", Some(&body2)),
            Protocol::Responses
        );
    }

    #[test]
    fn responses_with_instructions() {
        let body = json!({"instructions": "be brief", "input": []});
        assert_eq!(
            detect_protocol("/v1/responses", Some(&body)),
            Protocol::Responses
        );
    }

    #[test]
    fn unknown_shapes() {
        // 无 body
        assert_eq!(
            detect_protocol("/v1/chat/completions", None),
            Protocol::Unknown
        );
        // 非对象根
        assert_eq!(
            detect_protocol("/", Some(&json!([1, 2, 3]))),
            Protocol::Unknown
        );
        // 空对象
        assert_eq!(detect_protocol("/", Some(&json!({}))), Protocol::Unknown);
        // messages 为空数组（不认）
        let empty_msgs = json!({"messages": []});
        assert_eq!(detect_protocol("/", Some(&empty_msgs)), Protocol::Unknown);
        // messages 非数组
        let bad_msgs = json!({"messages": "oops"});
        assert_eq!(detect_protocol("/", Some(&bad_msgs)), Protocol::Unknown);
    }

    #[test]
    fn gemini_style_is_unknown() {
        // Gemini contents 形态不在三大协议内 → Unknown（fail_closed 时整棵脱敏）
        let body = json!({
            "contents": [{"parts": [{"text": "hi"}]}],
            "generationConfig": {"maxOutputTokens": 100}
        });
        assert_eq!(
            detect_protocol("/v1beta/models/gemini:generateContent", Some(&body)),
            Protocol::Unknown
        );
    }

    #[test]
    fn tool_loop_messages_still_chat_completions() {
        // 带 tool_calls 的 assistant + tool 响应消息
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "list files"},
                {"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "ls", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": "call_1", "content": "a.txt"}
            ]
        });
        assert_eq!(
            detect_protocol("/v1/chat/completions", Some(&body)),
            Protocol::ChatCompletions
        );
    }

    #[test]
    fn responses_tool_output_still_responses() {
        let body = json!({
            "model": "gpt-4o",
            "input": [
                {"type": "function_call", "call_id": "call_1", "name": "ls"},
                {"type": "function_call_output", "call_id": "call_1", "output": "a.txt"}
            ]
        });
        assert_eq!(
            detect_protocol("/v1/responses", Some(&body)),
            Protocol::Responses
        );
    }

    /// D6 关键断言：Unknown 不等于「透传」。此处只验证 detect 的输出；
    /// 「Unknown + fail_closed 仍整棵脱敏」的端到端断言在 M6 管线测试。
    #[test]
    fn unknown_is_just_a_channel_marker() {
        assert_eq!(
            detect_protocol("/", Some(&json!({"text": "任意内容"}))),
            Protocol::Unknown
        );
        assert_eq!(Protocol::Unknown.as_str(), "unknown");
    }
}
