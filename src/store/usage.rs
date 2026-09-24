//! token 用量提取（对齐 Python `shield_defaults.extract_usage`）。
//!
//! **只统计 token 数量，不做价格/费用计算**（用户明确要求：去掉价格逻辑，降低复杂度）。
//!
//! 支持三种响应形态：
//! - OpenAI chat/completions 非流式：顶层 `usage.{prompt_tokens,completion_tokens}`
//! - Anthropic messages：`usage.{input_tokens,output_tokens}`（含 SSE 的 message_start/message_delta）
//! - OpenAI Responses：`response.usage.{input_tokens,output_tokens}`
//!
//! 用量是**累计计数**：只更新本次出现的字段，不相加、不把缺失字段清零
//! （SSE 分片里 usage 会逐步补齐）。

use serde::{Deserialize, Serialize};

/// 一次响应里提取到的 token 用量。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }
    pub fn is_empty(&self) -> bool {
        self.prompt_tokens == 0 && self.completion_tokens == 0
    }
    /// 合并另一份采样（同一次响应的后续分片）。
    pub fn merge(&mut self, other: &Usage) {
        if other.prompt_tokens > 0 {
            self.prompt_tokens = other.prompt_tokens;
        }
        if other.completion_tokens > 0 {
            self.completion_tokens = other.completion_tokens;
        }
    }
}

/// 从单条 SSE 事件的 JSON 负载里提取 usage（尽力而为，认不出来就返回空）。
pub fn extract_usage_from_event(data: &serde_json::Value) -> Usage {
    let mut out = Usage::default();
    // 顶层 usage
    collect(data.get("usage"), &mut out);
    // Anthropic: message_start.message.usage / message_delta.usage
    if out.is_empty() {
        if let Some(msg) = data.get("message") {
            collect(msg.get("usage"), &mut out);
        }
    }
    // OpenAI Responses: response.completed.response.usage
    if out.is_empty() {
        if let Some(resp) = data.get("response") {
            collect(resp.get("usage"), &mut out);
        }
    }
    // Cohere / 兼容形态：meta.tokens
    if out.is_empty() {
        if let Some(meta) = data.get("meta") {
            collect(meta.get("tokens"), &mut out);
        }
    }
    out
}

/// 从响应 body（整包 JSON 或 SSE 文本）里提取 usage。
pub fn extract_usage(body: &str) -> Usage {
    let mut total = Usage::default();
    // 先按整包 JSON 试
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        let u = extract_usage_from_event(&v);
        if !u.is_empty() {
            return u;
        }
    }
    // SSE / NDJSON：逐行累加（后出现的非零值覆盖，取流末的最终计数）
    for line in body.lines() {
        let payload = line
            .strip_prefix("data:")
            .map(str::trim)
            .or_else(|| line.trim().strip_prefix('{').map(|_| line.trim()))
            .unwrap_or("");
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
            total.merge(&extract_usage_from_event(&v));
        }
    }
    total
}

/// 从 `usage` 对象里读字段（认 4 个别名：input/output 与 prompt/completion）。
fn collect(u: Option<&serde_json::Value>, out: &mut Usage) {
    let Some(u) = u.and_then(|v| v.as_object()) else {
        return;
    };
    let get = |keys: &[&str]| -> Option<u64> {
        for k in keys {
            if let Some(v) = u.get(*k).and_then(|x| x.as_i64()) {
                if v >= 0 {
                    return Some(v as u64);
                }
            }
        }
        None
    };
    if let Some(v) = get(&["prompt_tokens", "input_tokens"]) {
        out.prompt_tokens = v;
    }
    if let Some(v) = get(&["completion_tokens", "output_tokens"]) {
        out.completion_tokens = v;
    }
    // 只有 total_tokens 时按全算输入侧（统计口径可解释：总量不丢）
    if out.is_empty() {
        if let Some(v) = get(&["total_tokens"]) {
            out.prompt_tokens = v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_nonstream_usage() {
        let body = r#"{"usage":{"prompt_tokens":11,"completion_tokens":22},"choices":[]}"#;
        assert_eq!(
            extract_usage(body),
            Usage {
                prompt_tokens: 11,
                completion_tokens: 22
            }
        );
    }

    #[test]
    fn anthropic_usage() {
        let body = r#"{"usage":{"input_tokens":10,"output_tokens":8}}"#;
        assert_eq!(
            extract_usage(body),
            Usage {
                prompt_tokens: 10,
                completion_tokens: 8
            }
        );
    }

    #[test]
    fn responses_api_usage() {
        let body = r#"{"type":"response.completed","response":{"usage":{"input_tokens":7,"output_tokens":3}}}"#;
        assert_eq!(
            extract_usage(body),
            Usage {
                prompt_tokens: 7,
                completion_tokens: 3
            }
        );
    }

    #[test]
    fn sse_usage_accumulates_latest() {
        // Anthropic 流：message_start 给 input，message_delta 逐步给 output
        let sse = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":8}}\n\n",
            "data: [DONE]\n\n"
        );
        assert_eq!(
            extract_usage(sse),
            Usage {
                prompt_tokens: 10,
                completion_tokens: 8
            },
            "后出现的非零值应覆盖（累计计数语义）"
        );
    }

    #[test]
    fn sse_openai_usage() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{}}],\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":12}}\n\n",
            "data: [DONE]\n\n"
        );
        assert_eq!(
            extract_usage(sse),
            Usage {
                prompt_tokens: 30,
                completion_tokens: 12
            }
        );
    }

    #[test]
    fn total_tokens_only() {
        let body = r#"{"usage":{"total_tokens":128}}"#;
        assert_eq!(
            extract_usage(body),
            Usage {
                prompt_tokens: 128,
                completion_tokens: 0
            }
        );
    }

    #[test]
    fn cohere_meta_tokens() {
        let body = r#"{"meta":{"tokens":{"input_tokens":42}}}"#;
        assert_eq!(
            extract_usage(body),
            Usage {
                prompt_tokens: 42,
                completion_tokens: 0
            }
        );
    }

    #[test]
    fn no_usage_returns_empty() {
        assert!(extract_usage(r#"{"choices":[{"message":{"content":"hi"}}]}"#).is_empty());
        assert!(extract_usage("not json at all").is_empty());
        assert!(extract_usage("").is_empty());
    }

    #[test]
    fn merge_semantics() {
        let mut a = Usage {
            prompt_tokens: 10,
            completion_tokens: 5,
        };
        // 缺失字段不应把已有计数清零
        a.merge(&Usage {
            prompt_tokens: 0,
            completion_tokens: 8,
        });
        assert_eq!(
            a,
            Usage {
                prompt_tokens: 10,
                completion_tokens: 8
            }
        );
    }
}
