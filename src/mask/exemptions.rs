//! 路径感知豁免表（对齐 Python `_MASK_*` 系列常量 + `_leaf_exempt` 判定）。
//!
//! 判据优先级（与 Python 逐条一致）：
//! 1. 工具调用关联 ID 不分业务区一律豁免；
//! 2. 业务区内一律不豁免（业务字段必须扫描）；
//! 3. 业务区外按「协议位置」判定，禁止裸字段名豁免；
//! 4. 键名脱敏用结构键白名单。

use std::collections::HashSet;

/// 协议元数据标量键（值恒为协议枚举/参数名，豁免扫描）。
pub fn skip_scalar_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "model",
            "object",
            "finish_reason",
            "stop_reason",
            "citations",
            "detail",
            "encoding_format",
            "media_type",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// 值恒为协议元数据对象的键 → 整棵子树跳过（判定点在 dict 分支开头）。
pub fn skip_subtree_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> =
        once_cell::sync::Lazy::new(|| ["cache_control"].into_iter().collect());
    &S
}

/// role/type 仅在其协议容器内豁免。
pub fn role_type_parents() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "message",
            "messages",
            "content",
            "contents",
            "parts",
            "block",
            "blocks",
            "tools",
            "tool",
            "tool_calls",
            "function",
            "response_format",
            "candidates",
            "choices",
            "output",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// id 仅在协议容器位置豁免。
pub fn protocol_id_parents() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "message",
            "messages",
            "content",
            "contents",
            "parts",
            "block",
            "blocks",
            "tool_calls",
            "tool_use",
            "response",
            "output",
            "data",
            "object",
            "candidates",
            "choices",
            "function_call",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// 只在这类父 key 下才豁免的字段（工具名/媒体容器）。
pub fn protocol_parents() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "function",
            "functions",
            "function_call",
            "functionCall",
            "tool_use",
            "tools",
            "tool",
            "image_url",
            "inline_data",
            "thumbnail",
            "input_image",
            "source",
            "file",
            // 多模态 / 文件输入容器（Chat input_audio、Responses input_file、
            // 部分中转的 video_url）。
            //
            // 注意：不把 `audio` / `video` 加进来 —— 该集合同时决定 `name` /
            // `url` / `data` / `id` 的豁免，裸容器名会把 `{"video":{"name":"张三
            // 的身份证.mp4"}}` 这类业务字段整片放行。Gemini 音频走
            // `inline_data`（已覆盖），Chat 音频走 `input_audio`。
            "input_audio",
            "input_file",
            "video_url",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// `media_value_keys` 允许的父容器：媒体/文件载荷键必须落在这些容器内。
///
/// 为什么必须收窄：本模块的判据是「业务区外按协议位置判定，**禁止裸字段名
/// 豁免**」。若只按键名豁免，`{"customer":{"image_url":"张三的照片"}}`、
/// `{"attachments":[{"video_url":"…?phone=138…"}]}` 这类业务 JSON 会从
/// 「扫描」变成「豁免」，净增漏检面。
pub fn media_value_parents() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "content",
            "contents",
            "parts",
            "message",
            "messages",
            "input",
            "output",
            "file",
            "input_image",
            "input_file",
            "image_url",
            "source",
            "inline_data",
            "tool_use",
            "function",
            "attachments",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// 键名本身即语义明确的媒体/文件载荷键：**非业务区**下一律豁免，
/// 不再要求父键命中 `protocol_parents`。
///
/// 为什么需要：Responses API 的 `input_image.image_url` 是**字符串直接挂在
/// content 项下**（父键是 `content`，不是 `input_image`），仅靠“父键必须是
/// 媒体容器”的判据会漏；`input_file.file_data` 同理。这些键名足够特定，
/// 裸用不会误伤业务字段（业务区仍优先返回 false）。
pub fn media_value_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        ["image_url", "file_data", "video_url"]
            .into_iter()
            .collect()
    });
    &S
}

/// 需按位置判定的跳过键。
pub fn skip_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "id",
            "tool_call_id",
            "tool_use_id",
            "name",
            "url",
            "data",
            "b64_json",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// 工具调用关联 ID：不分业务区一律豁免。
pub fn correlation_id_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        ["tool_call_id", "tool_use_id", "call_id"]
            .into_iter()
            .collect()
    });
    &S
}

/// 业务区容器键：进入后任何字段都照常扫描。
pub fn business_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "input",
            "arguments",
            "parameters",
            "partial_json",
            "documents",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// 递归深度上限。
pub const MASK_MAX_DEPTH: usize = 24;
pub const RESTORE_MAX_DEPTH: usize = 24;

/// 数值型协议字段（数值豁免；字符串形态照常扫描）。
pub fn skip_numeric_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        [
            "max_tokens",
            "max_completion_tokens",
            "max_tokens_to_sample",
            "budget_tokens",
            "temperature",
            "top_p",
            "top_k",
            "n",
            "seed",
            "index",
            "created",
            "logprobs",
            "top_logprobs",
            "presence_penalty",
            "frequency_penalty",
            "best_of",
            "timeout",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
            "reasoning_tokens",
            "status_code",
            "http_status",
            "retry",
            "attempt",
            "weight",
            "priority",
        ]
        .into_iter()
        .collect()
    });
    &S
}

/// 对象**键名**白名单：集合内的键永不脱敏，集合外一律当数据键扫描。
pub fn protected_key_names() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
        let mut s: HashSet<&'static str> = HashSet::new();
        s.extend(skip_scalar_keys().iter().copied());
        s.extend(skip_subtree_keys().iter().copied());
        s.extend(skip_keys().iter().copied());
        s.extend(correlation_id_keys().iter().copied());
        s.extend(role_type_parents().iter().copied());
        s.extend(protocol_parents().iter().copied());
        s.extend(protocol_id_parents().iter().copied());
        s.extend(business_keys().iter().copied());
        s.extend([
            // 对话协议骨架
            "role",
            "type",
            "content",
            "contents",
            "parts",
            "messages",
            "message",
            "system",
            "user",
            "assistant",
            "tool",
            "tools",
            "function",
            "functions",
            "prompt",
            "input",
            "output",
            "text",
            "delta",
            "choices",
            "candidates",
            "usage",
            "error",
            "code",
            "status",
            "version",
            "headers",
            "request",
            "response",
            "metadata",
            "stream",
            "stop",
            "stop_sequences",
            "logit_bias",
            "response_format",
            "stream_options",
            "parallel_tool_calls",
            "tool_choice",
            "system_instruction",
            "generationConfig",
            "safetySettings",
            "toolConfig",
            "functionDeclarations",
            "functionCall",
            "inline_data",
            "image_url",
            "file_data",
            "source",
            "anthropic_version",
            "thinking",
            "signature",
            // JSON Schema 词汇
            "schema",
            "json_schema",
            "format",
            "definitions",
            "$defs",
            "$ref",
            "$schema",
            "properties",
            "required",
            "items",
            "enum",
            "const",
            "description",
            "title",
            "additionalProperties",
            "anyOf",
            "oneOf",
            "allOf",
            "not",
            "if",
            "then",
            "else",
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "minLength",
            "maxLength",
            "minItems",
            "maxItems",
            "pattern",
            "default",
            "examples",
            "nullable",
            "strict",
            "name",
            "strict_mode",
            // 缓存 / 计费 / 诊断
            "cache_control",
            "ttl",
            "ephemeral",
            // 对话协议顶级控制参数
            "temperature",
            "top_p",
            "top_k",
            "n",
            "max_tokens",
            "max_completion_tokens",
            "max_output_tokens",
            "presence_penalty",
            "frequency_penalty",
            "seed",
            "logprobs",
            "top_logprobs",
            "modalities",
            "audio",
            "prediction",
            "store",
            "service_tier",
            "reasoning",
            "reasoning_effort",
            "thinking_budget",
            "betas",
            "anthropic_beta",
            "context_management",
            "mcp_servers",
            "container",
            "generation_config",
            "safety_settings",
            "candidate_count",
            "systemInstruction",
            "session_id",
            "request_id",
            "keep_alive",
            "options",
            "api_key",
            "x_api_key",
            "authorization",
            "instructions",
            "tool_config",
        ]);
        s
    });
    &S
}

/// 顶层非对象 JSON 的合成根键。
pub const ROOT_WRAP_KEY: &str = "__shield_root__";

/// 值是 JSON 文本的键（还原时原文需转义）。
pub fn json_str_keys() -> &'static HashSet<&'static str> {
    static S: once_cell::sync::Lazy<HashSet<&'static str>> =
        once_cell::sync::Lazy::new(|| ["arguments", "partial_json"].into_iter().collect());
    &S
}

/// 叶子（字符串/数值）是否落在协议位置从而豁免扫描。
///
/// * `key` — 当前键名
/// * `parent` — 父键名
/// * `in_business` — 是否处于业务区容器内
pub fn leaf_exempt(key: Option<&str>, parent: Option<&str>, in_business: bool) -> bool {
    let Some(key) = key else { return false };
    // 关联 ID 优先于 in_business
    if correlation_id_keys().contains(key) {
        return true;
    }
    if in_business {
        return false;
    }
    // 媒体/文件载荷键：键名 + **已知媒体容器**双重判定。
    // Responses 的 `input_image.image_url` / `input_file.file_data` 父键是
    // `content`（字符串直挂内容项），靠父容器白名单覆盖；业务 JSON 里的
    // 同名键（`customer.image_url`）父键不在白名单，仍照常扫描。
    if media_value_keys().contains(key)
        && parent
            .map(|p| media_value_parents().contains(p))
            .unwrap_or(false)
    {
        return true;
    }
    if skip_scalar_keys().contains(key) {
        return true;
    }
    if (key == "role" || key == "type")
        && (parent.is_none()
            || parent
                .map(|p| role_type_parents().contains(p))
                .unwrap_or(false))
    {
        return true;
    }
    if skip_keys().contains(key) {
        // 协议位置判定
        if key == "name"
            && !parent
                .map(|p| protocol_parents().contains(p))
                .unwrap_or(false)
        {
            return false;
        }
        if (key == "url" || key == "data" || key == "b64_json" || key == "image_url")
            && !parent
                .map(|p| protocol_parents().contains(p))
                .unwrap_or(false)
        {
            return false;
        }
        if key == "id"
            && !parent
                .map(|p| protocol_id_parents().contains(p))
                .unwrap_or(false)
        {
            return false;
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_ids_always_exempt() {
        // 即使在业务区内也豁免（Responses API 把 call_id 放进 input[]）
        assert!(leaf_exempt(Some("call_id"), Some("input"), true));
        assert!(leaf_exempt(Some("tool_call_id"), None, false));
        assert!(leaf_exempt(Some("tool_use_id"), Some("content"), true));
    }

    #[test]
    fn business_zone_never_exempt() {
        // input 内的 type/role/model 是业务数据必须扫描
        assert!(!leaf_exempt(Some("type"), Some("input"), true));
        assert!(!leaf_exempt(Some("role"), Some("input"), true));
        assert!(!leaf_exempt(Some("model"), Some("arguments"), true));
        assert!(!leaf_exempt(Some("id"), Some("input"), true));
        assert!(!leaf_exempt(Some("url"), Some("input"), true));
    }

    #[test]
    fn protocol_positions_exempt() {
        // 协议位置的 type/role/model 豁免
        assert!(leaf_exempt(Some("type"), Some("content"), false));
        assert!(leaf_exempt(Some("role"), Some("message"), false));
        assert!(leaf_exempt(Some("model"), None, false));
        assert!(leaf_exempt(Some("finish_reason"), None, false));
        // 媒体容器里的 url 豁免
        assert!(leaf_exempt(Some("url"), Some("image_url"), false));
        // 业务对象里的 url 不豁免（customer.url）
        assert!(!leaf_exempt(Some("url"), Some("customer"), false));
        // 工具名豁免
        assert!(leaf_exempt(Some("name"), Some("function"), false));
        assert!(!leaf_exempt(Some("name"), Some("customer"), false));
        // 协议容器的 id 豁免
        assert!(leaf_exempt(Some("id"), Some("message"), false));
        // 业务对象 id 不豁免
        assert!(!leaf_exempt(Some("id"), Some("customer"), false));
    }

    #[test]
    fn multimodal_payload_positions_exempt() {
        // Chat 音频输入：input_audio.data（父键在 protocol_parents 内）
        assert!(leaf_exempt(Some("data"), Some("input_audio"), false));
        // Responses 图片：input_image.image_url 是**字符串直挂 content 项下**
        // （父键是 content），靠 media_value_keys 兜住
        assert!(leaf_exempt(Some("image_url"), Some("content"), false));
        // Responses 文件：input_file.file_data 同理
        assert!(leaf_exempt(Some("file_data"), Some("content"), false));
        assert!(leaf_exempt(Some("file_data"), Some("input_file"), false));
        // 视频容器里的 url
        assert!(leaf_exempt(Some("url"), Some("video_url"), false));
        // 普通 http URL 也豁免（协议位置语义，避免签名参数被误改写）
        assert!(leaf_exempt(Some("image_url"), Some("input_image"), false));
        // video_url 作为字符串值时，父容器在 media_value_parents 内才豁免
        assert!(leaf_exempt(Some("video_url"), Some("content"), false));
        // 业务区仍然必须扫描
        assert!(!leaf_exempt(Some("file_data"), Some("input"), true));
        assert!(!leaf_exempt(Some("image_url"), Some("arguments"), true));
        // 非协议位置的普通 url 不豁免（回归锁）
        assert!(!leaf_exempt(Some("url"), Some("attachments"), false));
        // 业务 JSON 里的同名字段不得被裸字段名豁免（S4 回归锁）
        assert!(!leaf_exempt(Some("image_url"), Some("customer"), false));
        assert!(!leaf_exempt(Some("file_data"), Some("customer"), false));
        // audio/video 不再作为协议容器（避免 name/url/id 整片豁免）
        assert!(!leaf_exempt(Some("name"), Some("video"), false));
        assert!(!leaf_exempt(Some("url"), Some("audio"), false));
    }

    #[test]
    fn protected_key_names_cover_protocol_top_keys() {
        // 广谱护栏：协议顶层键必须全在白名单里（否则上游 400）
        let keys = [
            "model",
            "messages",
            "system",
            "prompt",
            "input",
            "instructions",
            "tools",
            "tool_choice",
            "tool_config",
            "functions",
            "function_call",
            "temperature",
            "top_p",
            "top_k",
            "max_tokens",
            "max_completion_tokens",
            "max_output_tokens",
            "stream",
            "stream_options",
            "stop",
            "n",
            "seed",
            "logprobs",
            "top_logprobs",
            "logit_bias",
            "presence_penalty",
            "frequency_penalty",
            "user",
            "metadata",
            "response_format",
            "modalities",
            "audio",
            "prediction",
            "store",
            "service_tier",
            "reasoning",
            "reasoning_effort",
            "thinking",
            "thinking_budget",
            "cache_control",
            "betas",
            "anthropic_version",
            "anthropic_beta",
            "context_management",
            "mcp_servers",
            "container",
            "parallel_tool_calls",
            "contents",
            "generation_config",
            "safety_settings",
            "candidate_count",
            "safetySettings",
            "generationConfig",
            "systemInstruction",
            "session_id",
            "request_id",
            "keep_alive",
            "options",
            "format",
            "api_key",
            "x_api_key",
            "authorization",
        ];
        let prot = protected_key_names();
        for k in keys {
            assert!(
                prot.contains(k),
                "协议顶层键 {k} 不在白名单（会被键名脱敏改名 → 上游 400）"
            );
        }
    }

    #[test]
    fn cache_control_subtree_is_metadata() {
        assert!(skip_subtree_keys().contains("cache_control"));
        // 反向锁：response_format / format 不许进子树豁免（schema enum 可能载真实取值）
        assert!(!skip_subtree_keys().contains("response_format"));
        assert!(!skip_subtree_keys().contains("format"));
    }
}
