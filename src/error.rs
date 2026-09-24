//! 错误类型：管线内部统一错误面。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // M6 管线全量启用
pub enum ErrorKind {
    /// 请求体超过 max_body_bytes → 413（不看 fail_closed）
    BodyTooLarge,
    /// 声明非 JSON 且 fail_closed → 503
    NonJsonBody,
    /// JSON 解析失败且 fail_closed → 400
    InvalidJson,
    /// 递归深度超限 / 脱敏内部异常 → 503
    MaskFailed,
    /// 未命中上游路由 → 404
    NoRoute,
}

#[allow(dead_code)] // M6 使用
impl ErrorKind {
    pub fn status(&self) -> u16 {
        match self {
            ErrorKind::BodyTooLarge => 413,
            ErrorKind::NonJsonBody => 503,
            ErrorKind::InvalidJson => 400,
            ErrorKind::MaskFailed => 503,
            ErrorKind::NoRoute => 404,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            ErrorKind::BodyTooLarge => "request_too_large",
            ErrorKind::NonJsonBody => "non_json_body",
            ErrorKind::InvalidJson => "invalid_json",
            ErrorKind::MaskFailed => "shield_mask_failed",
            ErrorKind::NoRoute => "no_reverse_route",
        }
    }
}

/// 统一错误：kind + 可读信息。
#[derive(Debug, Clone)]
#[allow(dead_code)] // M6 使用
pub struct PipeError {
    pub kind: ErrorKind,
    pub message: String,
}

#[allow(dead_code)] // M6 使用
impl PipeError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.reason(), self.message)
    }
}

impl std::error::Error for PipeError {}
