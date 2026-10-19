//! 完整报文诊断环：最近 N 条请求的**完整**请求体/响应体。
//!
//! 与 `events` 表里的 `dialog` 不同 —— 后者是 `extract_dialog_text()` 抽取后的
//! 对话文本（只认 content/text/input 等键，且 8000 字符截断），排查
//! 「脱敏了没还原」时既看不到上游回来的占位符原样，也看不到 tool 定义、
//! arguments 等结构。本模块存的是原始字节形态。
//!
//! 为什么单独一张表而不塞进 `events.payload`：
//!   * 报文动辄几十 KB ~ MB，混进 `events` 会让列表查询 / 全文搜索 / 保留期
//!     清理全被拖垮；
//!   * 这里要的是**有界诊断环**（最近 N 条，超出即淘汰），不是历史归档。
//!
//! 表结构按 `(sid, kind)` 唯一：请求侧先落一行（kind=req），响应侧回来补一行
//! （kind=resp），详情页按 `sid` 合并展示。淘汰按「最近 N 个 sid」执行，
//! 同一请求的两行永远同生共死。

use serde::Serialize;

/// 一条完整报文的归属侧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceKind {
    /// 请求侧：原文请求体 + 脱敏后（发给上游）请求体
    Req,
    /// 响应侧：上游原始响应体 + 还原后（返回客户端）响应体
    Resp,
}

impl TraceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TraceKind::Req => "req",
            TraceKind::Resp => "resp",
        }
    }
}

/// 待落盘的一组报文（请求侧或响应侧各一份）。
#[derive(Debug, Clone)]
pub struct TraceBlob {
    pub sid: String,
    pub kind: TraceKind,
    pub ts: f64,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub model: String,
    pub stream: bool,
    /// req：客户端原文请求体；resp：上游原始响应体
    pub primary_body: String,
    /// req：脱敏后（发给上游）请求体；resp：还原后（返回客户端）响应体
    pub secondary_body: String,
    /// 截断前的原始字节数
    pub primary_bytes: usize,
    pub secondary_bytes: usize,
    /// 任一侧被截断
    pub truncated: bool,
    /// 附加信息（JSON）：resp 侧记 `unresolved` / `unresolved_samples`
    pub extra: serde_json::Value,
    /// 保留最近多少组（写线程据此淘汰；0 表示关闭，调用方不该入队）
    pub keep: usize,
}

/// 详情页用的合并视图：`(sid, req)` + `(sid, resp)` 合成一条。
#[derive(Debug, Clone, Serialize)]
pub struct TraceView {
    pub sid: String,
    pub ts: f64,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub model: String,
    pub stream: bool,
    /// 客户端原文请求体
    pub req_raw: String,
    /// 脱敏后（发给上游）请求体
    pub req_masked: String,
    pub req_bytes: usize,
    pub req_masked_bytes: usize,
    pub req_truncated: bool,
    /// 上游原始响应体（含占位符，排查未还原的关键证据）
    pub resp_raw: String,
    /// 还原后（返回客户端）响应体
    pub resp_out: String,
    pub resp_bytes: usize,
    pub resp_out_bytes: usize,
    pub resp_truncated: bool,
    /// 未还原占位符数 + 样本（仅响应侧）
    pub unresolved: usize,
    pub unresolved_samples: Vec<String>,
}

/// 按**字节**上限截断文本，并保证不切断 UTF-8 字符。
///
/// 返回 `(截断后文本, 是否发生截断)`。截断会追加一条人类可读的标注；
/// `max_bytes == 0` 视为「不限制」（调用方在关闭时根本不会入队）。
///
/// 为什么按字节而非字符：上限的初衷是控制内存/磁盘，字节才是成本单位；
/// 而 `is_char_boundary` 回退保证不会把多字节字符切成半个（否则
/// `String::from_utf8_lossy` 之后的展示会出现乱码，甚至 JSON 也解析不了）。
pub fn cap_body(text: &str, max_bytes: usize) -> (String, bool) {
    if max_bytes == 0 || text.len() <= max_bytes {
        return (text.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 48);
    out.push_str(&text[..end]);
    out.push_str(&format!(
        "\n…（已截断：原报文 {} 字节，此处保留前 {} 字节）",
        text.len(),
        end
    ));
    (out, true)
}

/// 按**字节**上限截断原始字节（避免先 `from_utf8_lossy` 全量复制）。
///
/// 语义与 `cap_body` 一致；多一个大 base64 请求时，省掉一次「先把 32MiB
/// 全量转成 String、再截掉 31MiB」的浪费。
pub fn cap_body_bytes(raw: &[u8], max_bytes: usize) -> (String, bool) {
    if max_bytes == 0 || raw.len() <= max_bytes {
        return (String::from_utf8_lossy(raw).to_string(), false);
    }
    let mut end = max_bytes;
    // 回退到 UTF-8 字符边界（不切断多字节字符）
    while end > 0 && (raw[end] & 0xC0) == 0x80 {
        end -= 1;
    }
    let mut out = String::from_utf8_lossy(&raw[..end]).to_string();
    out.push_str(&format!(
        "\n…（已截断：原报文 {} 字节，此处保留前 {} 字节）",
        raw.len(),
        end
    ));
    (out, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_bytes_keeps_short_body_untouched() {
        let (s, t) = cap_body_bytes(b"hello", 1024);
        assert_eq!(s, "hello");
        assert!(!t);
    }

    #[test]
    fn cap_bytes_never_splits_utf8() {
        // 「啊」3 字节；上限 4 落在第二个字符中间，必须回退到 3。
        let raw = "啊啊".as_bytes();
        let (s, t) = cap_body_bytes(raw, 4);
        assert!(t);
        assert!(s.starts_with('啊'));
    }

    #[test]
    fn cap_keeps_short_body_untouched() {
        let (s, t) = cap_body("hello 世界", 1024);
        assert_eq!(s, "hello 世界");
        assert!(!t);
    }

    #[test]
    fn cap_respects_zero_as_unlimited() {
        let long = "啊".repeat(1000);
        let (s, t) = cap_body(&long, 0);
        assert_eq!(s, long);
        assert!(!t);
    }

    #[test]
    fn cap_never_splits_utf8() {
        // 每个「啊」3 字节；上限 4 落在第二个字符中间，必须回退到 3。
        let text = "啊啊啊";
        let (s, t) = cap_body(text, 4);
        assert!(t);
        assert!(s.starts_with("啊"), "不得切出半个字符：{s:?}");
        assert!(s.contains("已截断"));
        // 截断前的部分必须是合法 UTF-8 前缀
        assert!(s.is_char_boundary(3));
    }
}
