//! 多模态 / 编码载荷（blob）识别与「解析前外置」。
//!
//! 背景（实测）：多模态请求里的 base64 图片/音频/视频动辄数百 KB ~ 数 MB。
//! 若该字段没被路径豁免命中，`MaskCtx::mask()` 会对整段做一次线性扫描 ——
//! 1MB 随机 base64 约 5~10 秒（本机容器配额下），32MiB 请求直接打满超时。
//! 而规则引擎对 base64 的检出率本来≈0（编码后的字符分布随机，且规则边界
//! 检查会挡住数字串），扫描它既慢又几乎没有收益。
//!
//! 本模块提供两条能力：
//!
//! 1. **形态判定** `classify_bytes` / `is_skippable_str`：判断一个字符串值
//!    是不是「data URI」或「大块裸 base64」。用于 `mask_tree` / `restore_final`
//!    的兜底跳过（方案 B 的判定逻辑）。
//! 2. **解析前外置** `extract` / `reinject`（方案 C）：在 JSON 解析**之前**
//!    按字节扫描，把值位置上的 blob 字符串内容替换成短 token；脱敏管线只
//!    处理小 body；转发前再把 token 拼回原始字节。这样解析、重复键检测、
//!    dialog 抽取、事件日志都不再复制大 base64，且脱敏完全跳过它。
//!
//! 安全边界：
//! * 只处理**值位置**的字符串字面量；键名永不替换（否则结构被破坏）。
//! * 含反斜杠转义的字符串不替换（拼回时无法保证字节保真，且真实 base64
//!   不需要转义；`\/` 虽然合法但罕见，保守跳过留给常规扫描）。
//! * 非合法 UTF-8 的 body 不做外置（直接走原路径）。
//! * 判定只看**形态**，不看字段名 —— 因此自定义/中转字段也能覆盖。
//! * 纯数字 / 纯字母 / 纯 hex 的长串**不**判为 blob，避免把「一长串手机号
//!   拼接」「超长十六进制密钥」误当成编码载荷而漏检。

use crate::config::{BlobMode, MultimodalBlobConfig};

/// 裸 base64 的默认最小长度：低于此长度的字符串照常扫描（成本可忽略）。
pub const DEFAULT_MIN_BASE64_BYTES: usize = 8192;

/// data URI 前缀探测窗口：`;base64,` 出现在内容前若干字节内即认为命中。
const DATA_URI_PROBE: usize = 1024;

/// blob 类型（只用于诊断/事件，不参与脱敏决策）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    /// `data:<mime>;base64,<payload>` 形态（含 Markdown 里的嵌入）
    DataUri,
    /// 裸 base64 形状的大字符串
    BareBase64,
}

/// 运行时策略（由 `mask.multimodal_blob` 配置构造，构造期已 clamp）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPolicy {
    pub enabled: bool,
    pub mode: BlobMode,
    pub min_base64_bytes: usize,
}

impl Default for BlobPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: BlobMode::Auto,
            min_base64_bytes: DEFAULT_MIN_BASE64_BYTES,
        }
    }
}

impl BlobPolicy {
    /// 从配置构造（阈值夹在 [1KiB, 8MiB]，与 `Config::normalized` 同口径）。
    pub fn from_config(c: &MultimodalBlobConfig) -> Self {
        Self {
            enabled: c.enabled,
            mode: c.mode,
            min_base64_bytes: c.min_base64_bytes.clamp(1024, 8 * 1024 * 1024),
        }
    }

    /// 是否至少启用了 data URI 判定。
    fn wants_data_uri(&self) -> bool {
        self.enabled && matches!(self.mode, BlobMode::DataUri | BlobMode::Auto)
    }

    /// 是否启用了裸 base64 判定。
    fn wants_bare_base64(&self) -> bool {
        self.enabled && matches!(self.mode, BlobMode::Auto)
    }
}

// ---------------------------------------------------------------------------
// 形态判定
// ---------------------------------------------------------------------------

/// 判定一段字符串内容（不含外层引号）是否为可跳过的 blob。
///
/// `content` 必须是 JSON 字符串的**原始内容字节**（未反转义）。
pub fn classify_bytes(content: &[u8], p: &BlobPolicy) -> Option<BlobKind> {
    if !p.enabled || content.is_empty() {
        return None;
    }
    // 含反斜杠：可能是 `\/`、`\uXXXX` 等转义形态，拼回时无法按原字节保真。
    // 真实多模态 base64 不需要转义，保守跳过。
    if content.contains(&b'\\') {
        return None;
    }
    // data URI 不看长度（短 data URI 也照跳，语义上它不是「可扫描的正文」）。
    if p.wants_data_uri() && looks_like_base64_data_uri(content) {
        return Some(BlobKind::DataUri);
    }
    if p.wants_bare_base64() && looks_like_large_base64(content, p.min_base64_bytes) {
        return Some(BlobKind::BareBase64);
    }
    None
}

/// `str` 版本（供 `mask_tree` / `restore_final` 使用）。短字符串走 O(1) 快路径。
pub fn is_skippable_str(s: &str, p: &BlobPolicy) -> bool {
    if !p.enabled || s.is_empty() {
        return false;
    }
    // 快路径：既不可能 data URI，也短于裸 base64 阈值 → 直接 false，
    // 保证普通对话文本（绝大多数 < 8KB）零额外成本。
    if s.len() < p.min_base64_bytes && !looks_like_base64_data_uri(s.as_bytes()) {
        return false;
    }
    classify_bytes(s.as_bytes(), p).is_some()
}

fn ascii_lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// `data:` 开头且前 `DATA_URI_PROBE` 字节内出现 `;base64,`（大小写不敏感）。
fn looks_like_base64_data_uri(b: &[u8]) -> bool {
    if b.len() < 5 || !b[..5].eq_ignore_ascii_case(b"data:") {
        return false;
    }
    let probe = b.len().min(DATA_URI_PROBE);
    let needle = b";base64,";
    let hay = &b[..probe];
    hay.windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(x, y)| ascii_lower(*x) == *y))
}

/// 大块裸 base64 形态判定。
///
/// 规则（全部满足）：
/// 1. 长度 ≥ `min`；
/// 2. 全为 ASCII base64 字符（标准 + URL-safe：`A-Za-z0-9+/=_-`）；
/// 3. 至少出现 **3 类**字符（大写/小写/数字/符号）且**必须含符号**
///    （`+ / = - _`）—— 排除纯数字、纯字母、纯 base62 长串（签名/拼接 ID），
///    真实 base64 在 ≥8KiB 时几乎必然含 `/` 或 `+`（概率 ≈ 1-(62/64)^8192）；
/// 4. 不是纯 hex（`0-9a-fA-F`）—— 排除超长十六进制密钥/哈希；
/// 5. `=` 只允许出现在末尾（0~2 个）。
fn looks_like_large_base64(b: &[u8], min: usize) -> bool {
    if b.len() < min {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut seen_pad = false;
    let mut pads = 0usize;
    let mut all_hex = true;
    for &c in b {
        if seen_pad && c != b'=' {
            return false; // `=` 之后还有非填充字符
        }
        match c {
            b'A'..=b'Z' => {
                has_upper = true;
                all_hex = false;
            }
            b'a'..=b'f' => {
                has_lower = true;
            }
            b'g'..=b'z' => {
                has_lower = true;
                all_hex = false;
            }
            b'0'..=b'9' => {
                has_digit = true;
            }
            b'+' | b'/' | b'-' | b'_' => {
                has_symbol = true;
                all_hex = false;
            }
            b'=' => {
                has_symbol = true;
                all_hex = false;
                seen_pad = true;
                pads += 1;
                if pads > 2 {
                    return false;
                }
            }
            _ => return false, // 空白 / 控制字符 / 非 ASCII
        }
    }
    if all_hex {
        return false;
    }
    let classes = [has_upper, has_lower, has_digit, has_symbol]
        .into_iter()
        .filter(|x| *x)
        .count();
    // 要求 ≥3 类且含符号：把「纯 base62 长串」（大小写+数字）排除在外，
    // 避免把长签名/拼接 ID 误判成编码载荷而漏检。
    classes >= 3 && has_symbol
}

// ---------------------------------------------------------------------------
// 解析前外置（token 化）
// ---------------------------------------------------------------------------

/// 一个被外置的 blob：token → 原始字符串内容字节（不含引号）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub token: String,
    pub content: Vec<u8>,
}

/// 外置结果。
#[derive(Debug, Clone)]
pub struct Extraction {
    /// token 化之后的 body（仍是合法 JSON）
    pub body: Vec<u8>,
    pub blobs: Vec<Blob>,
    /// 被外置的原始内容总字节数
    pub skipped_bytes: usize,
}

/// 在 JSON 解析**之前**把值位置上的 blob 字符串替换成短 token。
///
/// 返回 `None` 表示「不做外置」（未启用 / 非合法 UTF-8 / JSON 结构不完整 /
/// 没有命中 blob）——调用方应原样使用原始 body，行为与改动前完全一致。
pub fn extract(raw: &[u8], p: &BlobPolicy) -> Option<Extraction> {
    if !p.enabled || p.mode == BlobMode::Off || raw.is_empty() {
        return None;
    }
    // 只处理合法 UTF-8：非法字节在后续 `from_utf8_lossy` 里会被替换，
    // token 拼回无法保证字节保真，保守放弃外置。
    std::str::from_utf8(raw).ok()?;
    let nonce = gen_nonce(raw)?;

    let n = raw.len();
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut blobs: Vec<Blob> = Vec::new();
    let mut skipped_bytes = 0usize;
    let mut i = 0usize;
    while i < n {
        if raw[i] != b'"' {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        // 字符串字面量：找到结束引号
        let start = i + 1;
        let Some(end) = scan_string_end(raw, start) else {
            // 结构不完整（body 不是合法 JSON）→ 放弃外置
            return None;
        };
        // 是键还是值？结束引号之后第一个非空白字符是 ':' → 键。
        let mut j = end + 1;
        while j < n && is_json_ws(raw[j]) {
            j += 1;
        }
        let is_key = j < n && raw[j] == b':';
        let content = &raw[start..end];
        // 内容是 JSON 字符串内部原始字节；必须是合法 UTF-8 才能拼回。
        if !is_key && classify_bytes(content, p).is_some() && std::str::from_utf8(content).is_ok() {
            // idx 固定 6 位零填充：token 等宽 → 互不为前缀。
            // 不补零时 `kmb-x-1` 是 `kmb-x-10` 的前缀，11 个媒体块
            // 就会在第 1 个 token 替换时把第 11 个的前缀吃掉（静默损坏）。
            let token = format!("kmb-{nonce}-{:06}", blobs.len());
            out.push(b'"');
            out.extend_from_slice(token.as_bytes());
            out.push(b'"');
            skipped_bytes += content.len();
            blobs.push(Blob {
                token,
                content: content.to_vec(),
            });
            i = end + 1;
            continue;
        }
        out.extend_from_slice(&raw[i..end + 1]);
        i = end + 1;
    }
    if blobs.is_empty() {
        return None;
    }
    Some(Extraction {
        body: out,
        blobs,
        skipped_bytes,
    })
}

/// 把 token 替换回原始内容字节（转发前调用）。
///
/// 返回 `Some` 表示**所有** token 都成功拼回；`None` 表示有 token 在脱敏阶段
/// 被改写（例如自定义词恰好命中 token 的 nonce）——调用方必须回退到
/// 「未外置」路径，**绝不能**把残留 token 的半成品发给上游。
pub fn reinject_checked(text: &str, blobs: &[Blob]) -> Option<String> {
    if blobs.is_empty() {
        return Some(text.to_string());
    }
    let mut out = text.to_string();
    for b in blobs {
        if !out.contains(&b.token) {
            return None;
        }
        let content = String::from_utf8_lossy(&b.content);
        out = out.replace(&b.token, &content);
    }
    Some(out)
}

/// 便捷包装：失败时原样返回（仅供不要求 fail-safe 的测试/诊断使用；
/// 生产转发路径必须用 [`reinject_checked`]）。
pub fn reinject(text: &str, blobs: &[Blob]) -> String {
    match reinject_checked(text, blobs) {
        Some(t) => t,
        None => text.to_string(),
    }
}

// ---------------------------------------------------------------------------
// 字节级 JSON 扫描辅助
// ---------------------------------------------------------------------------

fn is_json_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// 从 `start`（第一个内容字节）开始找结束引号，返回**结束引号的下标**。
/// 处理 `\` 转义（含 `\uXXXX`：跳过 `\u` 后继续扫，hex 不会产生引号）。
fn scan_string_end(raw: &[u8], start: usize) -> Option<usize> {
    let n = raw.len();
    let mut i = start;
    while i < n {
        match raw[i] {
            b'"' => return Some(i),
            b'\\' => {
                if i + 1 >= n {
                    return None;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    None
}

/// 生成不会与 body 已有内容冲突的 nonce（16 字节 hex）。
fn gen_nonce(raw: &[u8]) -> Option<String> {
    for _ in 0..4 {
        let a = rand::random::<u64>();
        let b = rand::random::<u64>();
        let nonce = format!("{a:016x}{b:016x}");
        // 极端情况下 body 里恰好已有同样的串 → 换一个（避免 reinject 误替换）
        if !contains_subslice(raw, nonce.as_bytes()) {
            return Some(nonce);
        }
    }
    None
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(mode: BlobMode) -> BlobPolicy {
        BlobPolicy {
            enabled: true,
            mode,
            min_base64_bytes: 64,
        }
    }

    fn b64(n: usize) -> String {
        // 构造「多类别」的伪 base64：大小写 + 数字 + 符号
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        (0..n)
            .map(|i| alphabet[(i * 7 + 11) % alphabet.len()] as char)
            .collect()
    }

    #[test]
    fn data_uri_is_detected_regardless_of_length() {
        let p = policy(BlobMode::Auto);
        assert_eq!(
            classify_bytes(b"data:image/png;base64,AAAA", &p),
            Some(BlobKind::DataUri)
        );
        // 大小写不敏感
        assert_eq!(
            classify_bytes(b"DATA:image/png;BASE64,AAAA", &p),
            Some(BlobKind::DataUri)
        );
        // 非 base64 的 data URI（纯文本）不跳
        assert_eq!(classify_bytes(b"data:text/plain;utf8,hello", &p), None);
    }

    #[test]
    fn bare_base64_requires_length_and_mixed_classes() {
        let p = policy(BlobMode::Auto);
        assert_eq!(
            classify_bytes(b64(200).as_bytes(), &p),
            Some(BlobKind::BareBase64)
        );
        let long_digits = "1".repeat(2000);
        assert_eq!(
            classify_bytes(long_digits.as_bytes(), &p),
            None,
            "纯数字不判"
        );
        let long_hex = "deadbeef".repeat(500);
        assert_eq!(classify_bytes(long_hex.as_bytes(), &p), None, "纯 hex 不判");
        let long_lower = "a".repeat(2000);
        assert_eq!(
            classify_bytes(long_lower.as_bytes(), &p),
            None,
            "单类别不判"
        );
    }

    #[test]
    fn padding_only_at_tail() {
        let p = policy(BlobMode::Auto);
        let ok = format!("{}AB==", b64(100));
        assert!(classify_bytes(ok.as_bytes(), &p).is_some());
        let bad = format!("{}A=B=", b64(100));
        assert!(classify_bytes(bad.as_bytes(), &p).is_none());
    }

    #[test]
    fn mode_off_and_data_uri_only() {
        let off = BlobPolicy {
            enabled: true,
            mode: BlobMode::Off,
            min_base64_bytes: 64,
        };
        assert!(classify_bytes(b"data:image/png;base64,AAAA", &off).is_none());

        let only_uri = policy(BlobMode::DataUri);
        assert!(classify_bytes(b"data:image/png;base64,AAAA", &only_uri).is_some());
        assert!(classify_bytes(b64(200).as_bytes(), &only_uri).is_none());
    }

    #[test]
    fn extract_replaces_only_value_positions() {
        let p = policy(BlobMode::Auto);
        let payload = b64(300);
        let raw = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":[{{"type":"image_url","image_url":{{"url":"data:image/png;base64,{payload}"}}}}]}}],"other":"hello"}}"#
        );
        let ex = extract(raw.as_bytes(), &p).expect("应命中");
        assert_eq!(ex.blobs.len(), 1);
        // 值是整个 data URI 字符串（含前缀）
        assert_eq!(
            ex.blobs[0].content,
            format!("data:image/png;base64,{payload}").as_bytes()
        );
        assert_eq!(
            ex.skipped_bytes,
            format!("data:image/png;base64,{payload}").len()
        );
        // token 化后的 body 仍是合法 JSON，且结构完整
        let v: serde_json::Value = serde_json::from_slice(&ex.body).expect("合法 JSON");
        assert_eq!(v["model"], "gpt-4o");
        assert_eq!(v["other"], "hello");
        // 拼回后逐字节一致
        let restored = reinject(&String::from_utf8(ex.body).unwrap(), &ex.blobs);
        assert_eq!(restored, raw);
    }

    #[test]
    fn extract_handles_array_root_and_escapes() {
        let p = policy(BlobMode::Auto);
        let payload = b64(300);
        let raw = format!(r#"["{payload}","hello"]"#);
        let ex = extract(raw.as_bytes(), &p).expect("数组根也应命中");
        assert_eq!(ex.blobs.len(), 1);
        let v: serde_json::Value = serde_json::from_slice(&ex.body).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);

        // 含反斜杠转义的字符串不外置（保守）——注意 raw string 里 `\/` 就是
        // 反斜杠 + 斜杠（不是 `\\` + `/`）。
        let escaped = format!(r#"["{payload}\/x"]"#);
        assert!(extract(escaped.as_bytes(), &p).is_none());
    }

    #[test]
    fn extract_rejects_non_json_and_non_utf8() {
        let p = policy(BlobMode::Auto);
        assert!(extract(b"not json at all", &p).is_none());
        let mut bad = b"[\"".to_vec();
        bad.extend_from_slice(&[0xff, 0xfe]);
        bad.extend_from_slice(b"\"]");
        assert!(extract(&bad, &p).is_none());
    }

    #[test]
    fn extract_no_hit_returns_none() {
        let p = policy(BlobMode::Auto);
        let raw = br#"{"messages":[{"role":"user","content":"hello 13800138000"}]}"#;
        assert!(extract(raw, &p).is_none());
    }

    #[test]
    fn reinject_roundtrip_is_byte_identical() {
        let p = policy(BlobMode::Auto);
        let payload = b64(500);
        let raw = format!(r#"{{"a":"{payload}","b":1}}"#);
        let ex = extract(raw.as_bytes(), &p).unwrap();
        let masked = String::from_utf8(ex.body.clone()).unwrap();
        assert_eq!(reinject(&masked, &ex.blobs), raw);
    }

    #[test]
    fn skip_str_fast_path_for_short_text() {
        let p = BlobPolicy::default();
        assert!(!is_skippable_str("hello 13800138000", &p));
        assert!(!is_skippable_str("", &p));
        assert!(is_skippable_str("data:image/png;base64,AAAA", &p));
    }

    #[test]
    fn reinject_handles_eleven_or_more_tokens() {
        // S1 回归锁：token idx 必须等宽（零填充），否则 `-1` 会吃掉 `-10` 的前缀。
        let p = BlobPolicy {
            enabled: true,
            mode: BlobMode::Auto,
            min_base64_bytes: 64,
        };
        let mut items = Vec::new();
        for i in 0..12 {
            let payload = format!("{}{}", b64(200), i);
            items.push(format!(r#"{{"url":"data:image/png;base64,{payload}"}}"#));
        }
        let raw = format!("[{}]", items.join(","));
        let ex = extract(raw.as_bytes(), &p).expect("应命中 12 个 blob");
        assert_eq!(ex.blobs.len(), 12);
        let masked = String::from_utf8(ex.body.clone()).unwrap();
        let restored = reinject_checked(&masked, &ex.blobs).expect("必须全部拼回");
        assert_eq!(restored, raw, "12 个媒体块必须逐字节还原");
    }

    #[test]
    fn reinject_checked_fails_when_token_was_modified() {
        // S2 回归锁：token 被改写时必须返回 None（调用方据此回退），
        // 绝不能把残留 token 当成功结果转发。
        let p = BlobPolicy {
            enabled: true,
            mode: BlobMode::Auto,
            min_base64_bytes: 64,
        };
        let payload = b64(200);
        let raw = format!(r#"["data:image/png;base64,{payload}"]"#);
        let ex = extract(raw.as_bytes(), &p).unwrap();
        let masked = String::from_utf8(ex.body.clone())
            .unwrap()
            .replace(&ex.blobs[0].token, "kmb-damaged-000000");
        assert!(reinject_checked(&masked, &ex.blobs).is_none());
    }

    #[test]
    fn base62_long_string_is_not_blob() {
        // 大小写+数字但**无符号**的长串（base62 签名/拼接 ID）不判 blob，
        // 避免把需要扫描的长标识符当编码载荷跳过。
        let p = BlobPolicy {
            enabled: true,
            mode: BlobMode::Auto,
            min_base64_bytes: 64,
        };
        let s = "Ab3".repeat(200);
        assert_eq!(classify_bytes(s.as_bytes(), &p), None);
    }
}
