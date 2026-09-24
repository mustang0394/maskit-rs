//! 占位符：生成 / 解析 / 后缀字母表 / 转义形态。
//!
//! 对齐 Python transparent.py：
//! - 格式 `{{LABEL_suffix6}}`，后缀 6 位纯辅音（新）或 hex6（旧，仅识别）
//! - `_safe_label`：标签 ASCII 化（非 [A-Z0-9] 剔除，≤12 字符，空则 TERM）
//! - `_PARTIAL_RX`/`_PARTIAL_MAX=48`：流式半截占位符扣留判定
//! - `_PLACEHOLDER_RX` 等正则族：还原路径的三遍扫描（严格/转义/宽松）
//!
//! ⚠️ **所有正则必须是静态缓存**：热路径每次调用重新编译正则会带来
//! 数量级退化（实测 512KB 请求体从 ~30ms 劣化到 616ms）。

use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;

/// 占位符后缀字母表：纯辅音（无 aeiou、无 lio，见 Python `_TOKEN_ALPHABET` 注释）。
pub const TOKEN_ALPHABET: &[u8] = b"bcdfghjkmnpqrstvwxz";

/// 后缀模式（新辅音 | 旧 hex6），嵌入各正则。
pub const SUFFIX_PAT: &str = r"(?:[0-9a-f]{6}|[bcdfghjkmnpqrstvwxz]{6})";

/// 标签安全化：非 ASCII 字母数字剔除，≤12 字符，空则 TERM（对齐 `_safe_label`）。
pub fn safe_label(label: &str) -> String {
    let up = label.to_uppercase();
    let filtered: String = up
        .chars()
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        .collect();
    let trimmed: String = filtered.chars().take(12).collect();
    if trimmed.is_empty() {
        "TERM".to_string()
    } else {
        trimmed
    }
}

/// 6 位随机纯辅音后缀（CSPRNG，对齐 `_rand_suffix`）。
pub fn rand_suffix() -> String {
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(6);
    for _ in 0..6 {
        s.push(TOKEN_ALPHABET[rng.gen_range(0..TOKEN_ALPHABET.len())] as char);
    }
    s
}

/// 生成新占位符（对齐 `_new_token`：完整 token 与后缀都要不冲突）。
pub fn new_token(label: &str, taken: &dyn Fn(&str, &str) -> bool) -> String {
    let lab = safe_label(label);
    for _ in 0..20 {
        let suffix = rand_suffix();
        let token = format!("{{{{{lab}_{suffix}}}}}");
        if !taken(&token, &suffix) {
            return token;
        }
    }
    // 兜底仍用 6 位（Python 同款：19^6 空间，实际不可达）
    format!("{{{{{lab}_{}}}}}", rand_suffix())
}

/// 从 token 取 6 位后缀（小写）；形态不对返回空（对齐 `_token_suffix`）。
pub fn token_suffix(token: &str) -> String {
    let Some(inner) = token.strip_prefix("{{").and_then(|t| t.strip_suffix("}}")) else {
        return String::new();
    };
    let body = inner.trim();
    match body.rfind('_') {
        Some(i) => body[i + 1..].to_lowercase(),
        None => String::new(),
    }
}

/// 从 token 取标签部分（原样未归一化，对齐 `_token_label`）。
pub fn token_label(token: &str) -> String {
    let Some(inner) = token.strip_prefix("{{").and_then(|t| t.strip_suffix("}}")) else {
        return String::new();
    };
    let body = inner.trim();
    match body.rfind('_') {
        Some(i) => body[..i].to_string(),
        None => String::new(),
    }
}

/// 后缀是否允许进索引：必须 6 位纯辅音（hex6 不进，对齐 `_suffix_indexable`）。
pub fn suffix_indexable(suffix: &str) -> bool {
    suffix.len() == 6 && suffix.bytes().all(|b| TOKEN_ALPHABET.contains(&b))
}

/// 严格完整占位符正则（`_PLACEHOLDER_RX`）。
pub fn placeholder_rx() -> &'static Regex {
    static RX: Lazy<Regex> =
        Lazy::new(|| Regex::new(&format!(r"\{{\{{[A-Z0-9]{{1,12}}_{SUFFIX_PAT}\}}\}}")).unwrap());
    &RX
}

/// 容错双花括号占位符（允许内部空白/大小写改写，`_BRACED_PLACEHOLDER_RX`）。
pub fn braced_placeholder_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"\{{\{{\s*([A-Za-z0-9_]{{1,12}})({SUFFIX_PAT})\s*\}}\}}"
        ))
        .unwrap()
    });
    &RX
}

/// 任意花括号 + 后缀（行首行尾锚定，大小写不敏感；`_ANY_BRACED_SUFFIX_RX`）。
pub fn any_braced_suffix_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"(?i)^\{{\{{\s*([A-Za-z0-9_]{{1,12}})({SUFFIX_PAT})\s*\}}\}}$"
        ))
        .unwrap()
    });
    &RX
}

/// 转义形态（`\{\{X\}\}` / `\\{\\{X\\}\\}`，`_ESCAPED_PLACEHOLDER_RX`）。
pub fn escaped_placeholder_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"(?:\\{{0,3}}\{{){{1,3}}(?:\\{{0,3}})\s*([A-Za-z0-9_]{{1,12}})_({SUFFIX_PAT})\s*(?:\\{{0,3}}\}}){{1,3}}"
        ))
        .unwrap()
    });
    &RX
}

/// 宽松形态（花括号被剥掉 / 半残，`_LOOSE_PLACEHOLDER_RX`）。
pub fn loose_placeholder_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"\{{{{1,2}}\s*([A-Za-z0-9_]{{1,12}}_{SUFFIX_PAT})\s*\}}{{0,2}}|([A-Z0-9]{{1,12}}_{SUFFIX_PAT})"
        ))
        .unwrap()
    });
    &RX
}

/// 行尾半截占位符（流式扣留判定，`_PARTIAL_RX`）。
/// 反斜杠封顶 {0,3}、空白封顶 {0,4}，防 O(N²)（对齐 Python 修复）。
pub fn partial_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?:\\{0,3}\{){1,3}\s{0,4}[A-Za-z0-9_]{0,20}\s{0,4}\\{0,3}\}?\\{0,3}$|\\{1,3}$")
            .unwrap()
    });
    &RX
}

/// 扣留上限（`_PARTIAL_MAX`）：必须 ≥ _PARTIAL_RX 理论最长匹配。
pub const PARTIAL_MAX: usize = 48;

/// token 解析出的 (label_canonical, suffix)。
pub fn parse_canonical(token: &str) -> Option<(String, String)> {
    if placeholder_rx().is_match(token) {
        return Some((token_label(token), token_suffix(token)));
    }
    None
}

/// 归一化 token：`{{LABEL_suffix}}`（label 大写、suffix 小写）。
pub fn canonicalize(label_raw: &str, suffix: &str) -> String {
    format!(
        "{{{{{}_{}}}}}",
        safe_label(label_raw),
        suffix.to_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_label_basics() {
        assert_eq!(safe_label("phone"), "PHONE");
        assert_eq!(safe_label("自定义"), "TERM");
        assert_eq!(safe_label("IP-PRIVATE_2024"), "IPPRIVATE202"); // 截到 12 位
        assert_eq!(safe_label(""), "TERM");
        assert_eq!(safe_label("ABCDEFGHIJKLMNOPQ"), "ABCDEFGHIJKL");
    }

    #[test]
    fn token_suffix_and_label() {
        assert_eq!(token_suffix("{{PHONE_kkmmnp}}"), "kkmmnp");
        assert_eq!(token_label("{{PHONE_kkmmnp}}"), "PHONE");
        assert_eq!(token_suffix("{{IP_PRIVATE_zzxkkk}}"), "zzxkkk");
        assert_eq!(token_label("{{IP_PRIVATE_zzxkkk}}"), "IP_PRIVATE");
        assert_eq!(token_suffix("plain"), "");
    }

    #[test]
    fn suffix_indexable_rejects_hex() {
        assert!(suffix_indexable("bcdfgh"));
        assert!(!suffix_indexable("abc123"));
        assert!(!suffix_indexable("abc"));
    }

    #[test]
    fn new_token_uses_consonant_suffix() {
        let taken = |_t: &str, _s: &str| false;
        let tok = new_token("PHONE", &taken);
        assert!(placeholder_rx().is_match(&tok), "token={tok}");
        assert!(tok.starts_with("{{PHONE_"));
    }

    #[test]
    fn new_token_avoids_taken_suffixes() {
        let taken = |_t: &str, s: &str| s == "bbbbbb";
        let tok = new_token("TEST", &taken);
        assert!(!tok.contains("bbbbbb"));
    }

    #[test]
    fn regexes_match_python_shapes() {
        assert!(placeholder_rx().is_match("{{PHONE_abc123}}"));
        assert!(placeholder_rx().is_match("{{TERM_bcdfgh}}"));
        assert!(!placeholder_rx().is_match("{{phone_abc123}}"));
        assert!(!placeholder_rx().is_match("{{PHONE_abc12}}"));
        assert!(braced_placeholder_rx().is_match("{{ email_bcdfgh }}"));
        assert!(braced_placeholder_rx().is_match("{{EMAIL_abcdef}}"));
        assert!(escaped_placeholder_rx().is_match(r"\{\{EMAIL_abcdef\}\}"));
        assert!(escaped_placeholder_rx().is_match(r"\\{\\{EMAIL_abcdef\\}\\}"));
        assert!(loose_placeholder_rx().is_match("SECRET_b5a53c"));
        assert!(loose_placeholder_rx().is_match("{{SECRET_b5a53c"));
        assert!(partial_rx().is_match("结尾{{NAME_ab"));
        assert!(partial_rx().is_match("文本\\"));
        assert!(!partial_rx().is_match("普通文本结尾"));
    }

    #[test]
    fn partial_hold_length_bounded() {
        let text = format!("{{{{{}{}", "a".repeat(65), "");
        assert!(!partial_hold(&text), "超长不扣留");
    }

    /// 流式扣留判定（对齐 Python restore() 的 _PARTIAL_RX + _PARTIAL_MAX 逻辑）。
    fn partial_hold(buf: &str) -> bool {
        match partial_rx().find(buf) {
            Some(m) => m.end() == buf.len() && m.len() <= PARTIAL_MAX,
            None => false,
        }
    }

    /// 正则必须是静态缓存（回归：每次调用重新编译会让热路径慢一个数量级）。
    #[test]
    fn regexes_are_cached() {
        let a = placeholder_rx() as *const Regex;
        let b = placeholder_rx() as *const Regex;
        assert_eq!(a, b, "placeholder_rx 必须返回同一实例");
        assert_eq!(partial_rx() as *const Regex, partial_rx() as *const Regex);
        assert_eq!(
            loose_placeholder_rx() as *const Regex,
            loose_placeholder_rx() as *const Regex
        );
        // 1000 次调用应远快于 1000 次编译（编译约 10µs 级 → 10ms）
        let t0 = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = placeholder_rx().is_match("{{PHONE_bcdfgh}}");
        }
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert!(ms < 200.0, "1 万次占位符匹配耗时 {ms:.1}ms（正则未缓存？）");
    }
}
