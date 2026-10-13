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

/// 自定义敏感词的**确定性后缀**（对齐 Python `_deterministic_suffix`）。
///
/// 为什么自定义词要确定性、普通敏感值要随机：
/// - 普通敏感值（手机号/邮箱）必须随机 → 防上游枚举反推原文（安全红线）
/// - 自定义词由用户显式配置、原文本就在 config.json 里，**不存在泄漏风险**；
///   而它需要跨进程稳定：长任务 / Agent 工具调用跨越重启时，历史消息里的
///   `{{TERM_xxx}}` 必须还能还原，否则用户看到裸占位符。
///
/// 派生方式：sha256("maskit_cw:{counter}:{word}") 取前 6 字节映射到辅音字母表；
/// 词表内撞车时递增 counter 重试（保证词表内唯一）。
pub fn deterministic_suffix(orig: &str, used: &mut std::collections::HashSet<String>) -> String {
    use sha2::{Digest, Sha256};
    let alphabet = TOKEN_ALPHABET;
    let mut counter: u32 = 0;
    loop {
        let mut h = Sha256::new();
        h.update(format!("maskit_cw:{counter}:{orig}").as_bytes());
        let digest = h.finalize();
        let suffix: String = digest
            .iter()
            .take(6)
            .map(|b| alphabet[(*b as usize) % alphabet.len()] as char)
            .collect();
        if used.insert(suffix.clone()) {
            return suffix;
        }
        counter += 1;
    }
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
///
/// ⚠️ label 与 suffix 之间有**必需的 `_`**（与 Python 逐字一致）。
/// 曾漏掉这个下划线：`([A-Za-z0-9_]{1,12})` 贪婪吃满 12 字符后接不上 6 位后缀，
/// 于是 12 字符标签（`safe_label` 的上限，如 `CUSTOMERID20`）永远匹配不上；
/// 而宽松遍又会把「看起来完整的 `{{…}}`」当已处理跳过 → **该占位符永久还原不回来**。
/// 反向副作用是会把缺下划线的畸形形态 `{{TERMxxxxxx}}` 误认成占位符。
pub fn braced_placeholder_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"\{{\{{\s*([A-Za-z0-9_]{{1,12}})_((?i:{SUFFIX_PAT}))\s*\}}\}}"
        ))
        .unwrap()
    });
    &RX
}

/// 任意花括号 + 后缀（行首行尾锚定，大小写不敏感；`_ANY_BRACED_SUFFIX_RX`）。
pub fn any_braced_suffix_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"(?i)^\{{\{{\s*([A-Za-z0-9_]{{1,12}})_({SUFFIX_PAT})\s*\}}\}}$"
        ))
        .unwrap()
    });
    &RX
}

/// 转义形态（`\{\{X\}\}` / `\\{\\{X\\}\\}`，`_ESCAPED_PLACEHOLDER_RX`）。
///
/// ⚠️ 必须 `(?i)`（与 Python 的 `re.IGNORECASE` 一致）：模型「转义 + 顺手大写」
/// 会产出 `\{\{TERM_BKRHVH\}\}`，后缀字符类只写了小写辅音/hex，
/// 缺 IGNORECASE 就整条匹配不上（`canonicalize` 本来会把后缀转小写）。
pub fn escaped_placeholder_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"(?i)(?:\\{{0,3}}\{{){{1,3}}(?:\\{{0,3}})\s*([A-Za-z0-9_]{{1,12}})_({SUFFIX_PAT})\s*(?:\\{{0,3}}\}}){{1,3}}"
        ))
        .unwrap()
    });
    &RX
}

/// 宽松形态（花括号被剥掉 / 半残，`_LOOSE_PLACEHOLDER_RX`）。
pub fn loose_placeholder_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r"\{{{{1,2}}\s*([A-Za-z0-9_]{{1,12}}_(?i:{SUFFIX_PAT}))\s*\}}{{0,2}}|([A-Z0-9]{{1,12}}_(?i:{SUFFIX_PAT}))"
        ))
        .unwrap()
    });
    &RX
}

/// 行尾半截占位符（流式扣留判定，`_PARTIAL_RX`）。
/// 反斜杠封顶 {0,3}、空白封顶 {0,4}，防 O(N²)（对齐 Python 修复）。
///
/// 末位分支 `[A-Z0-9]{1,12}_[a-z0-9]{0,5}$` 覆盖**裸形态**（无花括号）残片：
/// 模型常把占位符降级成 `TERM_bcdfgh`，而还原侧的宽松遍
/// （`loose_placeholder_rx` 的第二分支）是认这种形态的 —— 若扣留正则不认，
/// 上游把它拆到两个 chunk 时两半都会被直接下发，且**永远拼不回来**。
///
/// 该分支要求后缀不足 6 位才命中，因此**完整**的裸 token（6 位后缀）不会被扣留；
/// 副作用是「以 `大写词_` 结尾」的普通文本可能被多扣一个 chunk，
/// 但扣留内容会与下一块精确拼接、并在终止事件/流末补发，不会丢内容。
pub fn partial_rx() -> &'static Regex {
    static RX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?:\\{0,3}\{){1,3}\s{0,4}[A-Za-z0-9_]{0,20}\s{0,4}\\{0,3}\}?\\{0,3}$|\\{1,3}$|[A-Z0-9]{1,12}_[a-z0-9]{0,5}$",
        )
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
        // 大写后缀（模型转义+大写改写）必须认（Python 侧是 re.IGNORECASE）
        assert!(escaped_placeholder_rx().is_match(r"\{\{TERM_BKRHVH\}\}"));
        assert!(loose_placeholder_rx().is_match("SECRET_b5a53c"));
        assert!(loose_placeholder_rx().is_match("{{SECRET_b5a53c"));
        assert!(partial_rx().is_match("结尾{{NAME_ab"));
        assert!(partial_rx().is_match("文本\\"));
        assert!(!partial_rx().is_match("普通文本结尾"));
        // 裸形态残片(无花括号)必须扣留:模型会把占位符降级成 `TERM_bcdfgh`,
        // 而宽松遍是认这种形态的 —— 不扣留就永远拼不回来。
        assert!(partial_rx().is_match("电话 TERM_bc"));
        assert!(partial_rx().is_match("TERM_"), "刚吐出下划线也要扣");
        // **完整**的裸 token(6 位后缀)不得扣留,否则会白等一个 chunk
        assert!(!partial_rx().is_match("TERM_bcdfgh"));
        assert!(!partial_rx().is_match("电话 TERM_bcdfgh"));
        // 长度上限必须覆盖新分支的理论最大匹配：12(标签)+1(下划线)+5(后缀) = 18
        const _: () = assert!(PARTIAL_MAX >= 18);
    }

    /// 回归：label 与 suffix 之间**必须**有下划线。
    ///
    /// 12 字符标签（`safe_label` 上限）曾因缺 `_` 而整条匹配不上，
    /// 导致该占位符永久还原不回来；反过来 `{{TERMxxxxxx}}`（无下划线）被误认。
    #[test]
    fn braced_requires_underscore_separator() {
        // 12 字符标签：必须匹配，且切成 (label, suffix)
        let c = braced_placeholder_rx()
            .captures("{{CUSTOMERID20_nsvdqs}}")
            .expect("12 字符标签必须能解析");
        assert_eq!(&c[1], "CUSTOMERID20");
        assert_eq!(&c[2], "nsvdqs");
        // any_braced_suffix_rx 同理（后缀反查靠它）
        let c2 = any_braced_suffix_rx()
            .captures("{{CUSTOMERID20_nsvdqs}}")
            .expect("12 字符标签必须能按后缀反查");
        assert_eq!(&c2[1], "CUSTOMERID20");
        // 缺下划线的畸形形态不得被当成占位符（Python 同样不认）
        assert!(!braced_placeholder_rx().is_match("{{TERMfwggbs}}"));
        assert!(!any_braced_suffix_rx().is_match("{{TERMfwggbs}}"));
        assert!(!placeholder_rx().is_match("{{TERMfwggbs}}"));
    }

    /// 回归:后缀大小写不敏感。
    ///
    /// 模型常把占位符后缀写成大写(`{{PHONE_CQPPJV}}`),而 `canonicalize`
    /// 本就会把后缀小写化、`escaped_placeholder_rx` 也早就有 `(?i)` ——
    /// 但 `braced` / `loose` 两条缺了它,导致「纯大写后缀」形态三遍扫描全部
    /// 错过,占位符**原样下发给客户端**(agent 拿到 `{{PHONE_CQPPJV}}`)。
    /// 用作用域 `(?i:...)` 只放宽后缀,不动标签类。
    #[test]
    fn suffix_case_insensitive() {
        // 双花括号形态
        let c = braced_placeholder_rx()
            .captures("{{PHONE_CQPPJV}}")
            .expect("大写后缀必须被 braced 认到");
        assert_eq!(&c[1], "PHONE");
        assert_eq!(c[2].to_lowercase(), "cqppjv");
        // 宽松形态:单层花括号 + 大写后缀
        assert!(loose_placeholder_rx().is_match("{PHONE_CQPPJV}"));
        // 宽松形态:裸 token + 大写后缀
        assert!(loose_placeholder_rx().is_match("PHONE_CQPPJV"));
        // 大小写混合
        assert!(braced_placeholder_rx().is_match("{{TERM_BcDfGh}}"));
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

    /// 正则必须是静态缓存(回归:每次调用重新编译会让热路径慢一个数量级)。
    ///
    /// 工判据分两层:
    ///   1. **指针同一** —— 确定性证明缓存生效(不依赖计时)。
    ///   2. **相对倍率** —— 对比「直接取缓存」与「现场编译 regex」的耗时。
    ///
    /// 为什么不用绝对阀值：早期断言「1 万次 < 200ms」在 debug 下本已接近上限，
    /// 共享 CI runner 被抢占时实测漂到 **205ms** —— 与「未缓存」区间重叠，
    /// 既会误报又不敢收紧。而缓存与现编的成本差是**三个数量级**
    /// (release 实测：0.61ms vs 832ms / 万次)，用倍率判官对负载不敏感。
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

        // ── 相对倍率：缓存 vs 现场编译 ──
        const N: u32 = 2_000;
        let t_cached = std::time::Instant::now();
        for _ in 0..N {
            let _ = placeholder_rx().is_match("{{PHONE_bcdfgh}}");
        }
        let cached = t_cached.elapsed();

        // 与 placeholder_rx 同形态的正则，现场编译 + 匹配
        let pat = format!(r"\{{\{{\s*([A-Za-z0-9_]{{1,12}})_((?i:{SUFFIX_PAT}))\s*\}}\}}");
        let t_compile = std::time::Instant::now();
        for _ in 0..N {
            let rx = Regex::new(&pat).unwrap();
            let _ = rx.is_match("{{PHONE_bcdfgh}}");
        }
        let compiled = t_compile.elapsed();

        // 因为缓存的单次成本接近空循环，极端抢占下 `cached` 可能极小，
        // 倍率噪声会很大；因此只在「比较对象明显占优时才要求高倍率」。
        let ratio = compiled.as_secs_f64() / cached.as_secs_f64().max(1e-9);
        assert!(
            ratio > 20.0,
            "缓存应至少快 20 倍(实测 {ratio:.1}x：缓存 {cached:?} vs 现编 {compiled:?})\n\
             —— 若接近 1x 说明正则未被缓存"
        );
    }
}
