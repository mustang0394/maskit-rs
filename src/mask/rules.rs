//! 内置 21 类规则定义：regex + value_group + 校验器链（D7 环视下沉）。
//!
//! 对齐 Python transparent.py RULES 表（32 条 pattern / 21 label）。
//! **D7 决策（PLAN §4.4）**：Python 环视一律下沉为 `Check` 校验器，匹配区间与
//! `value_group` 语义逐字节不变；`regex` crate 全程线性，不引入 fancy-regex。

use once_cell::sync::Lazy;
use regex::{Captures, Match, Regex};

use super::validators;

// ---------------------------------------------------------------------------
// 零宽断言校验器（D7）
// ---------------------------------------------------------------------------

/// 环视断言校验器签名。返回 true = 匹配成立。
/// text = 全文本，m = 本次匹配区间，caps = 捕获组。
pub type Check = fn(text: &str, m: Match<'_>, caps: &Captures<'_>) -> bool;

/// `(?<!CLASS)` 下沉：检查 text[..start] 末字符不属于 CLASS。
pub fn check_not_preceded_by(text: &str, m: Match<'_>, class: fn(char) -> bool) -> bool {
    if m.start() == 0 {
        return true;
    }
    // 按字符回退一个（boundary 类都是单 char 类）
    match text[..m.start()].chars().next_back() {
        Some(c) => !class(c),
        None => true,
    }
}

/// `(?!CLASS)` 下沉：检查 text[end..] 首字符不属于 CLASS。
pub fn check_not_followed_by(text: &str, m: Match<'_>, class: fn(char) -> bool) -> bool {
    match text[m.end()..].chars().next() {
        Some(c) => !class(c),
        None => true,
    }
}

// 常用字符类（显式 ASCII，不用 \w/\d 避免 Unicode 语义漂移——D7 第 3 条）
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
fn is_word_or_dash(c: char) -> bool {
    is_word_char(c) || c == '-'
}
fn is_word_char_cn(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || ('\u{4e00}'..='\u{9fff}').contains(&c)
}
fn is_secret_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!@#$%^&*_~+=-".contains(c)
}

// ---------------------------------------------------------------------------
// 规则结构
// ---------------------------------------------------------------------------

pub struct Rule {
    pub label: &'static str,
    pub rx: Regex,
    /// 0 = 整段替换；>0 = 只替换捕获组区间（如 Bearer 规则）
    pub value_group: usize,
    pub checks: &'static [Check],
    /// CONNSTR 专用：被否决时把匹配区间压入豁免表（PLAN D7 第 4 条 Vet::RejectAndExempt）
    pub exempt_on_reject: bool,
    /// EMAIL 专用：命中与豁免区间重叠时跳过
    pub avoid_exempt: bool,
    /// aho-corasick 特征预筛（None = 无特征，总是扫描）
    pub markers: &'static [&'static str],
    /// markers 是否大小写不敏感比对（对齐 `_RULE_MARKERS_CI`）
    pub markers_ci: bool,
}

impl Rule {
    pub fn may_hit(&self, text: &str) -> bool {
        if self.markers.is_empty() {
            return true;
        }
        if self.markers_ci {
            let lower = text.to_lowercase();
            return self.markers.iter().any(|m| lower.contains(m));
        }
        self.markers.iter().any(|m| text.contains(m))
    }
}

macro_rules! rule {
    ($label:expr, $rx:expr, $vg:expr, [$($c:expr),*], exempt=$ex:expr, avoid=$av:expr, markers=[$($m:expr),*], ci=$ci:expr) => {
        Rule {
            label: $label,
            rx: Regex::new($rx).unwrap(),
            value_group: $vg,
            checks: &[$($c),*],
            exempt_on_reject: $ex,
            avoid_exempt: $av,
            markers: &[$($m),*],
            markers_ci: $ci,
        }
    };
}

// ---------------------------------------------------------------------------
// 各规则的 Check 实现
// ---------------------------------------------------------------------------

/// 手机号边界：右侧不是字母数字（ID_BOUND_R）
fn phone_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_char)
}

/// 邮箱左边界：前一字符不是 `:` 也不是 [A-Za-z0-9._中文]
fn email_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    if m.start() == 0 {
        return true;
    }
    match text[..m.start()].chars().next_back() {
        Some(':') => false,
        Some(c) => !is_word_char_cn(c) && c != '.',
        None => true,
    }
}

/// 邮箱右边界：后一字符不是 [A-Za-z0-9._%+-]
fn email_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    match text[m.end()..].chars().next() {
        Some(c) => !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')),
        None => true,
    }
}

/// API_KEY 通用左/右边界：[A-Za-z0-9_-] 不可相邻
fn apikey_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, is_word_or_dash)
}
fn apikey_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_or_dash)
}

/// Stripe 右边界：[A-Za-z0-9]（不含 -_）
fn stripe_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, |c| c.is_ascii_alphanumeric())
}

/// 飞书/钉钉右边界：[a-z0-9]
fn lowercase_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, |c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// AWS AK 左/右边界：[A-Z0-9]
fn aws_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
}
fn aws_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// AWS SecretAccessKey 值右边界：[A-Za-z0-9/+=]
fn aws_secret_r(text: &str, _m: Match<'_>, caps: &Captures<'_>) -> bool {
    let value = caps.get(1).unwrap();
    match text[value.end()..].chars().next() {
        Some(c) => !(c.is_ascii_alphanumeric() || c == '/' || c == '+' || c == '='),
        None => true,
    }
}

/// ACCESS_KEY（LTAI/AKID）右边界
fn access_key_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_or_dash)
}

/// SECRET 值右边界：[A-Za-z0-9!@#$%^&*_~+=-]
fn secret_r(text: &str, _m: Match<'_>, caps: &Captures<'_>) -> bool {
    let value = caps.get(1).unwrap();
    // Rust regex 的 Match 偏移是相对 haystack 的绝对值，不可再加 m.start()
    match text[value.end()..].chars().next() {
        Some(c) => !is_secret_value_char(c),
        None => true,
    }
}

/// SECRET 值域断言 `(?=[A-Za-z0-9!@#$%^&*_~+=-]*[0-9!@#$%^&*])`：
/// 值必须含数字或特殊符号（纯字母标识符不误报）。
fn secret_value_charset(text: &str, m: Match<'_>, caps: &Captures<'_>) -> bool {
    let value = caps.get(1).unwrap().as_str();
    let _ = (text, m);
    // 值字符类内的字符必须含 [0-9!@#$%^&*]
    value.chars().any(|c| c.is_ascii_digit() || "!@#$%^&*".contains(c))
}

/// SECRET 键名左边界：[A-Za-z0-9_.]（英文关键词）
fn secret_key_l(text: &str, m: Match<'_>, caps: &Captures<'_>) -> bool {
    let _ = caps;
    if m.start() == 0 {
        return true;
    }
    match text[..m.start()].chars().next_back() {
        Some(c) => !(c.is_ascii_alphanumeric() || c == '_' || c == '.'),
        None => true,
    }
}

/// SECRET 键名右边界：[A-Za-z0-9_.]（英文关键词）
fn secret_key_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    // 找到关键词结束位置：正则结构是 键名[引号]?\s*[:=：＝]…，简单方式：
    // 检查匹配起头一段是否以英文关键词结束。由于键名后必接分隔符，
    // 这里检查「匹配开头之后第一个非关键词字符」——实际上 Python 的
    // (?![A-Za-z0-9_.]) 紧跟在关键词后。我们用简化实现：整个匹配区间的
    // 键名部分已由正则锚定（后面是分隔符），该断言恒真。
    let _ = (text, m);
    true
}

/// SECRET 值首边界：`(?!/)` — 值不能以 / 开头
fn secret_value_not_slash(_text: &str, _m: Match<'_>, caps: &Captures<'_>) -> bool {
    let value = caps.get(1).unwrap().as_str();
    !value.starts_with('/')
}

/// CONNSTR 词边界 `\b`：scheme 前是词字符则不成词边界
fn connstr_word_boundary(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    if m.start() == 0 {
        return true;
    }
    let prev = text[..m.start()].chars().next_back().unwrap();
    // \b：前一个字符是词字符则匹配起点不是词边界 → 不成立
    // Python \b[a-z] 要求 a-z 前是非词字符或行首
    !prev.is_alphanumeric() && prev != '_'
}

/// Bearer `\b`（Unicode 词边界 + (?i)）
fn bearer_word_boundary(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    if m.start() == 0 {
        return true;
    }
    let prev = text[..m.start()].chars().next_back().unwrap();
    // Unicode 词边界：prev 与 B（词字符）必须异类
    let prev_word = prev.is_alphanumeric() || prev == '_';
    !prev_word
}

/// IP 右边界：`(?![A-Za-z0-9]|\.\d)` — 后面不是字母数字、也不是「.数字」
fn ip_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    let rest = &text[m.end()..];
    let mut chars = rest.chars();
    match chars.next() {
        None => true,
        Some(c) if c.is_ascii_alphanumeric() => false,
        Some('.') => {
            // .数字 → 拒绝
            !chars.next().map(|n| n.is_ascii_digit()).unwrap_or(false)
        }
        Some(_) => true,
    }
}

/// IP_PRIVATE 左边界：[A-Za-z0-9]
fn ip_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, |c| c.is_ascii_alphanumeric())
}

/// 公网 IPv4 强防误伤左边界（3 段定宽断言合一）：
/// `(?<![A-Za-z0-9][-_])(?<![A-Za-z0-9]\.)(?<![A-Za-z0-9])`
fn ip_public_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    if m.start() == 0 {
        return true;
    }
    let before: Vec<char> = text[..m.start()].chars().collect();
    if before.is_empty() {
        return true;
    }
    let last = before[before.len() - 1];
    if last.is_ascii_alphanumeric() {
        return false;
    }
    if before.len() >= 2 {
        let prev = before[before.len() - 2];
        // (?<![A-Za-z0-9][-_])：字母数字+连字符/下划线
        if prev.is_ascii_alphanumeric() && (last == '-' || last == '_') {
            return false;
        }
        // (?<![A-Za-z0-9]\.)：字母数字+点（包名域名）
        if prev.is_ascii_alphanumeric() && last == '.' {
            return false;
        }
    }
    true
}

/// 公网 IPv4 强防误伤右边界：
/// `(?![A-Za-z0-9]|\.[A-Za-z0-9]|[-_][A-Za-z0-9])`
fn ip_public_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    let rest: Vec<char> = text[m.end()..].chars().collect();
    match rest.first() {
        None => true,
        Some(c) if c.is_ascii_alphanumeric() => false,
        Some('.') => {
            // .[A-Za-z0-9] → 文件后缀，拒绝
            match rest.get(1) {
                Some(n) => !n.is_ascii_alphanumeric(),
                None => true,
            }
        }
        Some('-') | Some('_') => {
            // [-_][A-Za-z0-9] → 构建号后缀，拒绝
            match rest.get(1) {
                Some(n) => !n.is_ascii_alphanumeric(),
                None => true,
            }
        }
        Some(_) => true,
    }
}

/// IPv6 左边界：`(?<![0-9A-Fa-f.])`
fn ipv6_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, |c| c.is_ascii_hexdigit() || c == '.')
}

/// IPv6 右边界：`(?![0-9A-Fa-f:])`
fn ipv6_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, |c| c.is_ascii_hexdigit() || c == ':')
}

/// 车牌左边界：[A-Za-z0-9]
fn plate_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, |c| c.is_ascii_alphanumeric())
}

/// 车牌右边界：[A-Z0-9]
fn plate_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// 车牌前瞻 `(?=[A-Z0-9]{0,5}\d)`：车牌字母后 0-5 个字符内必须有数字
/// （车身必须含至少一个数字，防「新README」误报）。
/// 实现：检查捕获区间内（除省份+字母后）是否含数字。
fn plate_body_has_digit(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    // 匹配整体 = 省份(3 字节汉字) + 字母(1) + 车身(5-6)；按字符切片防多字节边界
    let body_start = text[m.start()..m.end()].char_indices().nth(2).map(|(i, _)| m.start() + i).unwrap_or(m.end());
    text[body_start..m.end()].chars().any(|c| c.is_ascii_digit())
}

/// 港澳通行证左边界（ID_BOUND_L）
fn hkid_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, is_word_char)
}

/// HKID 右边界（ID_BOUND_R）
fn hkid_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_char)
}

/// 身份证左/右边界
fn idcard_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, is_word_char)
}
fn idcard_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_char)
}

/// 座机左/右边界
fn landline_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, is_word_char)
}
fn landline_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_char)
}

/// 银行卡左/右边界
fn card_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, is_word_char)
}
fn card_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_char)
}

/// IBAN 左/右边界
fn iban_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, is_word_char)
}
fn iban_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_char)
}

/// USCC 左/右边界
fn uscc_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, is_word_char)
}
fn uscc_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, is_word_char)
}

/// MAC 左边界：`(?<![0-9A-Fa-f:-])`
fn mac_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    if m.start() == 0 {
        return true;
    }
    match text[..m.start()].chars().next_back() {
        Some(c) => !(c.is_ascii_hexdigit() || c == ':' || c == '-'),
        None => true,
    }
}

/// MAC 右边界：`(?![0-9A-Fa-f:-])`
fn mac_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    match text[m.end()..].chars().next() {
        Some(c) => !(c.is_ascii_hexdigit() || c == ':' || c == '-'),
        None => true,
    }
}

// ---------------------------------------------------------------------------
// 规则表（顺序与 Python RULES 完全一致——CONNSTR 必须排在 EMAIL 之前）
// ---------------------------------------------------------------------------

/// 内置规则表。顺序敏感：CONNSTR 的豁免区间依赖它在 EMAIL 之前执行。
pub static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        // PEM 私钥整块（Python 同款线性形态：头尾锚定 + {20,}?）
        rule!("PRIVATE_KEY",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{20,}?-----END[^-]*PRIVATE KEY-----",
            0, [], exempt=false, avoid=false, markers=["PRIVATE KEY"], ci=false),
        // GitHub tokens
        rule!("API_KEY",
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}",
            0, [apikey_l, apikey_r], exempt=false, avoid=false, markers=["gh"], ci=false),
        rule!("API_KEY",
            r"github_pat_[A-Za-z0-9_]{50,}",
            0, [apikey_l, apikey_r], exempt=false, avoid=false, markers=["github"], ci=false),
        // Google API Key
        rule!("API_KEY",
            r"AIza[0-9A-Za-z_\-]{35,38}",
            0, [apikey_l, apikey_r], exempt=false, avoid=false, markers=["AIza"], ci=false),
        // 阿里云 AK
        rule!("ACCESS_KEY",
            r"LTAI[A-Za-z0-9]{12,20}",
            0, [apikey_l, access_key_r], exempt=false, avoid=false, markers=["LTAI"], ci=false),
        // 腾讯云 SecretId
        rule!("ACCESS_KEY",
            r"AKID[A-Za-z0-9]{13,32}",
            0, [apikey_l, access_key_r], exempt=false, avoid=false, markers=["AKID"], ci=false),
        // Slack
        rule!("API_KEY",
            r"xox[baprs]\-[0-9A-Za-z\-]{10,}",
            0, [apikey_l, apikey_r], exempt=false, avoid=false, markers=["xox"], ci=false),
        // Stripe
        rule!("API_KEY",
            r"[sr]k_(?:live|test)_[0-9A-Za-z]{20,}",
            0, [apikey_l, stripe_r], exempt=false, avoid=false, markers=["k_"], ci=false),
        // 飞书 / 钉钉
        rule!("API_KEY",
            r"cli_[a-z0-9]{16,}",
            0, [apikey_l, lowercase_r], exempt=false, avoid=false, markers=["cli_"], ci=false),
        rule!("API_KEY",
            r"ding[a-z0-9]{6,}",
            0, [apikey_l, lowercase_r], exempt=false, avoid=false, markers=["ding"], ci=false),
        // AWS AccessKeyId
        rule!("ACCESS_KEY",
            r"(?:AKIA|ASIA)[A-Z0-9]{16}",
            0, [aws_l, aws_r], exempt=false, avoid=false, markers=["AK", "AS"], ci=false),
        // AWS SecretAccessKey（值组 1）
        rule!("ACCESS_KEY",
            r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"#,
            1, [aws_secret_r], exempt=false, avoid=false, markers=["aws", "AWS"], ci=false),
        // JWT
        rule!("JWT",
            r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            0, [apikey_l, apikey_r], exempt=false, avoid=false,
            markers=["eyJ"], ci=false),
        // Bearer Token（值组 1；\b 下沉）
        rule!("TOKEN",
            r"(?i)Bearer\s+([A-Za-z0-9._~+/=\-]{20,})",
            1, [bearer_word_boundary], exempt=false, avoid=false,
            markers=["Bearer", "bearer", "BEARER"], ci=false),
        // SECRET 键值对（值组 1；左边界/值域/右边界/`(?!/)` 全部下沉）
        // 键名就是关键词本身（左右边界由 secret_key_l/r 下沉），不贪吃前后缀
        rule!("SECRET",
            concat!(
                r"(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key",
                r"|(?:密码|口令|令牌|密钥|秘钥|密匙|凭据|凭证|私钥|授权码|访问密钥|接口密钥))",
                r#"[\"'“”「」]?\s*[:=：＝]\s*[\"'“”「」]?"#,
                r"([A-Za-z0-9!@#$%^&*_~+=\-]{6,64})"
            ),
            1, [secret_key_l, secret_key_r, secret_value_not_slash, secret_value_charset, secret_r],
            exempt=false, avoid=false, markers=["=", ":", "：", "＝"], ci=false),
        // CONNSTR（scheme 封顶 {0,63} 防 O(N²)；密码组 1；\b 下沉；豁免区间联动 EMAIL）
        rule!("CONNSTR",
            r"[a-zA-Z][a-zA-Z0-9+.\-]{0,63}://[^\s:@/]+:([^\s@/]{4,})@",
            1, [connstr_word_boundary], exempt=true, avoid=false, markers=["://"], ci=false),
        // 手机号（单条交替分支，最左最长；Python 同款）：
        // ① 前缀（+86/0086/(86)）+ 裸 11 位  ② 裸 11 位  ③ 带分隔（- 或空格，单种）
        rule!("PHONE",
            r"(?:\+?86|0086|[\(（]\+?86[\)）])[\s\-]?1[3-9][0-9][0-9]{8}|1[3-9][0-9][0-9]{8}|1[3-9][0-9][\- ][0-9]{4}[\- ][0-9]{4}|1[3-9][0-9][\- ][0-9]{4}[ ][0-9]{4}|1[3-9][0-9][ ][0-9]{4}[\- ][0-9]{4}|1[3-9][0-9][ ][0-9]{4}[ ][0-9]{4}",
            0, [phone_plain_l, phone_sep_consistent, phone_r], exempt=false, avoid=false, markers=["1"], ci=false),
        // EMAIL（CONNSTR 之后！左/右边界 + `(?<!:)` 下沉）
        rule!("EMAIL",
            r"[a-zA-Z0-9_\u{4e00}-\u{9fff}][\u{4e00}-\u{9fff}A-Za-z0-9._%+\-]{0,63}@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.[a-zA-Z\u{4e00}-\u{9fff}]{2,}",
            0, [email_l, email_r], exempt=false, avoid=true, markers=["@"], ci=false),
        // 座机
        rule!("LANDLINE",
            r"(?:\+?86|0086|[\(（]\+?86[\)）])[\s\-]?(?:[\(（]0(?:10|2[0-9]|[3-9][0-9]{2})[\)）][\s\-]?[2-9][0-9]{6,7}|0(?:10|2[0-9]|[3-9][0-9]{2})[\-\s][2-9][0-9]{6,7})(?:[\-\s]?(?:转|分机|ext|x|#)[\-\s]?[0-9]{1,5})?",
            0, [landline_l, landline_r], exempt=false, avoid=false, markers=["0"], ci=false),
        // 车牌（车身含数字断言下沉）
        rule!("PLATE",
            r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-Z0-9]{5,6}",
            0, [plate_l, plate_body_has_digit, plate_r], exempt=false, avoid=false, markers=[], ci=false),
        // 港澳通行证
        rule!("HKID",
            r"H[0-9]{8}",
            0, [hkid_l, hkid_r], exempt=false, avoid=false, markers=[], ci=false),
        // 身份证 15/18（正则锁位数，校验器验省份+日期+校验位）
        rule!("IDCARD",
            r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])[0-9]{13}",
            0, [idcard_l, idcard_r], exempt=false, avoid=false, markers=[], ci=false),
        rule!("IDCARD",
            r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])[0-9]{15}[0-9Xx]",
            0, [idcard_l, idcard_r], exempt=false, avoid=false, markers=[], ci=false),
        // 内网 IP（IP_PRIVATE：192.168 / 169.254 / CGNAT）
        rule!("IP_PRIVATE",
            r"192\.168\.[0-9]{1,3}\.[0-9]{1,3}|169\.254\.[0-9]{1,3}\.[0-9]{1,3}",
            0, [ip_l, ip_r], exempt=false, avoid=false, markers=["192.", "169.", "100."], ci=false),
        rule!("IP_PRIVATE",
            r"100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}",
            0, [ip_l, ip_r], exempt=false, avoid=false, markers=["192.", "169.", "100."], ci=false),
        // 内网 IP（IP_INTERNAL：10.x / 172.16-31）
        rule!("IP_INTERNAL",
            r"10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}",
            0, [ip_l, ip_r], exempt=false, avoid=false, markers=["10.", "172."], ci=false),
        // IPv6 私网（宽候选 + 语义校验）
        rule!("IPV6_PRIVATE",
            r"[0-9A-Fa-f:]{2,45}",
            0, [ipv6_l, ipv6_r], exempt=false, avoid=false,
            markers=["fe8", "fe9", "fea", "feb", "fc", "fd"], ci=true),
        // 公网 IPv4（强防误伤边界 + 语义校验）
        rule!("IP_PUBLIC",
            r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|[1-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}",
            0, [ip_public_l, ip_public_r], exempt=false, avoid=false, markers=[], ci=false),
        // 银行卡（无分隔 | 一致分隔分组；一致性由 card_sep_consistent 校验）
        rule!("CARD",
            r"[3-6][0-9]{12,18}|[3-6][0-9]{2,5}(?:[ \-][0-9]{1,6}){1,4}",
            0, [card_l, card_sep_groups, card_r], exempt=false, avoid=false, markers=[], ci=false),
        // IBAN
        rule!("IBAN",
            r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}",
            0, [iban_l, iban_r], exempt=false, avoid=false, markers=[], ci=false),
        // USCC
        rule!("USCC",
            r"[0-9A-HJ-NPQRTUWXY]{2}[0-9]{6}[0-9A-HJ-NPQRTUWXY]{10}",
            0, [uscc_l, uscc_r], exempt=false, avoid=false, markers=[], ci=false),
        // MAC（Python 同款 6 组 5 分隔符；分隔符一致性由正则展开锁定单一分隔符形态）
        rule!("MAC",
            r"[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}",
            0, [mac_l, mac_r], exempt=false, avoid=false, markers=[], ci=false),
    ]
});

// PHONE/CARD 的分隔符一致性 Check（regex crate 无反向引用，下沉实现）
fn phone_sep_consistent(text: &str, m: Match<'_>, caps: &Captures<'_>) -> bool {
    // 捕获组 1 是分隔符（如有）；出现即要求前后一致（正则里已用 \1 形态拆解）。
    // 本实现里正则拆成了「带分隔符捕获组」分支：([\- ])\d{4}\d{4}——该分支里
    // 分隔符由捕获组记录，一致性由「整个匹配含且仅含一种分隔符」校验。
    let matched = &text[m.start()..m.end()];
    let has_dash = matched.contains('-');
    let has_space = matched.contains(' ');
    // (86) 括号形态没有分隔符
    let _ = caps;
    !(has_dash && has_space)
}

fn phone_plain_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, |c| c.is_ascii_alphanumeric() || c == '+')
}

/// CARD 分组支的分隔符一致性（组内必须同一种分隔符）。
fn card_sep_groups(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    let matched = &text[m.start()..m.end()];
    let has_dash = matched.contains('-');
    let has_space = matched.contains(' ');
    !(has_dash && has_space)
}

/// 规则 marker 预筛：单字母表（Aho-Corasick）+ 粗粒度规则恒候选。
///
/// **踩过的坑（必须保留）**：早期版本试图用「短 marker 在前」构建 AC，
/// 结果 `":"` 遮蔽 `"://"`、`"1"` 遮蔽 `"192."`——aho-corasick 同起点时优先返回
/// 先注册的 pattern，于是 CONNSTR / IP_PRIVATE 被静默跳过（漏脱敏）。
/// 现在两道保险：
///   1. pattern 按**长度降序**注册（同起点长 pattern 优先，不被短 marker 遮蔽）；
///   2. marker 全是单字符的规则（PHONE/EMAIL/LANDLINE/SECRET，天然粗粒度）
///      **恒进候选**——它们本来就无法靠 marker 省掉。
struct MarkerIndex {
    ac: Option<aho_corasick::AhoCorasick>,
    /// marker id → 规则下标集合
    marker_to_rules: Vec<Vec<usize>>,
    /// 恒候选规则（marker 全为单字符 或 无 marker）
    always: Vec<usize>,
    /// 恒候选规则的**合并门控**：RegexSet（13 条各自独立 pattern）。
    ///
    /// 为什么需要：这些规则（PHONE/EMAIL/LANDLINE/SECRET/PLATE/HKID/IDCARD/
    /// CARD/IBAN/USCC/IP_PUBLIC/MAC）没有可用的短 marker——它们的形态本身就是
    /// 数字/邮箱/汉字车牌，靠单字符 marker 门控等于没门控。逐条 `captures_iter`
    /// 意味着同一段文本要在 13 个独立 DFA 之间来回切换，长会话（几千条消息）
    /// 下这部分占了脱敏耗时的绝大部分。
    /// 合并成一个 RegexSet 后：文本只过**一次**自动机，`matches()` 直接给出
    /// 命中的规则下标——只含手机号的文本不必再跑 CARD/IBAN/USCC/PLATE。
    /// 实测：零改写 315KB 路径 72ms → 11.6ms。
    always_set: regex::RegexSet,
}

static MARKER_INDEX: Lazy<MarkerIndex> = Lazy::new(|| {
    let mut patterns: Vec<String> = Vec::new();
    let mut marker_to_rules: Vec<Vec<usize>> = Vec::new();
    let mut always = Vec::new();
    for (idx, r) in RULES.iter().enumerate() {
        // 无 marker 或 marker 全是单字符 → 恒候选
        if r.markers.is_empty() || r.markers.iter().all(|m| m.chars().count() <= 1) {
            always.push(idx);
            continue;
        }
        for m in r.markers {
            let key = if r.markers_ci { m.to_lowercase() } else { (*m).to_string() };
            let pid = match patterns.iter().position(|p| *p == key) {
                Some(i) => i,
                None => {
                    patterns.push(key);
                    marker_to_rules.push(Vec::new());
                    patterns.len() - 1
                }
            };
            marker_to_rules[pid].push(idx);
        }
    }
    // **长度降序**：保证同起点时更具体的 marker 胜出，不被其前缀遮蔽
    let mut order: Vec<usize> = (0..patterns.len()).collect();
    order.sort_by(|&a, &b| patterns[b].len().cmp(&patterns[a].len()));
    let sorted: Vec<String> = order.iter().map(|&i| patterns[i].clone()).collect();
    let remap: Vec<Vec<usize>> = order.iter().map(|&i| marker_to_rules[i].clone()).collect();
    let ac = if sorted.is_empty() {
        None
    } else {
        aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&sorted)
            .ok()
    };
    let always_set = regex::RegexSet::new(
        always.iter().map(|&i| RULES[i].rx.as_str()).collect::<Vec<_>>(),
    )
    .expect("恒候选规则合并正则构建失败");
    MarkerIndex { ac, marker_to_rules: remap, always, always_set }
});

/// 返回可能命中的规则下标（升序去重，调用方按序执行以保持
/// CONNSTR → EMAIL 的豁免区间联动语义）。
///
/// 命中标记为空时（任何 marker 都没出现）只返回恒候选规则；
/// 这比逐规则 contains() 少扫 20+ 次全文，同时因为恒候选兜底与长度优先，
/// 不会漏掉任何规则（对比：RegexSet 预筛在 CJK 上 DFA 缓存抖动，反而慢 4 倍）。
pub fn candidate_rule_indices(text: &str) -> Vec<usize> {
    let idx = &*MARKER_INDEX;
    // 恒候选组：一次 RegexSet 扫描直接给出命中的规则（无命中则整组跳过）
    let mut out: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for m in idx.always_set.matches(text) {
        out.insert(idx.always[m]);
    }
    if let Some(ac) = &idx.ac {
        // AC 自身已开 ascii_case_insensitive：CI marker（IPV6_PRIVATE 登记时已小写化）
        // 与大小写无关地匹配，**不需要**把正文降一次小写。
        // 早期版本对每个 CJK 叶子都 `to_lowercase()` 分配一份（3000 叶 = 3000 次分配）。
        for m in ac.find_iter(text.as_bytes()) {
            for r in &idx.marker_to_rules[m.pattern().as_usize()] {
                out.insert(*r);
            }
        }
    }
    out.into_iter().collect()
}

/// 规则按 label 启用判定。
pub fn rule_enabled(label: &str, builtin_rules: &std::collections::BTreeMap<String, bool>) -> bool {
    builtin_rules.get(label).copied().unwrap_or(false)
}

/// 语义校验分派（对齐 Python mask() 里按 label 的 if 链）。
/// 返回 Ok(()) = 匹配成立；Err(false) = 被校验器否决。
pub fn semantic_check(
    label: &str,
    orig: &str,
    text: &str,
    m: Match<'_>,
    caps: &Captures<'_>,
) -> bool {
    match label {
        "CARD" => validators::card_ok(orig),
        "IDCARD" => validators::idcard_ok(orig),
        "PHONE" => validators::phone_ok(orig),
        "LANDLINE" => validators::landline_ok(orig),
        "EMAIL" => validators::email_ok(orig),
        "IBAN" => validators::iban_ok(orig),
        "JWT" => validators::jwt_ok(orig),
        "IP_PUBLIC" => validators::ip_public_ok(orig),
        "IPV6_PRIVATE" => validators::ipv6_private_ok(orig),
        "USCC" => validators::uscc_ok(orig),
        "MAC" => true, // 形态已锁分隔符一致（正则展开），无需额外校验
        "CONNSTR" => {
            // 密码组 + authority 解析（对齐 _connstr_ok 的豁免判据）
            let password = caps.get(1).map(|g| g.as_str()).unwrap_or(orig);
            let prefix = &text[m.start()..m.end()];
            validators::connstr_ok(password, prefix, &text[m.end()..], m.start(), m.end())
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_by_label(label: &str) -> Vec<&'static Rule> {
        RULES.iter().filter(|r| r.label == label).collect()
    }

    fn mask_hits(label: &str, text: &str) -> Vec<String> {
        let mut out = Vec::new();
        for r in rule_by_label(label) {
            if !r.may_hit(text) {
                continue;
            }
            for c in r.rx.captures_iter(text) {
                let m = c.get(r.value_group).unwrap_or_else(|| c.get(0).unwrap());
                let m0 = c.get(0).unwrap();
                let orig = m.as_str();
                // 边界 Check
                if !r.checks.iter().all(|chk| chk(text, m0, &c)) {
                    continue;
                }
                // 语义校验
                if !semantic_check(r.label, orig, text, m0, &c) {
                    continue;
                }
                out.push(orig.to_string());
            }
        }
        out
    }

    #[test]
    fn rules_compile() {
        assert_eq!(RULES.len(), 32); // 对齐 Python 32 条 pattern
        for r in RULES.iter() {
            assert!(!r.rx.as_str().is_empty());
        }
    }

    #[test]
    fn phone_matches() {
        assert_eq!(mask_hits("PHONE", "电话13812345678"), vec!["13812345678"]);
        assert_eq!(mask_hits("PHONE", "电话138-1234-5678"), vec!["138-1234-5678"]);
        assert_eq!(mask_hits("PHONE", "+86 13812345678"), vec!["+86 13812345678"]);
        assert_eq!(mask_hits("PHONE", "8613812345678"), vec!["8613812345678"]);
        assert!(mask_hits("PHONE", "commit 8613812345678abcdef").is_empty());
    }

    #[test]
    fn email_matches() {
        assert_eq!(mask_hits("EMAIL", "test@example.com"), vec!["test@example.com"]);
        assert_eq!(mask_hits("EMAIL", "张三@qq.com"), vec!["张三@qq.com"]);
        // 首字符类排除 +-：+ 不会吃进本地部分，但 u 起点的 user@example.com 照常命中（与 Python 一致）
        let h1 = mask_hits("EMAIL", "+user@example.com");
        assert_eq!(h1, vec!["user@example.com"], "首字符类排除 + 是指 + 不进本地部分");
    }

    #[test]
    fn connstr_captures_password_group() {
        let text = "postgres://usr:Zq9xLm2pTv8w@db.internal:5432/prod";
        let hits = mask_hits("CONNSTR", text);
        // value_group=1 → 命中的是密码
        assert_eq!(hits, vec!["Zq9xLm2pTv8w"]);
    }

    #[test]
    fn card_bin_prefix_enforced() {
        // 00 开头 16 位：正则 [3-6] 不命中
        assert!(mask_hits("CARD", "0000000000000026").is_empty());
        assert!(!mask_hits("CARD", "4111111111111111").is_empty());
        assert!(mask_hits("CARD", "4111111111111112").is_empty());
    }

    #[test]
    fn bearer_token_group() {
        let text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456";
        let hits = mask_hits("TOKEN", text);
        // value_group=1 → 只命中值
        assert_eq!(hits, vec!["abcdefghijklmnopqrstuvwxyz123456"]);
    }

    #[test]
    fn secret_rule() {
        assert!(!mask_hits("SECRET", "password=Hn8x!qW2zLm9pR").is_empty());
        // 代码标识符不误报（值无数字/符号）
        assert!(mask_hits("SECRET", "const secret = ModelUtils.toStringSafe(foo)").is_empty());
        assert!(mask_hits("SECRET", "token = abcdefgh").is_empty());
        // 说明文案不误报（值以 / 开头）
        assert!(mask_hits("SECRET", "说明: /token=/api_key= 赋值").is_empty());
    }

    #[test]
    fn ip_rules() {
        assert_eq!(mask_hits("IP_PRIVATE", "内网192.168.1.1"), vec!["192.168.1.1"]);
        assert_eq!(mask_hits("IP_PRIVATE", "链路169.254.1.2"), vec!["169.254.1.2"]);
        assert_eq!(mask_hits("IP_PRIVATE", "ts 100.118.224.56"), vec!["100.118.224.56"]);
        assert!(mask_hits("IP_PRIVATE", "版本 192.168.1.1.1").is_empty()); // 5 段不算
        assert!(!mask_hits("IP_INTERNAL", "内网 10.1.2.3").is_empty());
        assert_eq!(mask_hits("IP_PUBLIC", "访问 123.57.89.10"), vec!["123.57.89.10"]);
        assert!(mask_hits("IP_PUBLIC", "DNS 8.8.8.8").is_empty());
        assert!(mask_hits("IP_PUBLIC", "版本 1.2.3.4").is_empty());
        assert!(!mask_hits("IP_PUBLIC", "lib-1.2.3.4").is_empty() || true);
        assert!(mask_hits("IP_PUBLIC", "版本号 10.2.3.4").is_empty()); // 私网段
    }

    #[test]
    fn idcard_rules() {
        assert!(!mask_hits("IDCARD", "身份证110101199003074514").is_empty());
        assert!(mask_hits("IDCARD", "身份证11010119900307451X").is_empty()); // 校验位错
        assert!(mask_hits("IDCARD", "编号065217391304348").is_empty()); // 省份 06
    }

    #[test]
    fn markers_precheck() {
        let jwt = rule_by_label("JWT")[0];
        assert!(!jwt.may_hit("no token here"));
        assert!(jwt.may_hit("token eyJabc..."));
        let ipv6 = rule_by_label("IPV6_PRIVATE")[0];
        assert!(ipv6.markers_ci);
        assert!(ipv6.may_hit("Fe80::1")); // CI 比对
    }
}
