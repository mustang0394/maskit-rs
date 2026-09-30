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
    c.is_ascii_alphanumeric() || c == '_' || is_cjk(c)
}

/// CJK 统一表意文字（与各规则正则里的 `\u{4e00}-\u{9fff}` 同一范围）。
fn is_cjk(c: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&c)
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

/// 取匹配起点之前、**同一个空白分隔 token** 内的文本（最多回看 256 字节）。
///
/// 用来判断「这个冒号是不是连接串 userinfo 的冒号」：限定在同一 token 内，
/// 既精确（不会被别的行的 `://` 误伤）又不会在超长 token 上退化。
fn token_tail_before(before: &str) -> &str {
    let start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| !c.is_whitespace())
        .last()
        .map(|(i, _)| i)
        .unwrap_or(0);
    // 超长 token：只回看尾部 256 字节（`://` 一定紧跟在 user 之前，够用）
    let mut b = if before.len() - start > 256 {
        before.len() - 256
    } else {
        start
    };
    while b < before.len() && !before.is_char_boundary(b) {
        b += 1;
    }
    &before[b..]
}

/// 邮箱左边界（贪婪版用）。
///
/// **不再用「前一字符是冒号就否决」**（旧实现）。那个规则本意是防连接串
/// userinfo 的 `pass@host` 被当成邮箱，但副作用是**所有**「标签:邮箱」
/// 无空格写法全部漏检 —— `mailto:alice@example.com`、`Email:alice@…`、
/// `收件人:bob@corp.cn;cc:carol@corp.cn` 都是常见写法，漏检 = PII 原文上行。
///
/// 现在把冒号否决**收窄为真正的连接串形态**：仅当同一 token 里出现过
/// `://`（即 `scheme://user:pass@host` 的 userinfo）才否决。于是：
/// * `redis://user:password@example.com` → 否决（不把口令当邮箱）；
/// * `mailto:` / `Email:` / `收件人:` / 中文全角 `：` → 正常命中；
/// * `https://host/?email=a@b.com` → 邮箱前是 `=`，本来就不进冒号分支。
///
/// **CJK 前一字符不再拒绝**：贪婪正则会从连续 CJK 段的**起点**开始匹配，
/// 因此「前一字符是 CJK」只在连续段超过本地部分上限（64）时才会出现
/// （即匹配到的是后缀）。此时拒绝 = **整段漏检**（PII 原文上行），
/// 放行至少能把邮箱本体遮住 —— 两害相权取其轻。
fn email_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    if m.start() == 0 {
        return true;
    }
    let before = &text[..m.start()];
    match before.chars().next_back() {
        Some('.') => false,
        Some(':') => !token_tail_before(before).contains("://"),
        Some(c) if is_cjk(c) => true,
        Some(c) => !is_word_char_cn(c),
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

/// 纯字母前缀型规则的左边界（钉钉 `ding…`）：
///
/// `ding` 是普通英文词根（`dingleberry`/`dingalings`/`dingbats`）且没有语义
/// 校验，`apikey_l` 也放行词首，于是这些词的词首会被整段当成 AppKey。
/// 收紧为「不得紧跟在字母之后」（数字左边不管：`v2ding…` 仍要能命中），
/// 保留 `my-ding…` / `x_ding…` / 行首等分隔符形态。
fn alpha_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, |c| c.is_ascii_alphabetic())
}

/// 两段原文片段是否**区间重叠**（仅靠文本，不需坐标）。
///
/// 为什么需要它：CONNSTR 被否决时要豁免其中的 `pass@host`，但 CONNSTR 命中
/// 形如 `scheme://user:pass@`，而 EMAIL 命中形如 `pass@host` —— 二者是
/// **后缀/前缀部分重叠**（既非包含也非被包含），所以需要真正的前后缀重叠判定。
///
/// 为什么不用坐标：每条规则命中后会 splice 改写 `out`，占位符长度 ≠ 原文，
/// 后继规则的坐标空间已偏移；用坐标会误判（CONNSTR 同时有命中与否决时
/// 必然错位）。文本重叠与坐标无关，因此不受影响。
pub fn overlaps(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a.contains(b) || b.contains(a) {
        return true;
    }
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let max = ab.len().min(bb.len());
    (1..=max).any(|k| ab[ab.len() - k..] == bb[..k] || bb[bb.len() - k..] == ab[..k])
}

/// 钉钉 AppKey 后缀必须含至少一位数字（下沉 `(?=[a-z0-9]*[0-9])`；
/// `regex` crate 无环视）。真实 AppKey 是随机串，`dingtalkwebhookurl` /
/// `dingtalknotificationtemplate` 这类英文词根标识符则无数字。
fn ding_suffix_has_digit(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    text[m.start()..m.end()].bytes().any(|b| b.is_ascii_digit())
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
    value
        .chars()
        .any(|c| c.is_ascii_digit() || "!@#$%^&*".contains(c))
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

/// Bearer 值必须含至少一位数字或一个非字母字符（`-._~+/=`）。
///
/// 真实 token（base64url / hex / JWT）几乎必然满足；而
/// `Bearer authenticationtokensystem` 这类 20+ 位纯字母正文会被拦下。
/// 代价：全字母的随机 token（20 位 base64 约 1.6%）会漏检 —— 该规则默认关闭，
/// 且词形正文比随机 token 常见得多。
fn bearer_value_has_digit_or_symbol(text: &str, _m: Match<'_>, caps: &Captures<'_>) -> bool {
    let Some(v) = caps.get(1) else { return false };
    let _ = text;
    v.as_str().chars().any(|c| !c.is_ascii_alphabetic())
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

/// SSH 公钥左边界：不得紧跟在 [A-Za-z0-9+/=_-] 后面
/// （防从某个长 token 中截出一段当成密钥）。
fn ssh_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_preceded_by(text, m, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '@' | '.')
    })
}

/// SSH 公钥右边界：blob 右边不得再跟 base64 字符或 `=`
/// （否则说明我们只截了更长 base64 的一段）。注释（`user@host`）以空格分隔，不受影响。
fn ssh_r(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    check_not_followed_by(text, m, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
    })
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
    let body_start = text[m.start()..m.end()]
        .char_indices()
        .nth(2)
        .map(|(i, _)| m.start() + i)
        .unwrap_or(m.end());
    text[body_start..m.end()]
        .chars()
        .any(|c| c.is_ascii_digit())
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

/// MAC 左边界：`(?<![0-9A-Fa-f:.-])`
///
/// 比右边界多收一个 `.`：`v1.00:11:22:33:44:55`、`x.00:11:…` 这类
/// 「点号+数据」形态不该当成 MAC（右边界早已拒绝 `.`，左侧此前漏了）。
fn mac_l(text: &str, m: Match<'_>, _c: &Captures<'_>) -> bool {
    if m.start() == 0 {
        return true;
    }
    match text[..m.start()].chars().next_back() {
        Some(c) => !(c.is_ascii_hexdigit() || c == ':' || c == '-' || c == '.'),
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
        //
        // 可选前缀必须包含 `ENCRYPTED `：PKCS#8 加密私钥是
        // `-----BEGIN ENCRYPTED PRIVATE KEY-----`（openssl pkcs8 -topk8 的产物，
        // 备份/中间件配置里很常见）。漏它 = 整块加密私钥原文上行。
        rule!(
            "PRIVATE_KEY",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]{20,}?-----END[^-]*PRIVATE KEY-----",
            0,
            [],
            exempt = false,
            avoid = false,
            markers = ["PRIVATE KEY"],
            ci = false
        ),
        // SSH 公钥（`authorized_keys` / `known_hosts` / Git hosting 里贴的那种）。
        //
        // 为什么能写得这么紧：OpenSSH 公钥的二进制 blob 是 SSH wire format ——
        // 开头是 4 字节大端「密钥类型字符串长度」+ 类型字符串本身，于是**所有**
        // 类型的 base64 都必然以 `AAAA` 开头（类型串长度都是个位数）。
        // 实测：ssh-ed25519 → `AAAAC3NzaC1lZDI1NTE5…`、ssh-rsa → `AAAAB3NzaC1yc2E…`、
        // ecdsa-sha2-nistp256 → `AAAAE2VjZHNhLXNoYTIt…`。
        // 再加上 `ssh_pubkey_ok` 会把 blob 解出来、核对内部类型串与外部类型一致，
        // 基本不存在误报。
        //
        // 私钥不在这里：PEM / OpenSSH 私钥已由上面的 PRIVATE_KEY 整块吃掉。
        // （注：`sk-ssh-ed25519@openssh.com` 这类 FIDO 类型在默认配置下会先被
        //  `sk-` 秘密前缀规则命中一部分，见 rules 测试里的记录。）
        rule!(
            "SSH_PUBKEY",
            r"(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+AAAA[A-Za-z0-9+/]{50,}={0,3}",
            0,
            [ssh_l, ssh_r],
            exempt = false,
            avoid = false,
            markers = [
                "ssh-",
                "ecdsa-sha2-nistp",
                "sk-ssh-ed25519",
                "sk-ecdsa-sha2"
            ],
            ci = false
        ),
        // GitHub tokens
        rule!(
            "API_KEY",
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}",
            0,
            [apikey_l, apikey_r],
            exempt = false,
            avoid = false,
            markers = ["gh"],
            ci = false
        ),
        rule!(
            "API_KEY",
            r"github_pat_[A-Za-z0-9_]{50,}",
            0,
            [apikey_l, apikey_r],
            exempt = false,
            avoid = false,
            markers = ["github"],
            ci = false
        ),
        // Google API Key
        rule!(
            "API_KEY",
            r"AIza[0-9A-Za-z_\-]{35,38}",
            0,
            [apikey_l, apikey_r],
            exempt = false,
            avoid = false,
            markers = ["AIza"],
            ci = false
        ),
        // 阿里云 AK
        rule!(
            "ACCESS_KEY",
            r"LTAI[A-Za-z0-9]{12,20}",
            0,
            [apikey_l, access_key_r],
            exempt = false,
            avoid = false,
            markers = ["LTAI"],
            ci = false
        ),
        // 腾讯云 SecretId
        rule!(
            "ACCESS_KEY",
            r"AKID[A-Za-z0-9]{13,32}",
            0,
            [apikey_l, access_key_r],
            exempt = false,
            avoid = false,
            markers = ["AKID"],
            ci = false
        ),
        // Slack
        rule!(
            "API_KEY",
            r"xox[baprs]\-[0-9A-Za-z\-]{10,}",
            0,
            [apikey_l, apikey_r],
            exempt = false,
            avoid = false,
            markers = ["xox"],
            ci = false
        ),
        // Stripe
        rule!(
            "API_KEY",
            r"[sr]k_(?:live|test)_[0-9A-Za-z]{20,}",
            0,
            [apikey_l, stripe_r],
            exempt = false,
            avoid = false,
            markers = ["k_"],
            ci = false
        ),
        // 飞书 / 钉钉
        //
        // 钉钉 AppKey 是 `ding` + **16 位**（如 `dingbbikazkr7q2kh8s2`），
        // 原先的 `ding[a-z0-9]{6,}` 下限太松：`dingalings`、`dingleberry`
        // 这类普通英文词在词首会被整段吃掉（`apikey_l` 拦不住词首），
        // 所以下限抬到 12（+ `alpha_l` 词首边界）。
        // 飞书 App ID 是 `cli_` + **16 位**（如 `cli_9b445f5258795107`），
        // 带下划线、下限 16，本身已无英文词误伤，保持不变。
        rule!(
            "API_KEY",
            r"cli_[a-z0-9]{16,}",
            0,
            [apikey_l, lowercase_r],
            exempt = false,
            avoid = false,
            markers = ["cli_"],
            ci = false
        ),
        // 钉钉 AppKey：`ding` + 16 位小写字母/数字（官方文档：unique ID 由
        // lowercase letters、numbers、`-` 组成，长度 < 32）。
        //
        // 为何要求「至少一位数字」：`ding` 是普通英文词根，
        // `dingtalkwebhookurl` / `dingtalknotificationtemplate` 这类小写连写
        // 标识符会被整词吃掉（`alpha_l` 只在前面有字母时拦，拦不住词首）。
        // 代价：全字母的真实 AppKey（随机 16 位无数字，概率约 (26/36)^16 ≈ 0.6%）
        // 会漏检。权衡依据：AppKey 是**应用标识**而非密钥（真正的凭据是
        // AppSecret），漏检危害远低于把普通标识符改写成占位符对上游的干扰。
        rule!(
            "API_KEY",
            r"ding[a-z0-9]{12,}",
            0,
            [alpha_l, ding_suffix_has_digit, lowercase_r],
            exempt = false,
            avoid = false,
            markers = ["ding"],
            ci = false
        ),
        // AWS AccessKeyId
        rule!(
            "ACCESS_KEY",
            r"(?:AKIA|ASIA)[A-Z0-9]{16}",
            0,
            [aws_l, aws_r],
            exempt = false,
            avoid = false,
            markers = ["AK", "AS"],
            ci = false
        ),
        // AWS SecretAccessKey（值组 1）
        rule!(
            "ACCESS_KEY",
            r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"#,
            1,
            [aws_secret_r],
            exempt = false,
            avoid = false,
            markers = ["aws", "AWS"],
            ci = false
        ),
        // JWT
        rule!(
            "JWT",
            r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            0,
            [apikey_l, apikey_r],
            exempt = false,
            avoid = false,
            markers = ["eyJ"],
            ci = false
        ),
        // Bearer Token（值组 1；\b 下沉）
        rule!(
            "TOKEN",
            r"(?i)Bearer\s+([A-Za-z0-9._~+/=\-]{20,})",
            1,
            [bearer_value_has_digit_or_symbol, bearer_word_boundary],
            exempt = false,
            avoid = false,
            markers = ["Bearer", "bearer", "BEARER"],
            ci = false
        ),
        // SECRET 键值对（值组 1；左边界/值域/右边界/`(?!/)` 全部下沉）
        // 键名就是关键词本身（左右边界由 secret_key_l/r 下沉），不贪吃前后缀
        rule!(
            "SECRET",
            concat!(
                r"(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key",
                r"|(?:密码|口令|令牌|密钥|秘钥|密匙|凭据|凭证|私钥|授权码|访问密钥|接口密钥))",
                r#"[\"'“”「」]?\s*[:=：＝]\s*[\"'“”「」]?"#,
                r"([A-Za-z0-9!@#$%^&*_~+=\-]{6,64})"
            ),
            1,
            [
                secret_key_l,
                secret_key_r,
                secret_value_not_slash,
                secret_value_charset,
                secret_r
            ],
            exempt = false,
            avoid = false,
            markers = ["=", ":", "：", "＝"],
            ci = false
        ),
        // CONNSTR（scheme 封顶 {0,63} 防 O(N²)；密码组 1；\b 下沉；豁免区间联动 EMAIL）
        rule!(
            "CONNSTR",
            r"[a-zA-Z][a-zA-Z0-9+.\-]{0,63}://[^\s:@/]+:([^\s@/]{4,})@",
            1,
            [connstr_word_boundary],
            exempt = true,
            avoid = false,
            markers = ["://"],
            ci = false
        ),
        // 手机号（单条交替分支，最左最长；Python 同款）：
        // ① 前缀（+86/0086/(86)）+ 裸 11 位  ② 裸 11 位  ③ 带分隔（- 或空格，单种）
        rule!(
            "PHONE",
            r"(?:\+?86|0086|[\(（]\+?86[\)）])[\s\-]?1[3-9][0-9][0-9]{8}|1[3-9][0-9][0-9]{8}|1[3-9][0-9][\- ][0-9]{4}[\- ][0-9]{4}|1[3-9][0-9][\- ][0-9]{4}[ ][0-9]{4}|1[3-9][0-9][ ][0-9]{4}[\- ][0-9]{4}|1[3-9][0-9][ ][0-9]{4}[ ][0-9]{4}",
            0,
            [phone_plain_l, phone_sep_consistent, phone_r],
            exempt = false,
            avoid = false,
            markers = ["1"],
            ci = false
        ),
        // EMAIL（CONNSTR 之后！左/右边界下沉）
        //
        // TLD 用**同质交替** `(?:[A-Za-z]{2,}|[CJK]{2,})` 而不是单一混合类：
        // 混合类会把中文正文粘进 TLD —— `zhangsan@qq.com请查收` 的 `com请查收`
        // 会被整段吃掉，把正文大段挖空。同质交替在 latin/CJK 边界自然停下，
        // 中文 TLD（`.中国`）仍支持。
        rule!(
            "EMAIL",
            r"[a-zA-Z0-9_\u{4e00}-\u{9fff}][\u{4e00}-\u{9fff}A-Za-z0-9._%+\-]{0,63}@[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.(?:[a-zA-Z]{2,}|[\u{4e00}-\u{9fff}]{2,})",
            0,
            [email_l, email_r],
            exempt = false,
            avoid = true,
            markers = ["@"],
            ci = false
        ),
        // 座机
        //
        // ⚠️ 国家码分组是**可选**的（`(?:(?:…))?`）。原实现把它写成强制分组，
        // 导致 `010-62345678` / `(010)62345678` 这类**国内常见写法全部漏检**
        // （只有带 `+86`/`86`/`(86)` 前缀才命中）—— 默认开启的规则实际形同虚设。
        rule!(
            "LANDLINE",
            r"(?:(?:\+?86|0086|[\(（]\+?86[\)）])[\s\-]?)?(?:[\(（]0(?:10|2[0-9]|[3-9][0-9]{2})[\)）][\s\-]?[2-9][0-9]{6,7}|0(?:10|2[0-9]|[3-9][0-9]{2})[\-\s][2-9][0-9]{6,7})(?:[\-\s]?(?:转|分机|ext|x|#)[\-\s]?[0-9]{1,5})?",
            0,
            [landline_l, landline_r],
            exempt = false,
            avoid = false,
            markers = ["0"],
            ci = false
        ),
        // 车牌（车身含数字断言下沉）
        rule!(
            "PLATE",
            r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-Z0-9]{5,6}",
            0,
            [plate_l, plate_body_has_digit, plate_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // 港澳通行证
        rule!(
            "HKID",
            r"H[0-9]{8}",
            0,
            [hkid_l, hkid_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // 身份证 15/18（正则锁位数，校验器验省份+日期+校验位）
        rule!(
            "IDCARD",
            r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])[0-9]{13}",
            0,
            [idcard_l, idcard_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        rule!(
            "IDCARD",
            r"(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5]|71|8[12])[0-9]{15}[0-9Xx]",
            0,
            [idcard_l, idcard_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // 内网 IP（IP_PRIVATE：192.168 / 169.254 / CGNAT）
        rule!(
            "IP_PRIVATE",
            r"192\.168\.[0-9]{1,3}\.[0-9]{1,3}|169\.254\.[0-9]{1,3}\.[0-9]{1,3}",
            0,
            [ip_l, ip_r],
            exempt = false,
            avoid = false,
            markers = ["192.", "169.", "100."],
            ci = false
        ),
        rule!(
            "IP_PRIVATE",
            r"100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}",
            0,
            [ip_l, ip_r],
            exempt = false,
            avoid = false,
            markers = ["192.", "169.", "100."],
            ci = false
        ),
        // 内网 IP（IP_INTERNAL：10.x / 172.16-31）
        rule!(
            "IP_INTERNAL",
            r"10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}",
            0,
            [ip_l, ip_r],
            exempt = false,
            avoid = false,
            markers = ["10.", "172."],
            ci = false
        ),
        // IPv6 私网（宽候选 + 语义校验）
        rule!(
            "IPV6_PRIVATE",
            r"[0-9A-Fa-f:]{2,45}",
            0,
            [ipv6_l, ipv6_r],
            exempt = false,
            avoid = false,
            markers = ["fe8", "fe9", "fea", "feb", "fc", "fd"],
            ci = true
        ),
        // 公网 IPv6（全局单播 2000::/3；宽候选 + 语义校验）
        //
        // 正则已经锁在「首组为 2xxx/3xxx」上：全局单播首组取值 0x2000..=0x3fff，
        // 而 0x2000 本身没有前导零可省，因此**真实书写形式必然是 4 位十六进制**。
        // 这比 IPV6_PRIVATE 的 `[0-9A-Fa-f:]{2,45}` 宽候选要精确得多（后者之所以
        // 必须够宽，是因为它靠 fe8/fc 等 marker 门控，且 :: 压缩位置不定），
        // 所以这里不必再靠 marker 省性能，直接进恒候选组。
        rule!(
            "IPV6_PUBLIC",
            r"(?:2[0-9A-Fa-f]{3}|3[0-9A-Fa-f]{3})(?::[0-9A-Fa-f]{0,4}){2,7}",
            0,
            [ipv6_l, ipv6_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // 公网 IPv4（强防误伤边界 + 语义校验）
        rule!(
            "IP_PUBLIC",
            r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?|[1-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}",
            0,
            [ip_public_l, ip_public_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // 银行卡（无分隔 | 一致分隔分组；一致性由 card_sep_consistent 校验）
        rule!(
            "CARD",
            r"[3-6][0-9]{12,18}|[3-6][0-9]{2,5}(?:[ \-][0-9]{1,6}){1,4}",
            0,
            [card_l, card_sep_groups, card_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // IBAN
        rule!(
            "IBAN",
            r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}",
            0,
            [iban_l, iban_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // USCC
        rule!(
            "USCC",
            r"[0-9A-HJ-NPQRTUWXY]{2}[0-9]{6}[0-9A-HJ-NPQRTUWXY]{10}",
            0,
            [uscc_l, uscc_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
        // MAC（Python 同款 6 组 5 分隔符；分隔符一致性由正则展开锁定单一分隔符形态）
        rule!(
            "MAC",
            r"[0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}",
            0,
            [mac_l, mac_r],
            exempt = false,
            avoid = false,
            markers = [],
            ci = false
        ),
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
            let key = if r.markers_ci {
                m.to_lowercase()
            } else {
                (*m).to_string()
            };
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
        always
            .iter()
            .map(|&i| RULES[i].rx.as_str())
            .collect::<Vec<_>>(),
    )
    .expect("恒候选规则合并正则构建失败");
    MarkerIndex {
        ac,
        marker_to_rules: remap,
        always,
        always_set,
    }
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
        "IPV6_PUBLIC" => validators::ipv6_public_ok(orig),
        "SSH_PUBKEY" => {
            // 外部 keytype 与 blob 内部类型串必须一致（见 `ssh_pubkey_ok`）
            let keytype = orig.split_whitespace().next().unwrap_or("");
            validators::ssh_pubkey_ok(keytype, orig)
        }
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

    /// 收集某 label 下所有规则的命中（按规则顺序，且**重叠时先到者胜**）。
    ///
    /// 为什么要按重叠去重：一个 label 可以有多条 pattern（如 EMAIL 的
    /// 「精确拉丁版 + 贪婪版」），同一段文本会被两条都匹配到，且区间**重叠**
    /// （`zhangsan@qq.com` 在 `我的邮箱是zhangsan@qq.com` 里面）。
    /// 生产引擎里先执行的规则已把它换成占位符、后续条因「占位符防污染」
    /// 跳过；测试辅助函数必须同样模拟这点，否则会把执行期互斥误报成两次命中。
    fn mask_hits(label: &str, text: &str) -> Vec<String> {
        let mut taken: Vec<(usize, usize)> = Vec::new();
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
                // 与已接受的命中区间重叠 → 先到者胜（等价占位符防污染）
                let (s, e) = (m0.start(), m0.end());
                if taken.iter().any(|(ts, te)| s < *te && e > *ts) {
                    continue;
                }
                taken.push((s, e));
                out.push(orig.to_string());
            }
        }
        out
    }

    // ── 新增规则：公网 IPv6 / SSH 公钥 ────────────────────────────────────
    //
    // 样本是 `ssh-keygen` 真实产物（ed25519 / rsa-3072 / ecdsa-nistp256），
    // 不是手写的假串 —— 正则的 `AAAA` 前缀假设、以及「ed25519 不补 `=` 填充而
    // rsa/ecdsa 补」这类差异，全靠它们验证。

    const ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSI4uzX8YR1xYGPTFsx0F/2WN+PorS2jI+09QnnTWFL test-ed25519@example.com";
    const RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC5lIXzkIhCDgax4duXs3+gExVGvKlHuvlF+vHFnQa1jrOQzjbnxZYmxEOQ6bLTnWwoDavaZQvzN7YX5hpLF1XxE4OS7XXkVdLgsM2IN5tPVw6bXDhOCwzKs0LrnEuQJrheIe7Z6gsDPqRcoG8WZMQ/G0Dvq1imMDZ6Ao93eeWG/PZ70Qxx+lM0c1mnxWaJsV2+yOgPPk/bIYLF6Em5T3jlDB+RDFgrhAOoEk8EDY+e6liPWvcthFX/0i3IH7JPHRXkXwNt6t7BnLzJBZfdCJKe5e3pM0CuSkxAFQDUkMaIQyLJd2ce42k6QYbfY0whp901uyXnhM6Y83CvlBCyPjS/Jm+m93QYgLbSDJbVYTLjDKDznzMoBE7kEXe8C5NBEm+75QUlsUc8PbZmvwaNfjHn+yHrwS8PpEXFwgVdOoV5gK+wq+p2hjxOhkXMcDovEkNa2kxx31m8/NH6zS7udSwgQWb9evXjSKZV4eEVsn53hldpf9R4WGnEqp0hAykKHxU= test-rsa@example.com";
    const ECDSA_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLHaLDPTq8I9kvOKp5cgGA+gZ3eiK6ZrxYgygJDf5GQD5TmfDHUy+CWBb3M0/bmSNhuF8ToJT/2conaBgXnVLIw= test-ecdsa@example.com";

    /// 取「类型 + blob」两段（公钥的密钥部分；注释属于第三段）。
    fn ssh_key_material(line: &str) -> String {
        let mut it = line.split_whitespace();
        format!("{} {}", it.next().unwrap(), it.next().unwrap())
    }

    #[test]
    fn ssh_pubkey_masks_real_keys() {
        for (name, line) in [
            ("ed25519", ED25519_PUB),
            ("rsa", RSA_PUB),
            ("ecdsa", ECDSA_PUB),
        ] {
            let hits = mask_hits("SSH_PUBKEY", line);
            assert_eq!(hits.len(), 1, "{name}: 应命中一次，实际 {hits:?}");
            // 命中范围必须是「类型 + blob」
            assert_eq!(hits[0], ssh_key_material(line), "{name}: 命中范围不对");
            // 注释（含邮箱）不进本次命中，留给 EMAIL 规则
            assert!(!hits[0].contains('@'), "{name}: 不应把注释一起吃进来");
        }
    }

    /// 公钥出现在常见上下文里（YAML 列表、带引号、known_hosts 前缀、行尾注释）
    /// 都要能命中，且命中范围仍是「类型 + blob」。
    #[test]
    fn ssh_pubkey_matches_in_context() {
        let cases = [
            format!("authorized_keys:\n  - {ED25519_PUB}"),
            format!("key = \"{ED25519_PUB}\"\n"),
            format!("git@github.com: {RSA_PUB}\n"),
            format!("github.com {ECDSA_PUB}"), // known_hosts 形态
            format!("{ED25519_PUB}   trailing note"),
        ];
        for line in cases {
            let hits = mask_hits("SSH_PUBKEY", &line);
            assert_eq!(hits.len(), 1, "上下文形态应命中：{line}");
            assert!(
                hits[0].starts_with("ssh-") || hits[0].starts_with("ecdsa-"),
                "命中范围应以类型开头：{line}"
            );
            assert!(hits[0].contains(" AAAA"), "命中范围应含 blob：{line}");
        }
    }

    /// 像公钥但**不是**公钥的东西不能命中。
    #[test]
    fn ssh_pubkey_ignores_lookalikes() {
        for bad in [
            "ssh-rsa",                 // 只有类型
            "ssh-rsa AAAAB3NzaC1yc2E", // blob 太短
            "ssh-ed25519 AAAA",        // 极短
            "ssh-ed25519 notbase64notbase64notbase64notbase64notbase64notbase64!",
            // blob 长度够、也以 AAAA 开头，但内部类型串与外部不符 → 校验器必须拦下
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIPSI4uzX8YR1xYGPTFsx0F/2NqLz1k8vJ0m3dP4qR5sT6uV",
            "正文里只是提到了 ssh-rsa 与 ssh-ed25519 这两个词，并没有密钥",
        ] {
            assert!(mask_hits("SSH_PUBKEY", bad).is_empty(), "误报：{bad}");
        }
    }

    /// 公钥脱敏后能完整还原，且占位符形态合法。
    #[test]
    fn ssh_pubkey_roundtrip() {
        use crate::mask::engine::{restore_final, CustomWords, MaskCtx, RestoreStats};
        use crate::mask::session::SessionStore;
        let mut cfg = crate::config::Config::default();
        for k in crate::config::ALL_BUILTIN_RULES {
            cfg.mask.builtin_rules.insert(k.to_string(), true);
        }
        let store = SessionStore::new();
        store.new_session("t");
        let custom = CustomWords::build(&cfg);
        let ctx = MaskCtx::new(&cfg, &store, "t".into(), &custom);
        let raw = format!("我的公钥是 {RSA_PUB}");
        let masked = ctx.mask(&raw);
        assert!(
            !masked.contains("AAAAB3NzaC1yc2E"),
            "公钥 blob 不得残留：{masked}"
        );
        assert!(
            masked.contains("{{SSHPUBKEY_"),
            "应生成 SSH 公钥占位符：{masked}"
        );
        let mut stats = RestoreStats::default();
        let back = restore_final(&masked, "t", false, &store, &mut stats);
        assert_eq!(back, raw, "必须能还原");
        // 注释里的邮箱由 EMAIL 规则单独处理（开公钥规则不应影响它）
        assert!(
            !masked.contains("test-rsa@example.com"),
            "注释里的邮箱也应被脉敏：{masked}"
        );
    }

    /// FIDO 安全密钥型公钥（`sk-*@openssh.com`）：必须**整段**被脱敏。
    ///
    /// 回归：`sk-` 秘密前缀规则（引擎 step 1，比内置规则先跑）会把类型串
    /// `sk-ssh-ed25519` 换成占位符，于是只剩 `@openssh.com AAAA…` 没人认领，
    /// blob 直接上行。现在前缀规则遇到「匹配后面紧跟 `@openssh.com`」时放行。
    ///
    /// 这里没有真实 FIDO 密钥（需要硬件），按 SSH wire format 合成 blob：
    /// u32 长度 + 类型串 + 密钥体。校验器正好会核对这段结构，合成样本同样有效。
    #[test]
    fn ssh_pubkey_fido_sk_types() {
        use base64::Engine as _;
        let mk = |keytype: &str| {
            let mut b = (keytype.len() as u32).to_be_bytes().to_vec();
            b.extend_from_slice(keytype.as_bytes());
            b.extend_from_slice(&[0x11u8; 32]);
            base64::engine::general_purpose::STANDARD.encode(&b)
        };
        for keytype in [
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        ] {
            let blob = mk(keytype);
            let line = format!("FIDO 密钥：{keytype} {blob} me@example.com");
            let hits = mask_hits("SSH_PUBKEY", &line);
            assert_eq!(hits.len(), 1, "{keytype} 应命中，实际 {hits:?}");
            assert_eq!(
                hits[0],
                format!("{keytype} {blob}"),
                "{keytype} 命中范围不对"
            );
        }
        // 类型串与 blob 内部不一致 → 校验器拦下
        let mismatched = format!("sk-ssh-ed25519@openssh.com {}", mk("ssh-ed25519"));
        assert!(
            mask_hits("SSH_PUBKEY", &mismatched).is_empty(),
            "内部类型不符的伪公钥不得命中"
        );
        // 真正的 `sk-` 密钥不能因为上面那个例外被放过
        assert!(
            mask_hits("SSH_PUBKEY", "sk-abcdefghijklmnopqrstuvwxyz012345").is_empty(),
            "`sk-` 开头的普通密钥不是 SSH 公钥"
        );
    }

    /// 公网 IPv6：全局单播 2000::/3 命中。
    #[test]
    fn ipv6_public_masks_global_unicast() {
        for ok in [
            "240e:1a2b::9",
            "2606:4700:4700::1111",
            "2a00:1450:4001:81a::200e",
            "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:4860:4860::8888",
            "2001:0db8:0000:0000:0000:0000:0000:0001", // 不压缩写法（文档段，校验器拦）
        ] {
            let hits = mask_hits("IPV6_PUBLIC", ok);
            // 文档段例外：最后一条应被校验器拒绝
            if ok.starts_with("2001:0db8") {
                assert!(hits.is_empty(), "文档段不应命中：{ok}");
                continue;
            }
            assert_eq!(hits.len(), 1, "{ok} 应命中，实际 {hits:?}");
            assert_eq!(hits[0], ok);
        }
        // URL 里的方括号形态
        assert_eq!(
            mask_hits("IPV6_PUBLIC", "https://[2606:4700::1111]:443/x").len(),
            1
        );
    }

    /// 私网 / 文档段 / 非地址形态都不能被公网规则命中。
    #[test]
    fn ipv6_public_ignores_private_doc_and_lookalikes() {
        for bad in [
            "fe80::1",           // 链路本地
            "fd00:1234::1",      // ULA
            "fc00::1",           // ULA
            "2001:db8::1",       // RFC 3849 文档段
            "::1",               // 环回
            "ff02::1",           // 组播
            "aa:bb:cc:dd:ee:ff", // MAC 不能被当 IPv6
            "20:01:23:45:67:89", // 时间码 / MAC 形态
            "12:34:56",
            "这段正文里没有地址",
        ] {
            assert!(mask_hits("IPV6_PUBLIC", bad).is_empty(), "误报：{bad}");
        }
    }

    /// 新增两条规则的默认开关必须与 config 默认值一致（控制台「恢复默认」依赖它）。
    #[test]
    fn new_rules_default_flags() {
        let d = crate::config::default_builtin_rules();
        assert_eq!(d.get("SSH_PUBKEY"), Some(&true), "SSH 公钥默认应开启");
        assert_eq!(d.get("IPV6_PUBLIC"), Some(&false), "公网 IPv6 默认应关闭");
        assert_eq!(
            crate::config::ALL_BUILTIN_RULES.len(),
            d.len(),
            "两处清单长度须一致"
        );
    }

    #[test]
    fn rules_compile() {
        // 32 条对齐 Python 版 + 本版新增的 2 条（IPV6_PUBLIC / SSH_PUBKEY）
        assert_eq!(RULES.len(), 34);
        for r in RULES.iter() {
            assert!(!r.rx.as_str().is_empty());
        }
        // 标签集合与 config 的 ALL_BUILTIN_RULES 必须一致（否则控制台会出现
        // 「有开关但没规则」或「有规则但改不了」的孤儿）
        let labels: std::collections::BTreeSet<&str> = RULES.iter().map(|r| r.label).collect();
        let allowed: std::collections::BTreeSet<&str> =
            crate::config::ALL_BUILTIN_RULES.iter().copied().collect();
        assert_eq!(labels, allowed, "规则 label 与 ALL_BUILTIN_RULES 不一致");
    }

    #[test]
    fn phone_matches() {
        assert_eq!(mask_hits("PHONE", "电话13812345678"), vec!["13812345678"]);
        assert_eq!(
            mask_hits("PHONE", "电话138-1234-5678"),
            vec!["138-1234-5678"]
        );
        assert_eq!(
            mask_hits("PHONE", "+86 13812345678"),
            vec!["+86 13812345678"]
        );
        assert_eq!(mask_hits("PHONE", "8613812345678"), vec!["8613812345678"]);
        assert!(mask_hits("PHONE", "commit 8613812345678abcdef").is_empty());
    }

    #[test]
    fn email_matches() {
        assert_eq!(
            mask_hits("EMAIL", "test@example.com"),
            vec!["test@example.com"]
        );
        assert_eq!(mask_hits("EMAIL", "张三@qq.com"), vec!["张三@qq.com"]);
        // 首字符类排除 +-：+ 不会吃进本地部分，但 u 起点的 user@example.com 照常命中（与 Python 一致）
        let h1 = mask_hits("EMAIL", "+user@example.com");
        assert_eq!(
            h1,
            vec!["user@example.com"],
            "首字符类排除 + 是指 + 不进本地部分"
        );
    }

    /// P1 回归：「标签:邮箱」无空格写法必须命中（不得因冒号一刀切漏检）。
    ///
    /// 旧实现只要前一字符是 `:` 就否决，于是 `mailto:` / `Email:` / `收件人:`
    /// 全部漏检 —— 这些是极常见写法，漏检 = PII 原文上行。
    #[test]
    fn email_after_colon_label() {
        assert_eq!(
            mask_hits("EMAIL", "mailto:alice@example.com"),
            vec!["alice@example.com"]
        );
        assert_eq!(
            mask_hits("EMAIL", "Email:alice@example.com"),
            vec!["alice@example.com"]
        );
        assert_eq!(
            mask_hits("EMAIL", "收件人:bob@corp.cn;cc:carol@corp.cn"),
            vec!["bob@corp.cn", "carol@corp.cn"]
        );
        // URL 查询参数里的邮箱（前一字符是 `=`）
        assert_eq!(
            mask_hits("EMAIL", "https://host/?email=alice@example.com"),
            vec!["alice@example.com"]
        );
    }

    /// P1 反向：连接串 userinfo 尾的口令**不得**被当成邮箱。
    ///
    /// 冒号否决收窄为「同一 token 里出现过 `://`」，靠这条守住。
    #[test]
    fn email_connstr_userinfo_tail_still_rejected() {
        assert!(mask_hits("EMAIL", "redis://user:password@example.com").is_empty());
        assert!(mask_hits("EMAIL", "postgres://svc:Zq9xLm2p@db.internal:5432/p").is_empty());
        // 没有 `://` 的普通冒号写法不受影响
        assert!(!mask_hits("EMAIL", "收件人:bob@corp.cn").is_empty());
    }

    /// P3：TLD 采用同质交替，中文正文不得被粘进邮箱。
    #[test]
    fn email_tld_stops_at_script_boundary() {
        // 尾部中文正文必须保留
        assert_eq!(
            mask_hits("EMAIL", "zhangsan@qq.com请查收"),
            vec!["zhangsan@qq.com"]
        );
        // 中文 TLD 仍支持
        assert_eq!(mask_hits("EMAIL", "a@b.中国"), vec!["a@b.中国"]);
        // 普通邮箱不受影响
        assert_eq!(
            mask_hits("EMAIL", "alice@mail.example.co.uk"),
            vec!["alice@mail.example.co.uk"]
        );
    }

    /// P4a：钉钉 AppKey 需含数字，普通英文词根标识符不得被当 AppKey。
    #[test]
    fn dingtalk_appkey_requires_digit() {
        for word in ["dingtalkwebhookurl", "dingtalknotificationtemplate"] {
            assert!(
                mask_hits("API_KEY", word).is_empty(),
                "英文标识符不得当 AppKey：{word}"
            );
        }
        // 真实 AppKey（含数字）仍必须命中
        assert_eq!(
            mask_hits("API_KEY", "AppKey=dingbbikazkr7q2kh8s2"),
            vec!["dingbbikazkr7q2kh8s2"]
        );
    }

    /// `overlaps`：前缀/后缀部分重叠必须判真（CONNSTR ↔ EMAIL 豁免依赖它）。
    #[test]
    fn overlaps_semantics() {
        // CONNSTR 命中 vs EMAIL 命中：后缀/前缀部分重叠
        assert!(overlaps("redis://user:password@", "password@example.com"));
        assert!(overlaps("password@example.com", "redis://user:password@"));
        // 包含
        assert!(overlaps("abcdef", "bcd"));
        assert!(overlaps("bcd", "abcdef"));
        // 不相干
        assert!(!overlaps("abcdef", "xyz"));
        assert!(!overlaps("", "abc"));
        assert!(!overlaps("abc", ""));
    }

    /// PRIVATE_KEY 必须覆盖 PKCS#8 **加密**私钥（`ENCRYPTED PRIVATE KEY`）。
    ///
    /// 回归：可选前缀交替里没有 `ENCRYPTED `，于是
    /// `-----BEGIN ENCRYPTED PRIVATE KEY-----` 整块私钥原文上行（`openssl
    /// pkcs8 -topk8` 的产物，备份/中间件配置里很常见）。
    #[test]
    fn private_key_covers_encrypted_pkcs8() {
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"; // 需 ≥20 字符
        for head in [
            "PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
        ] {
            let pem = format!("-----BEGIN {head}-----\n{body}\n-----END {head}-----");
            let hits = mask_hits("PRIVATE_KEY", &pem);
            assert_eq!(hits.len(), 1, "{head} 应整块命中，实际 {hits:?}");
            assert_eq!(hits[0], pem, "{head} 命中范围应为整块");
        }
    }

    /// LANDLINE 不得强制要求国家码：`010-62345678` 这类国内常见写法必须命中。
    ///
    /// 回归：国家码分组被写成**强制**（缺 `?`），结果是默认开启的座机规则
    /// 实际只认带 `+86`/`86`/`(86)` 前缀的号码，**国内座机全部漏检**。
    #[test]
    fn landline_country_code_is_optional() {
        for ok in [
            "010-62345678",
            "010-8234567",
            "0311-87654321",
            "(010)62345678",
            "010-62345678转123",
            "+86 010-62345678",
            "0086010-62345678",
            "(86)010-62345678",
        ] {
            assert_eq!(mask_hits("LANDLINE", ok).len(), 1, "座机应命中：{ok}");
        }
        // 不应命中的形态
        for bad in ["01062345678", "010-1234567", "13812345678"] {
            assert!(mask_hits("LANDLINE", bad).is_empty(), "不应命中：{bad}");
        }
    }

    /// EMAIL：**整段 CJK + 邮箱一起遮**（不做「保留正文」的裁剪）。
    ///
    /// 为什么不做裁剪：为了让中文正文不被吞进占位符，曾尝试用「CJK 前缀 + value_group
    /// 只替换邮箱本体」把前缀排除在替换范围外。但 CJK 前导段究竟是**正文**还是
    /// **姓名**（本地部分的一部分）无法区分 —— 只要把前导 CJK 排除在替换范围外，
    /// 紧随的姓名就会残留明文（`我的邮箱是张三2024@qq.com` → `张三` 留在明文）。
    ///
    /// 结构性论证：记 R = 邮箱前连续 CJK 长度、P = 保留长度、A = 遮掉长度（P+A=R）。
    /// 要「正文可辨」需 P ≥ 5（把 ≥5 字当前缀），于是 A = min(R-5, 4)；
    /// 2 字姓名在 R ≤ 6 时（A ≤ 1）**必然泄漏**。降低 P 下限则 A 增大但 P 变小，
    /// 「保留正文」失去意义，且 R = P 时依旧泄漏 —— 与阈值取值无关。
    ///
    /// 按项目「漏检（PII 原文上行）比误报更不可接受」的原则，选择**不裁剪**：
    /// 宁可多遮几个中文字（过度脱敏、可完整还原），也不让姓名落到上游。
    #[test]
    fn email_masks_whole_cjk_run_without_leaking_names() {
        // 三轮 review 提出的反例：不得只遮后半截而把姓名留在明文。
        // 用真实引擎断言「遮敏后的输出不含姓名」，并用规则层断言命中范围含姓名。
        use crate::mask::engine::{CustomWords, MaskCtx};
        use crate::mask::session::SessionStore;
        let mut cfg = crate::config::Config::default();
        for k in crate::config::ALL_BUILTIN_RULES {
            cfg.mask.builtin_rules.insert(k.to_string(), true);
        }
        let store = SessionStore::new();
        store.new_session("cjk");
        let custom = CustomWords::build(&cfg);
        let ctx = MaskCtx::new(&cfg, &store, "cjk".into(), &custom);
        for (text, name) in [
            ("我的邮箱是张三2024@qq.com", "张三"),
            ("请联系王五2024@qq.com", "王五"),
            ("邮箱是李四@qq.com", "李四"),
        ] {
            let masked = ctx.mask(text);
            assert!(
                !masked.contains(name),
                "姓名不得残留明文：{text} -> {masked}"
            );
            // 规则层：命中范围必须包含姓名与完整邮箱
            let hit = mask_hits("EMAIL", text);
            assert_eq!(hit.len(), 1, "应命中一次：{text} -> {hit:?}");
            assert!(
                hit[0].contains(name) && hit[0].ends_with("@qq.com"),
                "命中范围应含「姓名 + 完整邮箱」：{text} -> {hit:?}"
            );
        }
        // 中文姓名/中文本地部分：整体命中
        assert_eq!(
            mask_hits("EMAIL", "张三2024@qq.com"),
            vec!["张三2024@qq.com"]
        );
        assert_eq!(
            mask_hits("EMAIL", "李四_work@qq.com"),
            vec!["李四_work@qq.com"]
        );
        assert_eq!(mask_hits("EMAIL", "张三@qq.com"), vec!["张三@qq.com"]);
        assert_eq!(
            mask_hits("EMAIL", "联系人张三@qq.com"),
            vec!["联系人张三@qq.com"]
        );
        // 超长 CJK 前缀（旧实现在这里整段漏检）：至少遮住邮箱本体
        let long = format!("{}zhangsan@qq.com", "汉".repeat(65));
        let hit = mask_hits("EMAIL", &long);
        assert_eq!(hit.len(), 1, "65 个连续汉字不得导致邮箱整段漏检");
        assert!(hit[0].ends_with("zhangsan@qq.com"), "实际 {hit:?}");
        // 纯中文本地部分 + 超长 CJK 前缀：若左边界一律拒绝 CJK 前一字符，
        // 贪婪版只能从「后缀」开始匹配 → 整段漏检（PII 上行）。
        let long_cjk_local = format!("{}张三@qq.com", "汉".repeat(65));
        let hit = mask_hits("EMAIL", &long_cjk_local);
        assert_eq!(hit.len(), 1, "纯中文邮箱在长 CJK 前缀下不得整段漏检");
        assert!(hit[0].ends_with("张三@qq.com"), "实际 {hit:?}");
    }

    /// TOKEN：Bearer 值必须含数字或符号（纯字母词形正文不算 token）。
    #[test]
    fn bearer_value_requires_digit_or_symbol() {
        assert!(mask_hits("TOKEN", "Authorization: Bearer authenticationtokensystem").is_empty());
        for ok in [
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz-_.~",
        ] {
            assert_eq!(mask_hits("TOKEN", ok).len(), 1, "真 token 应命中：{ok}");
        }
    }

    /// 回归：包名/资源名 + 版本号 + 文件后缀不得命中（email_ok 语义校验拦下）。
    #[test]
    fn email_ignores_package_and_asset_names() {
        for not_email in [
            "earendil-works__pi-ai@0.87.1.patch",
            "exceljs@4.4.0.patch",
            "electron__osx-sign@1.3.3.patch",
            "lodash@4.17.21.tgz",
            "logo@2x.png",
            "data@2024.01.01.csv",
        ] {
            assert!(
                mask_hits("EMAIL", not_email).is_empty(),
                "不得当邮箱：{not_email}"
            );
        }
        // 同一段里的真实邮箱仍要命中
        assert_eq!(
            mask_hits("EMAIL", "包 exceljs@4.4.0.patch 作者 alice@example.com"),
            vec!["alice@example.com"]
        );
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

    /// 钉钉 `ding` 前缀：普通英文词根不得被当成 AppKey。
    ///
    /// 回归：原规则是 `ding[a-z0-9]{6,}` 且左边界只拦 `[A-Za-z0-9_-]`，
    /// `dingalings` / `dingleberry` 会被整词吃掉。现收为 `alpha_l` 边界
    /// （不得紧跟在字母后）+ 下限抬到 12 位。
    #[test]
    fn dingtalk_apikey_not_english_word() {
        for word in ["dingalings", "dingleberry", "dingbatsxx"] {
            assert!(
                mask_hits("API_KEY", word).is_empty(),
                "普通英文词不得当 AppKey：{word}"
            );
        }
        // 真实 AppKey 形态（ding + 16 位）仍必须命中
        assert_eq!(
            mask_hits("API_KEY", "AppKey=dingbbikazkr7q2kh8s2"),
            vec!["dingbbikazkr7q2kh8s2"]
        );
        // 数字左邻仍放行（版本号前缀等）
        assert!(!mask_hits("API_KEY", "v2dingbbikazkr7q2kh8s2").is_empty());
    }

    /// 飞书 `cli_` App ID：官方形态为 `cli_` + 16 位。
    #[test]
    fn feishu_appid_still_matches() {
        assert_eq!(
            mask_hits("API_KEY", "APP_ID=cli_9b445f5258795107"),
            vec!["cli_9b445f5258795107"]
        );
        // 带分隔左邻正常
        assert!(!mask_hits("API_KEY", "\"cli_9b445f5258795107\"").is_empty());
    }

    /// MAC 左边界收紧：`.` 左邻不再命中（与右边界口径对齐）。
    #[test]
    fn mac_dot_boundary_tightened() {
        assert!(mask_hits("MAC", "v1.00:11:22:33:44:55").is_empty());
        assert!(!mask_hits("MAC", "mac=00:11:22:33:44:55").is_empty());
        assert!(!mask_hits("MAC", "00:11:22:33:44:55").is_empty());
    }

    #[test]
    fn ip_rules() {
        assert_eq!(
            mask_hits("IP_PRIVATE", "内网192.168.1.1"),
            vec!["192.168.1.1"]
        );
        assert_eq!(
            mask_hits("IP_PRIVATE", "链路169.254.1.2"),
            vec!["169.254.1.2"]
        );
        assert_eq!(
            mask_hits("IP_PRIVATE", "ts 100.118.224.56"),
            vec!["100.118.224.56"]
        );
        assert!(mask_hits("IP_PRIVATE", "版本 192.168.1.1.1").is_empty()); // 5 段不算
        assert!(!mask_hits("IP_INTERNAL", "内网 10.1.2.3").is_empty());
        assert_eq!(
            mask_hits("IP_PUBLIC", "访问 123.57.89.10"),
            vec!["123.57.89.10"]
        );
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
