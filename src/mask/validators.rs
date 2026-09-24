//! 语义校验器：Luhn / 身份证 / IBAN / JWT / USCC / 车牌 / 手机号 / 座机 /
//! 邮箱 / 连接串 / IPv4 公网 / IPv6 私网。
//!
//! 逐条对齐 Python transparent.py 的 `_card_ok` / `_idcard_ok` / … 系列函数，
//! 语义（含误报防御细节）必须一致——这些是黄金样本对齐的基础。

use base64::Engine as _;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Luhn / 银行卡
// ---------------------------------------------------------------------------

/// Luhn 校验（对齐 `_luhn_ok`）。
pub fn luhn_ok(num: &str) -> bool {
    let digits: Vec<u32> = num.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 12 {
        return false;
    }
    let mut sum = 0u32;
    let mut dbl = false;
    for &d in digits.iter().rev() {
        let d = if dbl {
            if d > 4 {
                d * 2 - 9
            } else {
                d * 2
            }
        } else {
            d
        };
        sum += d;
        dbl = !dbl;
    }
    sum.is_multiple_of(10)
}

/// 银行卡最终判据（对齐 `_card_ok`）：去分隔符后 13-19 位纯数字 + Luhn。
pub fn card_ok(orig: &str) -> bool {
    let digits: String = orig.chars().filter(|c| c.is_ascii_digit()).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    luhn_ok(&digits)
}

// ---------------------------------------------------------------------------
// 身份证（15/18 位）
// ---------------------------------------------------------------------------

const IDCARD_WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const IDCARD_CODES: &[u8] = b"10X98765432";

fn is_valid_province(prefix: &str) -> bool {
    matches!(
        prefix,
        "11" | "12"
            | "13"
            | "14"
            | "15"
            | "21"
            | "22"
            | "23"
            | "31"
            | "32"
            | "33"
            | "34"
            | "35"
            | "36"
            | "37"
            | "41"
            | "42"
            | "43"
            | "44"
            | "45"
            | "46"
            | "50"
            | "51"
            | "52"
            | "53"
            | "54"
            | "61"
            | "62"
            | "63"
            | "64"
            | "65"
            | "71"
            | "81"
            | "82"
    )
}

/// 日期真实性（1880~今年，含闰年），对齐 Python datetime.date 校验。
fn is_real_date(y: i32, m: u32, d: u32) -> bool {
    if !(1..=12).contains(&m) {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let max_d = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    (1..=max_d).contains(&d)
}

/// 18 位身份证（对齐 `_idcard18_ok`）：省份 + 真实日期 + ISO 7064 MOD 11-2。
pub fn idcard18_ok(num: &str) -> bool {
    if num.len() != 18 || !num[..17].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !is_valid_province(&num[..2]) {
        return false;
    }
    let y: i32 = num[6..10].parse().unwrap_or(0);
    let m: u32 = num[10..12].parse().unwrap_or(0);
    let d: u32 = num[12..14].parse().unwrap_or(0);
    if !is_real_date(y, m, d) {
        return false;
    }
    let now_year = 2026; // 与测试运行期一致；Python 用当前年，这里固定避免时钟漂移
    if !(1880..=now_year).contains(&y) {
        return false;
    }
    let total: u32 = num[..17]
        .chars()
        .zip(IDCARD_WEIGHTS.iter())
        .map(|(c, w)| c.to_digit(10).unwrap_or(0) * w)
        .sum();
    let check = IDCARD_CODES[(total % 11) as usize] as char;
    num[17..].to_uppercase().starts_with(check)
}

/// 15 位身份证（对齐 `_idcard15_ok`）：省份 + 19YY 真实日期。
pub fn idcard15_ok(num: &str) -> bool {
    if num.len() != 15 || !num.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !is_valid_province(&num[..2]) {
        return false;
    }
    let yy: i32 = num[6..8].parse().unwrap_or(0);
    let m: u32 = num[8..10].parse().unwrap_or(0);
    let d: u32 = num[10..12].parse().unwrap_or(0);
    if !is_real_date(1900 + yy, m, d) {
        return false;
    }
    (1900..=1999).contains(&(1900 + yy))
}

/// 身份证统一校验（按长度分发，对齐 `_idcard_ok`）。
pub fn idcard_ok(num: &str) -> bool {
    match num.len() {
        18 => idcard18_ok(num),
        15 => idcard15_ok(num),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 手机号 / 座机
// ---------------------------------------------------------------------------

/// 手机号（对齐 `_phone_ok`）：核心 11 位、1[3-9] 开头、排除全同号。
pub fn phone_ok(num_str: &str) -> bool {
    let digits: String = num_str.chars().filter(|c| c.is_ascii_digit()).collect();
    let digits = if digits.starts_with("86") && digits.len() == 13 {
        digits[2..].to_string()
    } else if digits.starts_with("0086") && digits.len() == 15 {
        digits[4..].to_string()
    } else {
        digits
    };
    if digits.len() != 11 {
        return false;
    }
    let b = digits.as_bytes();
    if b[0] != b'1' || !(b'3'..=b'9').contains(&b[1]) {
        return false;
    }
    // 排除全同号
    if digits.chars().all(|c| c == digits.chars().next().unwrap()) {
        return false;
    }
    true
}

/// 座机（对齐 `_landline_ok`）：0 开头 + 区号 + 本地号首位 2-9。
pub fn landline_ok(num_str: &str) -> bool {
    let digits: String = num_str.chars().filter(|c| c.is_ascii_digit()).collect();
    let digits = if let Some(d) = digits.strip_prefix("0086") {
        d.to_string()
    } else if let Some(d) = digits.strip_prefix("86") {
        d.to_string()
    } else {
        digits
    };
    if !(10..=17).contains(&digits.len()) {
        return false;
    }
    if !digits.starts_with('0') {
        return false;
    }
    let b = digits.as_bytes();
    let local_first = if digits.len() >= 4 && (b[1] == b'1' || b[1] == b'2') {
        digits.as_bytes()[3] as char
    } else if digits.len() >= 5 && (b'3'..=b'9').contains(&b[1]) {
        digits.as_bytes()[4] as char
    } else {
        return false;
    };
    ('2'..='9').contains(&local_first)
}

// ---------------------------------------------------------------------------
// 邮箱
// ---------------------------------------------------------------------------

/// 邮箱校验（对齐 `_email_ok`）：单 @、无连续双点、TLD ≥ 2。
pub fn email_ok(email_str: &str) -> bool {
    let s = email_str.trim();
    if !s.contains('@') || s.starts_with('@') || s.ends_with('@') {
        return false;
    }
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);
    if local.is_empty() || domain.len() < 3 || !domain.contains('.') {
        return false;
    }
    if local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.contains("..")
    {
        return false;
    }
    let tld = domain.rsplit('.').next().unwrap_or("");
    tld.len() >= 2
}

// ---------------------------------------------------------------------------
// IBAN
// ---------------------------------------------------------------------------

/// IBAN mod-97（对齐 `_iban_ok`）。
pub fn iban_ok(iban: &str) -> bool {
    let s = iban.trim();
    if s.len() < 15 {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 4 {
        return false;
    }
    // 结构：2 字母 + 2 数字 + ≥11 位字母数字
    if !chars[0].is_ascii_uppercase() || !chars[1].is_ascii_uppercase() {
        return false;
    }
    if !chars[2].is_ascii_digit() || !chars[3].is_ascii_digit() {
        return false;
    }
    if !(15..=36).contains(&chars.len()) {
        return false;
    }
    if !chars[4..].iter().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    // 前移 4 位展开数字串求 mod 97（分块避免 bigint）
    let mut reordered: String = chars[4..].iter().collect();
    reordered.push_str(&chars[..4].iter().collect::<String>());
    let mut rem: u64 = 0;
    for c in reordered.chars() {
        let piece = if c.is_ascii_uppercase() {
            format!("{}", c as u32 - 'A' as u32 + 10)
        } else {
            c.to_string()
        };
        for d in piece.chars() {
            rem = (rem * 10 + d.to_digit(10).unwrap() as u64) % 97;
        }
    }
    rem == 1
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

/// JWT 三段形态 + header 含 "alg"（对齐 `_jwt_ok`）。
pub fn jwt_ok(token: &str) -> bool {
    let head = token.split('.').next().unwrap_or("");
    if head.is_empty() {
        return false;
    }
    // base64url 解码
    let padded = match head.len() % 4 {
        2 => format!("{head}=="),
        3 => format!("{head}="),
        _ => head.to_string(),
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(padded.trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&padded));
    match decoded {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s.contains("\"alg\""),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// USCC
// ---------------------------------------------------------------------------

const USCC_CHARS: &[u8] = b"0123456789ABCDEFGHJKLMNPQRTUWXY";
const USCC_WEIGHTS: [usize; 17] = [
    1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28,
];

/// USCC 校验位（GB 32100-2015 MOD31，对齐 `_uscc_ok`）。
pub fn uscc_ok(orig: &str) -> bool {
    if orig.len() != 18 {
        return false;
    }
    let b = orig.as_bytes();
    let idx = |c: u8| -> Option<usize> { USCC_CHARS.iter().position(|&x| x == c) };
    let mut total = 0usize;
    for i in 0..17 {
        match idx(b[i]) {
            Some(v) => total += USCC_WEIGHTS[i] * v,
            None => return false,
        }
    }
    let check = (31 - total % 31) % 31;
    USCC_CHARS[check] == b[17]
}

// ---------------------------------------------------------------------------
// IPv4 公网 / IPv6 私网
// ---------------------------------------------------------------------------

/// 已知公共 DNS 白名单（对齐 `KNOWN_PUBLIC_DNS`）。
const KNOWN_PUBLIC_DNS: &[&str] = &[
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "4.2.2.1",
    "4.2.2.2",
    "4.2.2.3",
    "114.114.114.114",
    "114.114.115.115",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "180.76.76.76",
    "9.9.9.9",
    "208.67.222.222",
    "208.67.220.220",
];

fn ipv4_parts(orig: &str) -> Option<[u32; 4]> {
    let parts: Vec<&str> = orig.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u32; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let v: u32 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        out[i] = v;
    }
    Some(out)
}

/// 公网 IPv4（对齐 `_ip_public_ok`）：白名单 + 版本号启发式 + global + 非组播。
pub fn ip_public_ok(orig: &str) -> bool {
    if KNOWN_PUBLIC_DNS.contains(&orig) {
        return false;
    }
    let Some(parts) = ipv4_parts(orig) else {
        return false;
    };
    let segs: Vec<&str> = orig.split('.').collect();
    // 四段全个位数：版本号/教学示例
    if segs.iter().all(|s| s.len() == 1) {
        return false;
    }
    // 构建号形态：首段个位 + 第三段 0 + 末段三位数
    if segs[0].len() == 1 && segs[2] == "0" && segs[3].len() == 3 {
        return false;
    }
    let [a, b, c, _d] = parts;
    // 私网/保留段/环回/组播（is_global 的展开）
    let is_private = a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || a == 0
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224; // 组播 + 保留
    !is_private
}

/// IPv6 私网（对齐 `_ipv6_private_ok`）：fe80::/10 链路本地 或 fc00::/7 ULA。
pub fn ipv6_private_ok(orig: &str) -> bool {
    if orig.matches(':').count() < 2 {
        return false;
    }
    let candidate = orig.split('%').next().unwrap_or(orig);
    // 简易解析：按 : 分组，处理 :: 压缩
    let Some(groups) = parse_ipv6(candidate) else {
        return false;
    };
    let first = groups[0];
    // fe80::/10 → 0xfe80..0xfebf
    if (0xfe80..=0xfebf).contains(&first) {
        return true;
    }
    // fc00::/7 → 0xfc00..0xfdff
    (0xfc00..=0xfdff).contains(&first)
}

/// IPv6 公网（全局单播 2000::/3）。
///
/// 与 `ip_public_ok` 同口径：排除**文档/保留段**，避免把技术文档里的示例地址
/// 当成真实地址（IPv4 那边对应地排除了 192.0.2.0/24）。这里只排除
/// `2001:db8::/32`（RFC 3849 专用文档段）；`2001::/32` Teredo、`2002::/16` 6to4
/// 虽然多是过渡机制，但确实是真实可路由地址，不排除。
pub fn ipv6_public_ok(orig: &str) -> bool {
    if orig.matches(':').count() < 2 {
        return false;
    }
    let candidate = orig.split('%').next().unwrap_or(orig);
    let Some(groups) = parse_ipv6(candidate) else {
        return false;
    };
    let first = groups[0];
    // 2000::/3 → 0x2000..=0x3fff
    if !(0x2000..=0x3fff).contains(&first) {
        return false;
    }
    // 2001:db8::/32 文档段
    if first == 0x2001 && groups[1] == 0x0db8 {
        return false;
    }
    true
}

/// SSH 公钥校验：把 blob 解出来，核对 SSH wire format 的内部类型串。
///
/// blob 的结构是「u32 大端长度 + 类型字符串 + 密钥内容」，所以可以**精确**校验：
/// 长度字段必须等于外部写的 keytype 长度，且后面的字节就是那个 keytype。
/// 这样即使正文里恰好出现 `ssh-rsa AAAA…` 形状的字符串，只要 blob 不是真密钥就判否。
///
/// 兼容带与不带 `=` 填充的两种 base64（ssh-keygen 对 ed25519 不补 `=`）。
pub fn ssh_pubkey_ok(keytype: &str, orig: &str) -> bool {
    use base64::Engine as _;
    if keytype.is_empty() {
        return false;
    }
    let Some(blob) = orig.split_whitespace().nth(1) else {
        return false;
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(blob));
    let Ok(bytes) = bytes else {
        return false;
    };
    if bytes.len() < 4 {
        return false;
    }
    let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if declared != keytype.len() || bytes.len() < 4 + declared {
        return false;
    }
    &bytes[4..4 + declared] == keytype.as_bytes()
}

/// 解析 IPv6 到 8 组 u16。支持 :: 压缩与 %zone 剥离；失败返回 None。
fn parse_ipv6(s: &str) -> Option<[u16; 8]> {
    let mut out = [0u16; 8];
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let parse_group = |g: &str| -> Option<u16> {
        if g.is_empty() || g.len() > 4 || !g.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(g, 16).ok()
    };
    let head_groups: Vec<u16> = if head.is_empty() {
        vec![]
    } else {
        head.split(':')
            .map(parse_group)
            .collect::<Option<Vec<_>>>()?
    };
    match tail {
        None => {
            if head_groups.len() != 8 {
                return None;
            }
            for (i, g) in head_groups.iter().enumerate() {
                out[i] = *g;
            }
        }
        Some(t) => {
            let tail_groups: Vec<u16> = if t.is_empty() {
                vec![]
            } else {
                t.split(':').map(parse_group).collect::<Option<Vec<_>>>()?
            };
            let total = head_groups.len() + tail_groups.len();
            if total > 8 {
                return None;
            }
            for (i, g) in head_groups.iter().enumerate() {
                out[i] = *g;
            }
            let base = 8 - tail_groups.len();
            for (i, g) in tail_groups.iter().enumerate() {
                out[base + i] = *g;
            }
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// 连接串（CONNSTR 豁免判定）
// ---------------------------------------------------------------------------

/// 文档占位主机（对齐 `_CONNSTR_DUMMY_HOSTS`）。
const DUMMY_HOSTS: &[&str] = &[
    "host",
    "hostname",
    "myhost",
    "server",
    "myserver",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "sample.com",
    "your-host",
    "yourhost",
    "yourdomain.com",
];
const DUMMY_HOST_SUFFIXES: &[&str] = &[".example", ".invalid"];
const PLACEHOLDER_USERS: &[&str] = &[
    "user",
    "username",
    "your_username",
    "yourusername",
    "usr",
    "guest",
];
const PLACEHOLDER_PASSWORDS: &[&str] = &[
    "pass",
    "password",
    "passwd",
    "your_password",
    "yourpassword",
    "changeme",
    "change_me",
    "guest",
];

/// 连接串密码真伪校验（对齐 `_connstr_ok` 的文档/模板豁免判据）。
///
/// * `password` — 捕获的密码组
/// * `prefix` — 完整匹配 `scheme://user:pass@`（Python m.group(0)）
/// * `after` — 匹配结束位置之后的文本（用于解析 authority）
///
/// 返回 (脱敏成立, 豁免区间 Some((start,end))——豁免时返回匹配区间供 EMAIL 避让)。
pub fn connstr_ok(
    password: &str,
    prefix: &str,
    after: &str,
    match_start: usize,
    match_end: usize,
) -> bool {
    // 通配占位 / 锚定模板形态：不是真实密码，但也不豁免（返回 false = 不脱敏）
    if is_wildcard(password) || is_anchored_template(password) {
        return false;
    }
    let user_part = extract_user(prefix, password);
    let (host, port) = parse_authority(after);
    let host_lower = host.trim_matches(|c| c == '[' || c == ']').to_lowercase();
    let user_lower = user_part.to_lowercase();
    let pass_lower = password.to_lowercase();
    let host_dummy = DUMMY_HOSTS.contains(&host_lower.as_str())
        || DUMMY_HOST_SUFFIXES.iter().any(|s| host_lower.ends_with(s));
    let user_dummy = PLACEHOLDER_USERS.contains(&user_lower.as_str());
    let pass_dummy = PLACEHOLDER_PASSWORDS.contains(&pass_lower.as_str());

    // 1. 非数字端口 + 用户名/密码是占位词 → 豁免
    if !port.is_empty() && !port.chars().any(|c| c.is_ascii_digit()) && (user_dummy || pass_dummy) {
        return false;
    }
    // 2. 占位主机 + 占位密码 → 豁免
    if host_dummy && pass_dummy {
        return false;
    }
    // 3. 经典教学凭据对
    if user_dummy && pass_dummy {
        return false;
    }
    let _ = (match_start, match_end);
    true
}

fn is_wildcard(pw: &str) -> bool {
    !pw.is_empty() && pw.chars().all(|c| matches!(c, 'x' | 'X' | '*' | '.'))
}

fn is_anchored_template(pw: &str) -> bool {
    // {password} / ${PORT} / <password> / [password] / $PORT / %PWD%
    let b = pw.as_bytes();
    if b.len() < 3 {
        return false;
    }
    let ident_start = |c: u8| c.is_ascii_alphabetic() || c == b'_';
    let ident = |s: &[u8]| -> bool {
        !s.is_empty()
            && ident_start(s[0])
            && s[1..]
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'_')
    };
    match b[0] {
        b'{' => pw.ends_with('}') && ident(&b[1..b.len() - 1]),
        b'<' => pw.ends_with('>') && ident(&b[1..b.len() - 1]),
        b'[' => pw.ends_with(']') && ident(&b[1..b.len() - 1]),
        b'$' => {
            if b[1] == b'{' {
                pw.ends_with('}') && ident(&b[2..b.len() - 1])
            } else {
                ident(&b[1..])
            }
        }
        b'%' => pw.ends_with('%') && ident(&b[1..b.len() - 1]),
        _ => false,
    }
}

/// 从 `scheme://user:pass@` 前缀回推 username。
fn extract_user(prefix: &str, password: &str) -> String {
    if let Some((_scheme, rest)) = prefix.split_once("://") {
        let needle = format!(":{password}@");
        if let Some(idx) = rest.rfind(&needle) {
            return rest[..idx].to_string();
        }
        return rest.split(':').next().unwrap_or("").to_string();
    }
    String::new()
}

/// 从匹配后的文本解析 authority 的 (host, port)。
fn parse_authority(after: &str) -> (String, String) {
    let tail: String = after.chars().take(256).collect();
    let end = tail
        .find(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '/' | '?' | '#' | '"' | '\'' | '`' | ')' | '>' | '}' | ',' | ';'
                )
        })
        .unwrap_or(tail.len());
    let auth = &tail[..end];
    if auth.starts_with('[') {
        if let Some(j) = auth.find(']') {
            let host = auth[1..j].to_string();
            let rest = &auth[j + 1..];
            let port = rest.strip_prefix(':').unwrap_or("").to_string();
            return (host, port);
        }
    }
    match auth.split_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (auth.to_string(), String::new()),
    }
}

// ---------------------------------------------------------------------------
// 凭据摘要 / 预览
// ---------------------------------------------------------------------------

/// 凭据不可逆摘要（sha256 前 16 位，对齐 `_cred_digest`）。
pub fn cred_digest(orig: &str) -> String {
    let mut h = Sha256::new();
    h.update(orig.as_bytes());
    let out = h.finalize();
    out.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// 高熵凭据标签（前缀 + 末 4 位预览的分档判据）。
pub fn is_high_entropy_label(label: &str) -> bool {
    matches!(label, "API_KEY" | "TOKEN" | "ACCESS_KEY" | "JWT")
}

/// 凭据预览（对齐 `_cred_preview`）：可识别但不可用。
pub fn cred_preview(orig: &str, label: &str) -> String {
    let n = orig.chars().count();
    if label == "PRIVATE_KEY" {
        let kind = if orig.contains("RSA PRIVATE KEY") {
            "RSA"
        } else if orig.contains("EC PRIVATE KEY") {
            "EC"
        } else if orig.contains("OPENSSH PRIVATE KEY") {
            "OPENSSH"
        } else if orig.contains("DSA PRIVATE KEY") {
            "DSA"
        } else if orig.contains("PGP PRIVATE KEY") {
            "PGP"
        } else {
            "PEM"
        };
        return format!("<{kind} 私钥 {n} 字节>");
    }
    if is_high_entropy_label(label) && n >= 20 {
        let chars: Vec<char> = orig.chars().collect();
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[n - 4..].iter().collect();
        return format!("{head}…{tail}");
    }
    format!("<{label} {n} 位>")
}

/// 普通预览（对齐 `_preview` 非凭据分支）。
pub fn plain_preview(orig: &str) -> String {
    let chars: Vec<char> = orig.chars().collect();
    let n = chars.len();
    match n {
        0 => String::new(),
        1..=2 => format!("{}{}", chars[0], "*"),
        3..=5 => {
            let mut s = String::new();
            s.push(chars[0]);
            s.push_str(&"*".repeat(n - 1));
            s
        }
        6..=12 => {
            let mut s = String::new();
            s.push(chars[0]);
            s.push_str(&"*".repeat(n - 2));
            s.push(chars[n - 1]);
            s
        }
        _ => {
            let mut s: String = chars[..2].iter().collect();
            s.push_str("**");
            s.extend(chars[n - 2..].iter());
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_and_card() {
        assert!(luhn_ok("4111111111111111"));
        assert!(!luhn_ok("4111111111111112"));
        assert!(card_ok("4111111111111111"));
        assert!(card_ok("4111 1111 1111 1111"));
        // card_ok 只验位数+Luhn；00 开头的排除在规则层正则 [3-6]，
        // 「大小+年份」跨空格拼卡的排除也在正则层（分组支要求分隔符一致）。
        assert!(card_ok("0000000000000026"));
        assert!(card_ok("313524224 2023")); // 13 位且 Luhn 过 — 拦截在规则层
    }

    #[test]
    fn idcard() {
        // 18 位（GB11643 校验位 4）
        assert!(idcard18_ok("110101199003074514"));
        assert!(!idcard18_ok("11010119900307451X"));
        // 15 位（省份 11 + 1990-03-07 真实日期）
        assert!(idcard15_ok("110101900307451"));
        assert!(!idcard15_ok("065217391304348")); // 省份 06 非法
                                                  // 数值型身份证（校验位合法）
        assert!(idcard_ok("110101199003077213"));
    }

    #[test]
    fn phone_landline() {
        assert!(phone_ok("13812345678"));
        assert!(phone_ok("+86 13812345678"));
        assert!(phone_ok("138-1234-5678"));
        assert!(!phone_ok("11111111111")); // 全同号
        assert!(!phone_ok("12345678901")); // 第二位 2 不合法
        assert!(landline_ok("010-82345678"));
        assert!(landline_ok("0108234567"));
    }

    #[test]
    fn email() {
        assert!(email_ok("test@example.com"));
        assert!(email_ok("张三@qq.com"));
        assert!(!email_ok("a@b.c")); // TLD 1 位
        assert!(!email_ok("@example.com"));
        assert!(!email_ok("test@exam..com"));
    }

    #[test]
    fn iban() {
        assert!(iban_ok("GB82WEST12345698765432"));
        assert!(!iban_ok("GB82WEST12345698765433")); // 校验位错
    }

    #[test]
    fn jwt() {
        // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 → {"alg":"HS256","typ":"JWT"}
        let tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(jwt_ok(tok));
        assert!(!jwt_ok("abc.def.ghi"));
    }

    #[test]
    fn uscc() {
        assert!(uscc_ok("91100000100003962T")); // 国家电网
        assert!(uscc_ok("91310000631295002H")); // 浦发银行
        assert!(!uscc_ok("91100000100003962A")); // 篡改校验位
    }

    #[test]
    fn ip_public() {
        assert!(ip_public_ok("123.57.89.10"));
        assert!(ip_public_ok("47.98.12.34"));
        assert!(!ip_public_ok("8.8.8.8")); // DNS 白名单
        assert!(!ip_public_ok("1.1.1.1"));
        assert!(!ip_public_ok("114.114.114.114"));
        assert!(!ip_public_ok("1.2.3.4")); // 全个位数 = 版本号
        assert!(!ip_public_ok("192.168.1.1")); // 私网
        assert!(!ip_public_ok("10.0.0.1"));
        assert!(!ip_public_ok("127.0.0.1")); // 环回
    }

    #[test]
    fn ipv6_private() {
        assert!(ipv6_private_ok("fe80::1"));
        assert!(ipv6_private_ok("fe80::1%eth0")); // zone id
        assert!(ipv6_private_ok("fd00:1234:5678::1")); // ULA
        assert!(ipv6_private_ok("Fe80::1")); // 混合大小写
        assert!(!ipv6_private_ok("2001:db8::1")); // 文档段
        assert!(!ipv6_private_ok("240e:1a2b::9")); // 公网
        assert!(!ipv6_private_ok("aa:bb:cc:dd:ee:ff")); // MAC 不该当 IPv6
    }

    #[test]
    fn ipv6_public() {
        // 全局单播 2000::/3
        assert!(ipv6_public_ok("240e:1a2b::9"));
        assert!(ipv6_public_ok("2606:4700:4700::1111"));
        assert!(ipv6_public_ok("2a00:1450:4001:81a::200e"));
        assert!(ipv6_public_ok("2001:4860:4860::8888"));
        assert!(ipv6_public_ok("3fff::1"));
        assert!(ipv6_public_ok("2606:4700::1111%eth0")); // zone id
        assert!(ipv6_public_ok("2606:4700::1111".to_uppercase().as_str())); // 大写
                                                                            // 2001:db8::/32 是 RFC 3849 文档段，与 ip_public_ok 排除 192.0.2.0/24 同口径
        assert!(!ipv6_public_ok("2001:db8::1"));
        assert!(!ipv6_public_ok("2001:0db8:0000::1"));
        // 私网 / 环回 / 组播 / 非地址
        assert!(!ipv6_public_ok("fe80::1"));
        assert!(!ipv6_public_ok("fd00:1234::1"));
        assert!(!ipv6_public_ok("fc00::1"));
        assert!(!ipv6_public_ok("::1"));
        assert!(!ipv6_public_ok("ff02::1"));
        assert!(!ipv6_public_ok("aa:bb:cc:dd:ee:ff")); // MAC
        assert!(!ipv6_public_ok("1fff::1")); // 刚好低于 2000::/3
        assert!(!ipv6_public_ok("4000::1")); // 刚好高于 3fff
        assert!(!ipv6_public_ok("12:34:56")); // 冒号不够
        assert!(!ipv6_public_ok("没有地址"));
    }

    #[test]
    fn ssh_pubkey_structure() {
        use base64::Engine as _;
        // 用真实结构造一个最小样本（会随形式变化而变化，故与 rules 里的真实密钥互补）
        let mk = |keytype: &str, body: &[u8]| {
            let mut b = (keytype.len() as u32).to_be_bytes().to_vec();
            b.extend_from_slice(keytype.as_bytes());
            b.extend_from_slice(body);
            format!(
                "{keytype} {}",
                base64::engine::general_purpose::STANDARD.encode(&b)
            )
        };
        let ed = mk("ssh-ed25519", &[0u8; 32]);
        assert!(ssh_pubkey_ok("ssh-ed25519", &ed));
        // 类型对不上 → 拒绝（这正是「像公钥但内部类型不符」的兵例）
        assert!(!ssh_pubkey_ok("ssh-rsa", &ed));
        assert!(!ssh_pubkey_ok("ssh-ed25519", "ssh-ed25519 AAAA"));
        assert!(!ssh_pubkey_ok("ssh-ed25519", "ssh-ed25519 不是base64!!!!"));
        assert!(!ssh_pubkey_ok("ssh-ed25519", "ssh-ed25519")); // 没有 blob
        assert!(!ssh_pubkey_ok("", &ed));
        // 声明的长度超出实际字节数 → 拒绝
        let truncated = base64::engine::general_purpose::STANDARD.encode([0, 0, 0, 40u8]);
        assert!(!ssh_pubkey_ok("ssh-rsa", &format!("ssh-rsa {truncated}")));
    }

    #[test]
    fn connstr() {
        // 真实口令：脱敏
        assert!(connstr_ok(
            "Zq9xLm2pTv8w",
            "postgres://usr:Zq9xLm2pTv8w@",
            ":5432/prod",
            0,
            26
        ));
        // 教学组合 user:pass → 豁免
        assert!(!connstr_ok("pass", "mysql://user:pass@", ":3306/db", 0, 18));
        // 通配占位 → 不脱敏也不豁免区间
        assert!(!connstr_ok("xxxx", "redis://default:xxxx@", ":6379", 0, 21));
    }

    #[test]
    fn previews() {
        assert_eq!(cred_digest("abc").len(), 16);
        // 高熵凭据：前缀 + 末 4 位
        let pv = cred_preview("sk-1234567890abcdefghijklmnopqrst", "API_KEY");
        assert!(pv.starts_with("sk-1"));
        assert!(pv.ends_with("qrst"));
        // 低熵口令：不给字符
        let pv2 = cred_preview("ServerPass123!", "SECRET");
        assert!(!pv2.contains("ServerPass"));
        assert!(plain_preview("13812345678").starts_with("1"));
        assert!(!plain_preview("13812345678").contains("13812345678"));
    }
}
