//! JSON 树管线：mask_tree / restore_tree + 保序 JSON + 重复键检测 +
//! 深度上限 + 字节级 splice（保前缀缓存）。
//!
//! 对齐 Python transparent.py 的 `_mask_tree` / `_restore_tree` / `_load_json_pairs`
//! / `_splice_mask` / `mask_body` 语义。

use serde_json::{Map, Value};

use super::engine::{restore_final, MaskCtx, RestoreStats};
use super::exemptions::{
    business_keys, protected_key_names, skip_numeric_keys, skip_subtree_keys, MASK_MAX_DEPTH,
    ROOT_WRAP_KEY,
};
use super::placeholder;
use super::session::SessionStore;

// ---------------------------------------------------------------------------
// 保序 JSON 解析 + 重复键检测
// ---------------------------------------------------------------------------

/// 解析结果：保序 Value + 是否有重复键（对齐 `_load_json_pairs`）。
pub struct ParsedBody {
    pub value: Value,
    pub has_dup_keys: bool,
}

/// 解析 JSON 并检测重复键。
///
/// serde_json 的 `preserve_order` 特性保留键序；重复键取后者（与 Python 一致）。
/// 重复键检测用轻量扫描：逐层检查对象内的重复键名。
pub fn load_json_pairs(text: &str) -> Option<ParsedBody> {
    let value: Value = serde_json::from_str(text).ok()?;
    let has_dup = detect_duplicate_keys(text);
    Some(ParsedBody {
        value,
        has_dup_keys: has_dup,
    })
}

/// 检测 JSON 文本中的重复键（任意层级）。
///
/// 实现：用 serde_json 的 StreamDeserializer 不行（会丢掉重复）。
/// 这里用一个轻量 tokenizer 扫描对象层级与键名集合。
pub fn detect_duplicate_keys(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut stack: Vec<Option<std::collections::HashSet<String>>> = Vec::new();
    let mut i = 0usize;
    let n = bytes.len();
    // 期望键名的位置：对象内、不是值位置
    let mut expecting_key: Vec<bool> = Vec::new();
    while i < n {
        match bytes[i] {
            b'{' => {
                stack.push(Some(std::collections::HashSet::new()));
                expecting_key.push(true);
                i += 1;
            }
            b'[' => {
                stack.push(None);
                expecting_key.push(false);
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                expecting_key.pop();
                i += 1;
                // 值结束后：回到「期待逗号或 }」
                if let Some(last) = expecting_key.last_mut() {
                    if *last {
                        // 保持
                    }
                }
            }
            b'"' => {
                // 读字符串
                let (s, ni) = read_json_string(bytes, i);
                i = ni;
                // 判断是键还是值：若当前在对象内且处于期待键的位置，且下一个非空白字符是 ':'
                let mut j = i;
                while j < n && (bytes[j] as char).is_whitespace() {
                    j += 1;
                }
                let is_key = j < n && bytes[j] == b':';
                if is_key {
                    if let Some(Some(set)) = stack.last_mut() {
                        if !set.insert(s) {
                            return true;
                        }
                        // 键读完，进入值位置
                        if let Some(last) = expecting_key.last_mut() {
                            *last = false;
                        }
                    }
                }
            }
            b',' => {
                // 回到期待键（仅对象）
                if let Some(last) = expecting_key.last_mut() {
                    if stack.last().map(|s| s.is_some()).unwrap_or(false) {
                        *last = true;
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    false
}

/// 读取一个 JSON 字符串字面量（返回内容 + 结束位置），支持转义。
fn read_json_string(bytes: &[u8], start: usize) -> (String, usize) {
    let mut out = String::new();
    let mut i = start + 1;
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b'"' => {
                i += 1;
                break;
            }
            b'\\' if i + 1 < n => {
                let esc = bytes[i + 1];
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'u' if i + 5 < n => {
                        let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).unwrap_or("");
                        if let Ok(cp) = u32::from_str_radix(hex, 16) {
                            if let Some(c) = char::from_u32(cp) {
                                out.push(c);
                            }
                        }
                        i += 6;
                        continue;
                    }
                    other => out.push(other as char),
                }
                i += 2;
            }
            _ => {
                // 按 UTF-8 边界推进
                let ch_len = utf8_len(bytes[i]);
                if let Ok(s) = std::str::from_utf8(&bytes[i..(i + ch_len).min(n)]) {
                    out.push_str(s);
                }
                i += ch_len;
            }
        }
    }
    (out, i)
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

// ---------------------------------------------------------------------------
// mask_tree（对齐 Python `_mask_tree` / `_leaf_exempt`）
// ---------------------------------------------------------------------------

/// 递归脱敏 JSON 树。`flag` 记录是否真的改写过。
pub fn mask_tree(
    obj: &Value,
    ctx: &MaskCtx<'_>,
    key: Option<&str>,
    parent: Option<&str>,
    path: &mut Vec<String>,
    depth: usize,
    changed: &mut bool,
) -> Result<Value, String> {
    if depth > MASK_MAX_DEPTH {
        return Err("json_depth_exceeded".into());
    }
    // 业务区判定：路径里是否出现业务区键（沿用 Python `any(k in _MASK_BUSINESS_KEYS ...)`）
    let in_business = path.iter().any(|k| business_keys().contains(k.as_str()));
    match obj {
        Value::String(s) => {
            if super::exemptions::leaf_exempt(key, parent, in_business) {
                return Ok(obj.clone());
            }
            let out = ctx.mask(s);
            if &out != s {
                *changed = true;
            }
            Ok(Value::String(out))
        }
        Value::Bool(_) | Value::Null => Ok(obj.clone()),
        Value::Number(n) => {
            // 数值型协议字段豁免；业务区内的数值照常扫描
            let exempt_key = key
                .map(|k| skip_numeric_keys().contains(k))
                .unwrap_or(false);
            if exempt_key || super::exemptions::leaf_exempt(key, parent, in_business) {
                return Ok(obj.clone());
            }
            let s = if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                format!("{f}")
            } else {
                return Ok(obj.clone());
            };
            let out = ctx.mask(&s);
            if out != s {
                *changed = true;
                Ok(Value::String(out))
            } else {
                Ok(obj.clone())
            }
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(mask_tree(v, ctx, key, parent, path, depth + 1, changed)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            // 协议元数据对象整棵跳过
            if !in_business
                && key
                    .map(|k| skip_subtree_keys().contains(k))
                    .unwrap_or(false)
            {
                return Ok(obj.clone());
            }
            let mut out = Map::new();
            for (k, v) in map {
                // 键名脱敏（结构键白名单外一律扫描）
                let mut new_key = k.clone();
                if !protected_key_names().contains(k.as_str()) {
                    let masked_key = ctx.mask(k);
                    if masked_key != *k {
                        new_key = masked_key;
                        *changed = true;
                    }
                }
                // path 推进用**原键**（业务区判定必须看客户端真实键名）
                // 用可变栈 push/pop，避免每个树节点克隆一份 Vec<String>
                // （长会话每轮上千条消息时，这是最主要的分配来源）。
                path.push(k.clone());
                let masked_v = mask_tree(v, ctx, Some(k), key, path, depth + 1, changed);
                path.pop();
                out.insert(new_key, masked_v?);
            }
            Ok(Value::Object(out))
        }
    }
}

// ---------------------------------------------------------------------------
// restore_tree（对齐 Python `_restore_tree`）
// ---------------------------------------------------------------------------

/// 递归还原 JSON 树。返回 (还原后的值, 统计)。
pub fn restore_tree(
    obj: &Value,
    sid: &str,
    store: &SessionStore,
    stats: &mut RestoreStats,
    depth: usize,
) -> Value {
    if depth > super::exemptions::RESTORE_MAX_DEPTH {
        stats.unresolved += 1;
        return obj.clone();
    }
    match obj {
        Value::String(s) => {
            // JSON 字符串字段（tool 参数）需转义还原
            let escape = false; // 由调用方按 key 判定后传入（见 restore_tree_keyed）
            let out = restore_final(s, sid, escape, store, stats);
            Value::String(out)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| restore_tree(v, sid, store, stats, depth + 1))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let escape = super::exemptions::json_str_keys().contains(k.as_str());
                let restored = match v {
                    Value::String(s) => Value::String(restore_final(s, sid, escape, store, stats)),
                    other => restore_tree(other, sid, store, stats, depth + 1),
                };
                out.insert(k.clone(), restored);
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// 字节级 splice（对齐 Python `_splice_mask`，保前缀缓存）
// ---------------------------------------------------------------------------

pub const SPLICE_MAX: usize = 8 << 20;
pub const SPLICE_MAX_FORMS: usize = 128;

/// 在原始字节上就地替换被脱敏的原文（保住客户端排版/转义风格）。
///
/// 调用方**必须**校验 `json.loads(结果) == masked_root`，不过就退回重序列化。
pub fn splice_mask(
    raw: &[u8],
    pairs: &std::collections::HashMap<String, String>,
) -> Option<Vec<u8>> {
    if pairs.is_empty() || raw.is_empty() || raw.len() > SPLICE_MAX {
        return None;
    }
    let mut table: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (orig, tok) in pairs {
        if orig.is_empty() || tok.is_empty() || orig == tok {
            continue;
        }
        for ascii_esc in [false, true] {
            let lit = json_string_literal(orig, ascii_esc);
            let repl = json_string_literal(tok, ascii_esc);
            if lit != repl {
                table.push((lit, repl));
            }
        }
    }
    if table.is_empty() || table.len() > SPLICE_MAX_FORMS {
        return None;
    }
    // 长 form 优先
    table.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    let patterns: Vec<Vec<u8>> = table.iter().map(|(k, _)| k.clone()).collect();
    let ac = aho_corasick::AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(&patterns)
        .ok()?;
    let mut out = Vec::with_capacity(raw.len() + 64);
    let mut last = 0usize;
    let mut hits = 0usize;
    for m in ac.find_iter(raw) {
        out.extend_from_slice(&raw[last..m.start()]);
        out.extend_from_slice(&table[m.pattern().as_usize()].1);
        last = m.end();
        hits += 1;
    }
    out.extend_from_slice(&raw[last..]);
    if hits == 0 {
        return None;
    }
    Some(out)
}

/// 生成 JSON 字符串内容形态（不含首尾引号，对齐 Python `json.dumps(x)[1:-1]`）。
fn json_string_literal(s: &str, ascii_esc: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            // 代理对（非 BMP）按 Python ensure_ascii 形态输出
            c if ascii_esc && (c as u32) > 0x7f => {
                let cp = c as u32;
                if cp > 0xFFFF {
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.extend_from_slice(format!("\\u{hi:04x}\\u{lo:04x}").as_bytes());
                } else {
                    out.extend_from_slice(format!("\\u{cp:04x}").as_bytes());
                }
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// mask_body（对齐 Python `mask_body`：三级回写策略）
// ---------------------------------------------------------------------------

/// 请求体脱敏结果。
pub struct MaskedBody {
    pub text: String,
    /// 是否真的改写了（零改写时保留原字节 → 保前缀缓存）
    pub changed: bool,
    /// 是否走了整棵重序列化（诊断）
    pub reserialized: bool,
    /// 首个差异字节位置（诊断；-1 = 未算）
    pub first_diff_byte: isize,
    /// body 形态标记（诊断）
    pub body_shape: Option<&'static str>,
}

pub const FIRST_DIFF_MAX: usize = 1 << 20;

/// 请求体脱敏（JSON 感知 + 三级回写）。
pub fn mask_body(raw: &[u8], ctx: &MaskCtx<'_>) -> Result<MaskedBody, String> {
    let text = String::from_utf8_lossy(raw).to_string();
    if text.is_empty() {
        return Ok(MaskedBody {
            text,
            changed: false,
            reserialized: false,
            first_diff_byte: -1,
            body_shape: None,
        });
    }
    let Some(parsed) = load_json_pairs(&text) else {
        // 非 JSON：整段当纯文本
        let out = ctx.mask(&text);
        let changed = out != text;
        ctx.seed_known(&out);
        return Ok(MaskedBody {
            text: out,
            changed,
            reserialized: false,
            first_diff_byte: -1,
            body_shape: None,
        });
    };
    let ParsedBody {
        value,
        has_dup_keys,
    } = parsed;
    let root_is_object = value.is_object();
    let mut body = if root_is_object {
        value.clone()
    } else {
        // 非对象根：包合成根键（发往上游前拆掉）
        let mut m = Map::new();
        m.insert(ROOT_WRAP_KEY.to_string(), value.clone());
        Value::Object(m)
    };

    let mut changed = false;
    let mut renamed = Map::new();
    let mut path: Vec<String> = Vec::new();
    let obj = body.as_object().ok_or("internal: body not object")?;
    for (k, v) in obj {
        let mut new_key = k.clone();
        if k != ROOT_WRAP_KEY && !protected_key_names().contains(k.as_str()) {
            let mk = ctx.mask(k);
            if mk != *k {
                new_key = mk;
                changed = true;
            }
        }
        let masked_v = mask_tree(v, ctx, Some(k), None, &mut path, 0, &mut changed)?;
        renamed.insert(new_key, masked_v);
    }
    body = Value::Object(renamed);
    let masked_root = if root_is_object {
        body.clone()
    } else {
        body.get(ROOT_WRAP_KEY).cloned().unwrap_or(Value::Null)
    };

    let body_shape = if !root_is_object {
        Some("non_object_root")
    } else {
        None
    };

    // 零改写：一个字节都不动
    if !changed && !has_dup_keys {
        ctx.seed_known(&text);
        return Ok(MaskedBody {
            text,
            changed: false,
            reserialized: false,
            first_diff_byte: -1,
            body_shape,
        });
    }

    // 1) 首选字节级 splice（重复键禁用：丢掉的键不在替换表里，等价校验会误判通过）
    let mut masked_raw: Option<String> = None;
    if !has_dup_keys {
        if let Some(fwd) = ctx.store.get(&ctx.sid).map(|s| s.fwd.clone()) {
            let pairs: std::collections::HashMap<String, String> =
                fwd.into_iter().filter(|(_, t)| !t.is_empty()).collect();
            if let Some(spliced) = splice_mask(raw, &pairs) {
                // 等价校验
                if let Ok(s) = String::from_utf8(spliced.clone()) {
                    if serde_json::from_str::<Value>(&s).ok().as_ref() == Some(&masked_root) {
                        masked_raw = Some(s);
                    }
                }
            }
        }
    }
    // 2) 退路：整棵重序列化（沿用客户端的 \u 转义策略）
    let reserialized = masked_raw.is_none();
    let out_text = match masked_raw {
        Some(s) => s,
        None => {
            let ascii = raw.windows(2).any(|w| w == b"\\u");
            serialize_compact(&masked_root, ascii)
        }
    };
    ctx.seed_known(&out_text);
    let first_diff = if out_text != text {
        first_diff_byte(text.as_bytes(), out_text.as_bytes())
    } else {
        -1
    };
    Ok(MaskedBody {
        text: out_text,
        changed: true,
        reserialized,
        first_diff_byte: first_diff,
        body_shape,
    })
}

/// 紧凑序列化（`separators=(",", ":")` + 可选 ASCII 转义）。
fn serialize_compact(v: &Value, ascii: bool) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    if ascii {
        // 把非 ASCII 转成 \uXXXX（对齐 Python ensure_ascii=True）
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if (c as u32) > 0x7f {
                let cp = c as u32;
                if cp > 0xFFFF {
                    let v2 = cp - 0x10000;
                    out.push_str(&format!(
                        "\\u{:04x}\\u{:04x}",
                        0xD800 + (v2 >> 10),
                        0xDC00 + (v2 & 0x3FF)
                    ));
                } else {
                    out.push_str(&format!("\\u{cp:04x}"));
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s
    }
}

/// 首个差异字节（诊断；超限返回 -1）。
pub fn first_diff_byte(a: &[u8], b: &[u8]) -> isize {
    if a.len() > FIRST_DIFF_MAX || b.len() > FIRST_DIFF_MAX {
        return -1;
    }
    let n = a.len().min(b.len());
    let mut i = 0;
    while i < n && a[i] == b[i] {
        i += 1;
    }
    i as isize
}

/// 从请求体提取 model（对齐 `_extract_model`）。
pub fn extract_model(body: &Value) -> String {
    body.get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// 响应侧 PII 扫描所需的占位符集合（对齐 `_seed_known` 语义的辅助）。
pub fn collect_placeholder_tokens(text: &str) -> Vec<String> {
    placeholder::placeholder_rx()
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::mask::engine::CustomWords;
    use serde_json::json;

    fn full_rules() -> Config {
        let mut cfg = Config::default();
        for k in crate::config::ALL_BUILTIN_RULES {
            cfg.mask.builtin_rules.insert(k.to_string(), true);
        }
        cfg
    }

    struct Ctx2 {
        cfg: Config,
        store: SessionStore,
        custom: CustomWords,
    }

    impl Ctx2 {
        fn new(words: &[(&str, &str)]) -> Self {
            let mut cfg = full_rules();
            for (w, l) in words {
                cfg.mask.custom_words.insert(w.to_string(), l.to_string());
            }
            let store = SessionStore::new();
            store.new_session("j");
            let custom = CustomWords::build(&cfg);
            Ctx2 { cfg, store, custom }
        }
        fn ctx(&self) -> MaskCtx<'_> {
            MaskCtx::new(&self.cfg, &self.store, "j".into(), &self.custom)
        }
        fn mask_body(&self, raw: &[u8]) -> MaskedBody {
            mask_body(raw, &self.ctx()).unwrap()
        }
    }

    #[test]
    fn duplicate_key_detection() {
        assert!(detect_duplicate_keys(r#"{"a":"1","a":"2"}"#));
        assert!(!detect_duplicate_keys(r#"{"a":"1","b":"2"}"#));
        assert!(detect_duplicate_keys(r#"{"o":{"x":1,"x":2}}"#));
        assert!(!detect_duplicate_keys(r#"[{"a":1},{"a":2}]"#));
        // 字符串里的 "a": 不算键
        assert!(!detect_duplicate_keys(r#"{"a":"x\": 1"}"#));
    }

    #[test]
    fn load_json_pairs_keeps_order() {
        let p = load_json_pairs(r#"{"z":1,"a":2}"#).unwrap();
        let keys: Vec<&String> = p.value.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["z", "a"], "保序");
    }

    #[test]
    fn mask_body_zero_rewrite_byte_identical() {
        let c = Ctx2::new(&[]);
        let raw = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"帮我看看代码"}],"stream":true}"#.as_bytes();
        let out = c.mask_body(raw);
        assert!(!out.changed, "无敏感内容必须零改写");
        assert_eq!(out.text.as_bytes(), raw, "逐字节一致（保前缀缓存）");
    }

    #[test]
    fn mask_body_zero_rewrite_preserves_unicode_escape() {
        let c = Ctx2::new(&[]);
        let raw = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"\u5e2e\u6211"}]}"#;
        let out = c.mask_body(raw);
        assert_eq!(out.text.as_bytes(), raw, "\\u 转义形态原样保留");
    }

    #[test]
    fn mask_body_splice_preserves_layout() {
        let c = Ctx2::new(&[("张三", "NAME")]);
        let raw =
            r#"{"model": "gpt-4o", "messages": [{"role": "user", "content": "我叫张三，请看看"}]}"#
                .as_bytes();
        let out = c.mask_body(raw);
        assert!(out.changed);
        assert!(!out.reserialized, "应走字节级 splice");
        assert!(
            out.text.contains(r#"": ""#),
            "客户端排版（冒号后空格）必须保留"
        );
        assert!(!out.text.contains("张三"), "原文脱敏");
        assert!(out.text.contains("{{NAME_"), "签发占位符");
        // 首个差异位正好在被脱敏的值上
        let anchor = raw
            .windows("张三".len())
            .position(|w| w == "张三".as_bytes())
            .unwrap();
        assert_eq!(
            out.first_diff_byte as usize, anchor,
            "只允许被脱敏的那一段变化"
        );
    }

    #[test]
    fn mask_body_numeric_scalar_masked() {
        let c = Ctx2::new(&[]);
        // 数值型手机号必须脱敏（B2）
        let raw = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"phone":13812345678}"#;
        let out = c.mask_body(raw);
        assert!(out.changed);
        assert!(!out.text.contains("13812345678"), "数值型手机号必须脱敏");
        let v: Value = serde_json::from_str(&out.text).unwrap();
        assert!(v["phone"].is_string(), "脱敏后变占位符字符串");
    }

    #[test]
    fn mask_body_pii_as_key_masked() {
        let c = Ctx2::new(&[]);
        let raw = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"13812345678":"备注"}"#.as_bytes();
        let out = c.mask_body(raw);
        assert!(!out.text.contains("13812345678"), "键名脱敏（B2）");
        let v: Value = serde_json::from_str(&out.text).unwrap();
        assert!(v
            .as_object()
            .unwrap()
            .keys()
            .any(|k| k.contains("{{PHONE_")));
    }

    #[test]
    fn mask_body_duplicate_key_forces_reserialize() {
        let c = Ctx2::new(&[]);
        let raw = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"note":"13812345678","note":"safe"}"#;
        let out = c.mask_body(raw);
        assert!(out.changed);
        assert!(!out.text.contains("13812345678"), "被覆盖的明文不得放行");
    }

    #[test]
    fn mask_body_protocol_fields_untouched() {
        let c = Ctx2::new(&[]);
        let raw = br#"{"model":"gpt-4o","max_tokens":1024,"temperature":0.7,"n":1,"seed":42,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
        let out = c.mask_body(raw);
        let v: Value = serde_json::from_str(&out.text).unwrap();
        assert_eq!(v["model"], "gpt-4o");
        assert_eq!(v["max_tokens"], 1024);
        assert_eq!(v["temperature"], 0.7);
        assert_eq!(v["n"], 1);
        assert_eq!(v["seed"], 42);
        assert_eq!(v["messages"][0]["role"], "user");
    }

    #[test]
    fn mask_body_business_zone_scanned() {
        let c = Ctx2::new(&[("张三", "NAME")]);
        let raw = r#"{"messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"name\":\"张三\",\"phone\":\"13812345678\"}"}}]}]}"#.as_bytes();
        let out = c.mask_body(raw);
        let v: Value = serde_json::from_str(&out.text).unwrap();
        let args = v["messages"][1]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(!args.contains("张三"), "工具参数业务区必须脱敏");
        assert!(!args.contains("13812345678"));
        // 协议字段保留
        assert_eq!(v["messages"][1]["tool_calls"][0]["id"], "call_1");
        assert_eq!(
            v["messages"][1]["tool_calls"][0]["function"]["name"],
            "lookup"
        );
    }

    #[test]
    fn mask_body_cache_control_untouched() {
        let c = Ctx2::new(&[("ephemeral", "TERM")]);
        let raw = r#"{"system":[{"type":"text","text":"我的手机号13812345678","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}"#.as_bytes();
        let out = c.mask_body(raw);
        let v: Value = serde_json::from_str(&out.text).unwrap();
        assert_eq!(
            v["system"][0]["cache_control"]["type"], "ephemeral",
            "协议元数据整棵跳过"
        );
        assert!(
            !v["system"][0]["text"]
                .as_str()
                .unwrap()
                .contains("13812345678"),
            "同一块正文照常脱敏"
        );
    }

    #[test]
    fn mask_body_response_format_schema_scanned() {
        let c = Ctx2::new(&[("张三", "NAME")]);
        let raw = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_schema","json_schema":{"name":"r","schema":{"type":"object","properties":{"owner":{"enum":["张三"]}}}}}}"#.as_bytes();
        let out = c.mask_body(raw);
        assert!(
            !out.text.contains("张三"),
            "response_format 内业务取值仍须脱敏（反向锁）"
        );
    }

    #[test]
    fn mask_body_non_object_root() {
        let c = Ctx2::new(&[]);
        let raw = r#"[{"role":"user","content":"电话13812345678"}]"#.as_bytes();
        let out = c.mask_body(raw);
        assert!(!out.text.contains("13812345678"), "列表根照常脱敏");
        assert!(!out.text.contains(ROOT_WRAP_KEY), "包装键不得出现在输出");
        let v: Value = serde_json::from_str(&out.text).unwrap();
        assert!(v.is_array(), "输出仍是数组根");
    }

    #[test]
    fn mask_body_deep_json_fails() {
        let c = Ctx2::new(&[]);
        // 构造 30 层嵌套
        let mut node = json!({"v": "机密原文"});
        for _ in 0..30 {
            node = json!({"n": node});
        }
        let body = json!({"messages": [{"role": "user", "content": node}]});
        let raw = serde_json::to_vec(&body).unwrap();
        let r = mask_body(&raw, &c.ctx());
        assert!(r.is_err(), "深度超限必须报错（fail-closed 由调用方 503）");
    }

    #[test]
    fn restore_tree_masks_and_restores() {
        let c = Ctx2::new(&[("张三", "NAME")]);
        let raw =
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"客户张三"}]}"#.as_bytes();
        let masked = c.mask_body(raw);
        let v: Value = serde_json::from_str(&masked.text).unwrap();
        let mut stats = RestoreStats::default();
        let restored = restore_tree(&v, "j", &c.store, &mut stats, 0);
        assert_eq!(restored["messages"][0]["content"], "客户张三");
        assert!(stats.restored > 0);
    }

    #[test]
    fn restore_tree_escapes_tool_arguments() {
        let c = Ctx2::new(&[]);
        // 手工登记含引号原文
        {
            let taken = crate::mask::session::token_taken();
            let mut s = c.store.get_mut("j").unwrap();
            c.store.remember(&mut s, "张\"三", "TERM", &taken);
        }
        let token = c.store.get("j").unwrap().fwd["张\"三"].clone();
        let args = json!({"name": token}).to_string();
        let v = json!({"tool_calls": [{"function": {"arguments": args}}]});
        let mut stats = RestoreStats::default();
        let restored = restore_tree(&v, "j", &c.store, &mut stats, 0);
        let out_args = restored["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let parsed: Value = serde_json::from_str(out_args).unwrap();
        assert_eq!(parsed["name"], "张\"三", "JSON 字符串字段还原必须转义");
    }

    #[test]
    fn splice_returns_none_when_no_hits() {
        let mut pairs = std::collections::HashMap::new();
        pairs.insert("不存在".to_string(), "{{TERM_bcdfgh}}".to_string());
        assert!(splice_mask(b"{\"a\":1}", &pairs).is_none());
    }

    #[test]
    fn serialize_compact_ascii_matches_python() {
        let v = json!({"content": "张三"});
        let s = serialize_compact(&v, true);
        assert!(s.contains("\\u5f20"), "ensure_ascii=True 形态");
        let s2 = serialize_compact(&v, false);
        assert!(s2.contains("张三"), "ensure_ascii=False 形态");
    }
}
