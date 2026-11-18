//! util 模块聚合（http_client 移至 upstream 模块）。

/// 从 `idx` 向前回退到最近的 UTF-8 字符边界。
///
/// `idx` 超过长度时返回长度。用于任何“按字节上限截断”的入口，
/// 避免 `&s[..N]` 恰好切在多字节字符中间导致 panic。
pub fn floor_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// 返回不超过 `max_bytes` 且不切开 UTF-8 字符的前缀。
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    &s[..floor_boundary(s, max_bytes)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_is_utf8_safe() {
        let s = "a密b😀c"; // 1 + 3 + 1 + 4 + 1
        for n in 0..=s.len() {
            let cut = floor_boundary(s, n);
            assert!(s.is_char_boundary(cut));
            assert!(cut <= n);
        }
        assert_eq!(truncate_utf8(s, 2), "a");
        assert_eq!(truncate_utf8(s, 4), "a密");
        assert_eq!(truncate_utf8(s, 5), "a密b");
        assert_eq!(truncate_utf8(s, 8), "a密b");
        assert_eq!(truncate_utf8(s, 999), s);
    }

    #[test]
    fn empty_and_exact_boundary() {
        assert_eq!(truncate_utf8("", 10), "");
        assert_eq!(truncate_utf8("abc", 3), "abc");
        assert_eq!(truncate_utf8("abc", 0), "");
    }
}
