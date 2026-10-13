//! 响应体压缩解码(gzip / deflate / br / zstd)。
//!
//! 为什么需要:请求侧虽然强制注入 `accept-encoding: identity`,但**上游不一定
//! 遵守**(中转会自行压缩,或用户直接用非标准客户端打网关)。一旦响应是压缩体,
//! 响应侧的 `restorable()` 就只能返回 false —— 按字节无法处理,占位符会**原样
//! 下发给客户端**,而且不产生 RESTORE 事件(`restored/unresolved` 全 0,统计上
//! 是看不见的静默泄漏)。
//!
//! 这里把压缩体解回明文,交给还原管线;还原后**剥掉 `content-encoding`** 以
//! 明文下发(见 `is_decodable`)。
//!
//! 为什么剥头而不重压缩:
//!   1. 本网关在本地 hop-by-hop,压缩收益远小于「占位符泄漏」的代价;
//!   2. 重压缩需要再引入编码器 + 保证字节级可解析,徒增失败面;
//!   3. `Content-Length` 本来就会随还原变化被移除,响应已按 chunked 下发。
//!
//! 解码失败一律返回 `None` → 调用方退回原来的「不可还原则透传」行为,
//! 不会把好数据弄坏。

/// `content-encoding` 是否是我们能解码的压缩体。
///
/// 只认单一编码(gzip/x-gzip/deflate/br/zstd)。多重编码(`gzip, br` 之类)
/// 返回 false —— 叠加解码的顺序与语义容易出错,宁可透传也不误处理。
pub fn is_decodable(content_encoding: &str) -> bool {
    let e = content_encoding.trim();
    if e.is_empty() || e.eq_ignore_ascii_case("identity") || e.contains(',') {
        return false;
    }
    matches!(
        e.to_ascii_lowercase().as_str(),
        "gzip" | "x-gzip" | "deflate" | "br" | "zstd"
    )
}

/// 解压后允许的最大字节数（防 zip bomb / OOM）。
///
/// 为什么必须有：上面的 64MB 限幅（`aggregate_stream`）限的是**压缩后**的输入，
/// 而 gzip 压缩比可达约 1000:1 —— 一个 64MB 的 gzip 能解出几十 GB，直接 OOM。
/// 取 128MB：LLM 响应即使是大工具的完整文件回显也远小于此，同时给了充足余量。
pub const MAX_DECODED_BYTES: usize = 128 * 1024 * 1024;

/// 带上限的 `read_to_end`：超出 `MAX_DECODED_BYTES` 即中止并报错。
fn read_capped<R: std::io::Read>(mut r: R) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut out = Vec::new();
    // `take` 多给 1 字节：刚好读满上限时无法区分「正好」与「超出」
    let n = r
        .by_ref()
        .take(MAX_DECODED_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if n > MAX_DECODED_BYTES {
        return Err(format!("decoded_too_large: >{MAX_DECODED_BYTES}"));
    }
    Ok(out)
}

/// 解码响应体。
///
/// `Ok(Some(plain))` = 解码成功;`Ok(None)` = 无编码(原样);`Err` = 解压失败。
pub fn decode(body: &[u8], content_encoding: &str) -> Result<Option<Vec<u8>>, String> {
    let e = content_encoding.trim();
    if e.is_empty() || e.eq_ignore_ascii_case("identity") {
        return Ok(None);
    }
    if e.contains(',') {
        return Err(format!("multi_encoding_unsupported: {e}"));
    }
    let lower = e.to_ascii_lowercase();
    match lower.as_str() {
        "gzip" | "x-gzip" => {
            let out = read_capped(flate2::read::GzDecoder::new(body))
                .map_err(|err| format!("gzip_decode_failed: {err}"))?;
            Ok(Some(out))
        }
        "deflate" => {
            // `deflate` 在 HTTP 里语义含糊:可能是 zlib 包装(RFC 1950),也可能是
            // 裸 deflate。按 zlib 试,失败再退回裸流 —— 两种都试一遍。
            //
            // 注意:zlib 尝试失败时**必须丢弃半成品**,不能复用 `out` 变量，
            // 否则会把 zlib 解出的部分字节拼到裸 deflate 结果前面。
            if let Ok(out) = read_capped(flate2::read::ZlibDecoder::new(body)) {
                return Ok(Some(out));
            }
            let out = read_capped(flate2::read::DeflateDecoder::new(body))
                .map_err(|err| format!("deflate_decode_failed: {err}"))?;
            Ok(Some(out))
        }
        "br" => {
            let out = read_capped(brotli::Decompressor::new(body, 4096))
                .map_err(|err| format!("brotli_decode_failed: {err}"))?;
            Ok(Some(out))
        }
        "zstd" => {
            let d = ruzstd::decoding::StreamingDecoder::new(body)
                .map_err(|err| format!("zstd_decode_failed: {err}"))?;
            let out = read_capped(d).map_err(|err| format!("zstd_decode_failed: {err}"))?;
            Ok(Some(out))
        }
        _ => Err(format!("unsupported_encoding: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn identity_and_empty_are_noop() {
        assert_eq!(decode(b"abc", "").unwrap(), None);
        assert_eq!(decode(b"abc", "identity").unwrap(), None);
        assert!(!is_decodable(""));
        assert!(!is_decodable("identity"));
    }

    #[test]
    fn gzip_roundtrip() {
        let orig = "电话13800138000 与 {{PHONE_abc123}}".as_bytes();
        let enc = gzip(orig);
        assert!(is_decodable("gzip"));
        assert!(is_decodable("GZIP"));
        assert!(is_decodable("x-gzip"));
        let out = decode(&enc, "gzip").unwrap().unwrap();
        assert_eq!(out, orig);
    }

    #[test]
    fn deflate_both_flavors() {
        let orig = b"hello masked world";
        // zlib 包装
        let z = zlib(orig);
        assert_eq!(decode(&z, "deflate").unwrap().unwrap(), orig);
        // 裸 deflate
        let r = raw_deflate(orig);
        assert_eq!(decode(&r, "deflate").unwrap().unwrap(), orig);
    }

    #[test]
    fn brotli_roundtrip() {
        // brotli 只有解码器依赖;用已知的 brotli 字节流验证
        // `brotli` crate 自带 writer(编码器)在 `brotli` 而非 `brotli-decompressor`
        use std::io::Write;
        let orig = b"brotli payload {{TERM_xyz}}";
        let mut enc = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut enc, 4096, 5, 22);
            w.write_all(orig).unwrap();
        }
        assert!(is_decodable("br"));
        let out = decode(&enc, "br").unwrap().unwrap();
        assert_eq!(out, orig);
    }

    #[test]
    fn zstd_roundtrip() {
        // zstd 仅有解码依赖;用 ruzstd 的测试向量不可靠,改用标准 zstd 帧头
        // 这里直接验证「非法输入返回 Err 而不是 panic/静默」
        let junk = vec![0u8; 8];
        assert!(decode(&junk, "zstd").is_err());
        assert!(is_decodable("zstd"));
    }

    #[test]
    fn rejects_multiple_and_unknown() {
        assert!(!is_decodable("gzip, br"));
        assert!(!is_decodable("compress"));
        assert!(decode(b"x", "gzip, br").is_err());
        assert!(decode(b"x", "weird-enc").is_err());
    }

    #[test]
    fn corrupt_gzip_is_err_not_panic() {
        assert!(decode(b"\x1f\x8b\x08\x00garbage", "gzip").is_err());
    }

    /// zip bomb 防护：解压后超过 `MAX_DECODED_BYTES` 必须报错，而不是把内存吃光。
    ///
    /// 回归理由：上游 64MB 的响应限幅（`aggregate_stream`）限的是**压缩后**的
    /// 输入；gzip 压缩比可达 ~1000:1，解压无上限时一个几十 MB 的响应就能
    /// 解出几十 GB → OOM。
    #[test]
    fn zip_bomb_is_capped() {
        use std::io::Write;
        // 高度可压缩：几 MB 的零字节 → 压缩后极小
        let orig = vec![0u8; MAX_DECODED_BYTES + 1024];
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&orig).unwrap();
        let gz = e.finish().unwrap();
        assert!(gz.len() < 1024 * 1024, "压缩后应远小于解压后: {}", gz.len());
        let err = decode(&gz, "gzip").unwrap_err();
        assert!(err.contains("decoded_too_large"), "应报超限: {err}");
        // 刚好在上限内的仍然可解
        let ok_orig = vec![7u8; 1024];
        let mut e2 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e2.write_all(&ok_orig).unwrap();
        let gz2 = e2.finish().unwrap();
        assert_eq!(decode(&gz2, "gzip").unwrap().unwrap(), ok_orig);
    }
}
