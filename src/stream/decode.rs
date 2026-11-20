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

/// `content-encoding` 的规范化形式：去首尾空白 + ASCII 小写。
///
/// 为什么必须共用：响应侧 `restorable()` 与解码侧曾各写一套判断 —— 解码把
/// `IDENTITY` 视为「无编码」，还原却按精确字符串比较把小写 `identity` 当唯一
/// 无编码形式。上游回 `Content-Encoding: IDENTITY` 时，两者结论相反：不解码、
/// 也不还原，占位符原样下发且不产生 RESTORE 事件（静默泄漏）。
pub fn normalize_encoding(content_encoding: &str) -> String {
    content_encoding.trim().to_ascii_lowercase()
}

/// 规范化后是否等价于「无编码」。
pub fn is_identity(content_encoding: &str) -> bool {
    let e = normalize_encoding(content_encoding);
    e.is_empty() || e == "identity"
}

/// `content-encoding` 是否是我们能解码的压缩体。
///
/// 只认单一编码(gzip/x-gzip/deflate/br/zstd)。多重编码(`gzip, br` 之类)
/// 返回 false —— 叠加解码的顺序与语义容易出错,宁可透传也不误处理。
pub fn is_decodable(content_encoding: &str) -> bool {
    let e = normalize_encoding(content_encoding);
    if e.is_empty() || e == "identity" || e.contains(',') {
        return false;
    }
    matches!(e.as_str(), "gzip" | "x-gzip" | "deflate" | "br" | "zstd")
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

/// 请求体解压上限。
///
/// 比响应侧更保守：`server.max_body_bytes` 默认 32MiB，请求体在 HTTP 语义上
/// 是「用户输入」，不该允许解出几百 MB。128MiB 与响应侧同量级，但请求侧
/// 单独留常量便于按需调整。
pub const MAX_REQUEST_DECODED_BYTES: usize = 128 * 1024 * 1024;

/// 请求解压上限的哨兵前缀：调用方据此把它映射成 413（而不是 415）。
pub const DECODE_TOO_LARGE_PREFIX: &str = "decoded_too_large:";

/// 解压请求体（客户端 → 网关方向）。
///
/// 为什么必须有：请求侧此前只按 `content-type` 判断是否走 JSON 管线，**从不看
/// `content-encoding`**。压缩 JSON 无法当普通文本解析，于是 `fail_closed=true`
/// 时合法 gzip 请求被拒成 400，`fail_closed=false` 时压缩体被原样转发 ——
/// 里面所有 PII 从未经过脱敏。
///
/// 返回 `Ok(None)` 表示无需解压（无编码 / identity）；`Err` 表示编码不支持、
/// 多重编码或解压失败，调用方必须按未脱敏体处理，不能透传。
/// `max_out`：调用方的业务上限（通常 `server.max_body_bytes`）。
///
/// 必须由调用方传入而不是只用常量：解压发生在内存里，若只按 128MiB 常量封顶、
/// 事后才比较 `max_body`，一个约 128KiB 的高压缩比请求就能让单请求分配 128MiB
/// （默认 `max_body` 32MiB 的 4 倍），并发时可直接打满内存。
pub fn decode_request(
    body: &[u8],
    content_encoding: &str,
    max_out: usize,
) -> Result<Option<Vec<u8>>, String> {
    if is_identity(content_encoding) {
        return Ok(None);
    }
    let cap = max_out.clamp(1, MAX_REQUEST_DECODED_BYTES);
    let capped = request_decode_capped(body, content_encoding, cap)?;
    Ok(Some(capped))
}

/// 带上限的实际解压；与响应侧共用算法但用请求侧上限。
fn request_decode_capped(
    body: &[u8],
    content_encoding: &str,
    cap: usize,
) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let e = normalize_encoding(content_encoding);
    if e.contains(',') {
        return Err(format!("multi_encoding_unsupported: {e}"));
    }
    let read = |mut r: Box<dyn std::io::Read>| -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let n = r
            .by_ref()
            .take(cap as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|err| err.to_string())?;
        if n > cap {
            return Err(format!("{DECODE_TOO_LARGE_PREFIX} >{cap}"));
        }
        Ok(out)
    };
    // 超出上限的错误必须原样保留哨兵前缀，不能被 `gzip_decode_failed:` 包掉 ——
    // 调用方靠前缀区分 413（超限）与 415（编码不支持/损坏）。
    fn keep_sentinel(kind: &str, err: String) -> String {
        if err.starts_with(DECODE_TOO_LARGE_PREFIX) {
            err
        } else {
            format!("{kind}: {err}")
        }
    }
    match e.as_str() {
        // 必须用 `MultiGzDecoder`：`GzDecoder` 只解第一个成员，多成员 gzip
        // 会被静默截断（合法 JSON 变成半截，fail-closed 反而拒绝合法请求）。
        "gzip" | "x-gzip" => read(Box::new(flate2::read::MultiGzDecoder::new(body)))
            .map_err(|err| keep_sentinel("gzip_decode_failed", err)),
        "deflate" => {
            // zlib 包装 vs 裸 deflate：先试 zlib，失败再试裸流。
            // **超限错误必须原样返回**：`if let Ok` 会把它吞掉，转去按裸
            // deflate 重试，最终变成「损坏流」→ 入口按 415 而非 413 处理。
            match read(Box::new(flate2::read::ZlibDecoder::new(body))) {
                Ok(out) => return Ok(out),
                Err(err) if err.starts_with(DECODE_TOO_LARGE_PREFIX) => return Err(err),
                Err(_) => {}
            }
            read(Box::new(flate2::read::DeflateDecoder::new(body)))
                .map_err(|err| keep_sentinel("deflate_decode_failed", err))
        }
        "br" => read(Box::new(brotli::Decompressor::new(body, 4096)))
            .map_err(|err| keep_sentinel("brotli_decode_failed", err)),
        "zstd" => {
            let d = ruzstd::decoding::StreamingDecoder::new(body)
                .map_err(|err| format!("zstd_decode_failed: {err}"))?;
            read(Box::new(d)).map_err(|err| keep_sentinel("zstd_decode_failed", err))
        }
        _ => Err(format!("unsupported_encoding: {e}")),
    }
}

/// 解码响应体。
///
/// `Ok(Some(plain))` = 解码成功;`Ok(None)` = 无编码(原样);`Err` = 解压失败。
pub fn decode(body: &[u8], content_encoding: &str) -> Result<Option<Vec<u8>>, String> {
    let e = normalize_encoding(content_encoding);
    if e.is_empty() || e == "identity" {
        return Ok(None);
    }
    if e.contains(',') {
        return Err(format!("multi_encoding_unsupported: {e}"));
    }
    match e.as_str() {
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

/// 可流式解码的编码。br/zstd 仍走整包（增量 API 复杂，先保证 gzip/deflate）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamDecodeKind {
    Gzip,
    /// Content-Encoding: deflate —— 可能是 zlib 包装，也可能是裸 deflate，
    /// 收到前两字节后按 RFC1950 头判定。
    Deflate,
}

pub fn streaming_decodable(content_encoding: &str) -> Option<StreamDecodeKind> {
    match content_encoding.trim().to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => Some(StreamDecodeKind::Gzip),
        // deflate 两种 flavor 都真实存在；延迟到收到前两字节再判定。
        "deflate" => Some(StreamDecodeKind::Deflate),
        _ => None,
    }
}

/// 增量解压器：逐 chunk 解出明文，供 SSE 流式还原。
///
/// gzip：手动剥离 10 字节头与可选字段后用 raw deflate 增量解码
/// （miniz_oxide 后端没有 gzip 构造器）；zlib：直接 zlib 头。
/// 解压失败无法回退回「原样透传」（已经 yield 过明文），调用方只能中断流并
/// 记日志；这是流式化的固有代价，gzip 流损坏本就极罕见。
pub struct StreamDecoder {
    kind: StreamDecodeKind,
    /// None = gzip/deflate 头还没收全。
    d: Option<flate2::Decompress>,
    header: Vec<u8>,
    done: bool,
    /// 成员结束后的已见字节数（gzip trailer 最多 8 字节）。
    post_done: usize,
}

impl StreamDecoder {
    pub fn new(kind: StreamDecodeKind) -> Self {
        Self {
            kind,
            d: None,
            header: Vec::new(),
            done: false,
            post_done: 0,
        }
    }

    /// 喂入压缩字节，把可解出的明文追加到 `out`。
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        if self.done {
            self.post_done += input.len();
            if self.post_done > 8 {
                return Err("multi_member_or_trailing_data_unsupported".into());
            }
            return Ok(());
        }
        if self.d.is_none() {
            self.header.extend_from_slice(input);
            match self.kind {
                StreamDecodeKind::Gzip => {
                    let Some(hlen) = parse_gzip_header(&self.header)? else {
                        if self.header.len() > 64 * 1024 {
                            return Err("gzip_header_too_large".into());
                        }
                        return Ok(());
                    };
                    let rest = self.header.split_off(hlen);
                    self.d = Some(flate2::Decompress::new(false));
                    let d = self.d.as_mut().expect("just set");
                    let consumed = feed_deflate(d, &rest, out, &mut self.done)?;
                    return self.check_trailing(&rest[consumed..]);
                }
                StreamDecodeKind::Deflate => {
                    if self.header.len() < 2 {
                        return Ok(());
                    }
                    // RFC1950 zlib 头：CM=8 且 (CMF<<8|FLG) % 31 == 0
                    let zlib = (self.header[0] & 0x0f) == 8
                        && ((self.header[0] as u16) << 8 | self.header[1] as u16)
                            .is_multiple_of(31);
                    self.d = Some(flate2::Decompress::new(zlib));
                    let rest = std::mem::take(&mut self.header);
                    let d = self.d.as_mut().expect("just set");
                    let consumed = feed_deflate(d, &rest, out, &mut self.done)?;
                    return self.check_trailing(&rest[consumed..]);
                }
            }
        }
        let d = self.d.as_mut().expect("gzip header initialized");
        let consumed = feed_deflate(d, input, out, &mut self.done)?;
        self.check_trailing(&input[consumed..])
    }

    /// 成员结束后检查是否有未消费字节。
    ///
    /// gzip 的 raw deflate 在 StreamEnd 时剩下 8 字节 trailer；超过 8 字节是
    /// 串联多成员（RFC1952 允许），当前实现不支持。**明确报错**，避免静默
    /// 丢弃第二个成员（调用方会 warn 并截断，至少可见）；不是静默成功。
    fn check_trailing(&self, rest: &[u8]) -> Result<(), String> {
        if !self.done {
            return Ok(());
        }
        let allowed = match self.kind {
            StreamDecodeKind::Gzip => 8,
            StreamDecodeKind::Deflate => 0,
        };
        if rest.len() > allowed {
            return Err("multi_member_or_trailing_data_unsupported".into());
        }
        Ok(())
    }

    /// 流结束：刷出尾部并校验完整性。
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), String> {
        use flate2::{FlushDecompress, Status};
        if self.done {
            return Ok(());
        }
        let Some(d) = self.d.as_mut() else {
            return Err("gzip_header_incomplete".into());
        };
        let mut buf = [0u8; 64 * 1024];
        loop {
            let out_before = d.total_out();
            let status = d
                .decompress(&[], &mut buf, FlushDecompress::Finish)
                .map_err(|e| format!("decode_error: {e}"))?;
            let produced = (d.total_out() - out_before) as usize;
            if d.total_out() as usize > MAX_DECODED_BYTES {
                return Err(format!("decoded_too_large: >{MAX_DECODED_BYTES}"));
            }
            out.extend_from_slice(&buf[..produced]);
            if matches!(status, Status::StreamEnd) {
                self.done = true;
                return Ok(());
            }
            if produced == 0 {
                return Err("decode_truncated".into());
            }
        }
    }
}

/// 解析 gzip 头（含 FEXTRA/FNAME/FCOMMENT/FHCRC），返回头长度。
fn parse_gzip_header(b: &[u8]) -> Result<Option<usize>, String> {
    if b.len() < 10 {
        return Ok(None);
    }
    if b[0] != 0x1f || b[1] != 0x8b || b[2] != 8 {
        return Err("gzip_bad_header".into());
    }
    let flg = b[3];
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        if b.len() < pos + 2 {
            return Ok(None);
        }
        let xlen = u16::from_le_bytes([b[pos], b[pos + 1]]) as usize;
        pos += 2 + xlen;
        if b.len() < pos {
            return Ok(None);
        }
    }
    for bit in [0x08u8, 0x10u8] {
        // FNAME / FCOMMENT：零结尾
        if flg & bit != 0 {
            loop {
                if pos >= b.len() {
                    return Ok(None);
                }
                let c = b[pos];
                pos += 1;
                if c == 0 {
                    break;
                }
            }
        }
    }
    if flg & 0x02 != 0 {
        // FHCRC
        pos += 2;
        if b.len() < pos {
            return Ok(None);
        }
    }
    Ok(Some(pos))
}

/// raw deflate 增量喂入，返回解出的明文。
fn feed_deflate(
    d: &mut flate2::Decompress,
    mut input: &[u8],
    out: &mut Vec<u8>,
    done: &mut bool,
) -> Result<usize, String> {
    use flate2::{FlushDecompress, Status};
    let mut buf = [0u8; 64 * 1024];
    let mut consumed = 0usize;
    while !input.is_empty() {
        let in_before = d.total_in();
        let out_before = d.total_out();
        let status = d
            .decompress(input, &mut buf, FlushDecompress::None)
            .map_err(|e| format!("decode_error: {e}"))?;
        let used = (d.total_in() - in_before) as usize;
        let produced = (d.total_out() - out_before) as usize;
        if d.total_out() as usize > MAX_DECODED_BYTES {
            return Err(format!("decoded_too_large: >{MAX_DECODED_BYTES}"));
        }
        out.extend_from_slice(&buf[..produced]);
        input = &input[used..];
        consumed += used;
        if matches!(status, Status::StreamEnd) {
            *done = true;
            break;
        }
        if used == 0 && produced == 0 {
            return Err("decode_stalled".into());
        }
    }
    Ok(consumed)
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
    fn streaming_gzip_decodes_split_chunks() {
        let orig = "data: {\"choices\":[{\"delta\":{\"content\":\"你好\"}}]}\n\n".repeat(64);
        let enc = gzip(orig.as_bytes());
        let mut dec = StreamDecoder::new(StreamDecodeKind::Gzip);
        let mut out = Vec::new();
        for chunk in enc.chunks(7) {
            dec.push(chunk, &mut out).unwrap();
        }
        dec.finish(&mut out).unwrap();
        assert_eq!(out, orig.as_bytes());
    }

    #[test]
    fn streaming_zlib_decodes_split_chunks() {
        let orig = "{\"message\":{\"content\":\"电话 13800138000\"}}\n".repeat(32);
        let enc = zlib(orig.as_bytes());
        let mut dec = StreamDecoder::new(StreamDecodeKind::Deflate);
        let mut out = Vec::new();
        for chunk in enc.chunks(5) {
            dec.push(chunk, &mut out).unwrap();
        }
        dec.finish(&mut out).unwrap();
        assert_eq!(out, orig.as_bytes());
    }

    #[test]
    fn streaming_raw_deflate_decodes_split_chunks() {
        let orig = "{\"message\":{\"content\":\"裸 deflate 也要能还原\"}}\n".repeat(16);
        let enc = raw_deflate(orig.as_bytes());
        let mut dec = StreamDecoder::new(StreamDecodeKind::Deflate);
        let mut out = Vec::new();
        for chunk in enc.chunks(3) {
            dec.push(chunk, &mut out).unwrap();
        }
        dec.finish(&mut out).unwrap();
        assert_eq!(out, orig.as_bytes());
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
    /// 回归（审查发现 #2）：`IDENTITY` / 带空白变体必须与 `identity` 等价。
    #[test]
    fn encoding_normalization_is_case_and_space_insensitive() {
        for enc in ["identity", "IDENTITY", " Identity ", "\tIDentIty\n", ""] {
            assert!(is_identity(enc), "{enc:?} 应等价于无编码");
            assert!(!is_decodable(enc), "{enc:?} 不应被当作压缩体");
        }
        assert_eq!(normalize_encoding(" GZip\n"), "gzip");
        assert!(is_decodable(" GZip\n"), "带空白的 gzip 也必须能解码");
        assert!(!is_identity("gzip"));
    }

    /// 请求体解压：明文/identity 返回 None，压缩体解出原文，坏流报错。
    #[test]
    fn request_decode_handles_identity_and_gzip() {
        assert!(decode_request(b"{}", "", 1024).unwrap().is_none());
        assert!(decode_request(b"{}", "IDENTITY", 1024).unwrap().is_none());

        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let plain = br#"{"messages":[{"content":"13800138000"}]}"#;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(plain).unwrap();
        let gz = enc.finish().unwrap();
        let out = decode_request(&gz, "GZIP", 1 << 20).unwrap().unwrap();
        assert_eq!(out, plain.to_vec());

        assert!(
            decode_request(b"not-gzip", "gzip", 1 << 20).is_err(),
            "坏流必须报错（调用方据此拒绝）"
        );
        assert!(
            decode_request(b"x", "gzip, br", 1 << 20).is_err(),
            "多重编码必须报错"
        );
        assert!(
            decode_request(b"x", "made-up", 1 << 20).is_err(),
            "未知编码必须报错"
        );
        // 解出超过调用方上限：必须以哨兵前缀返回，供调用方映射 413。
        let err = decode_request(&gz, "gzip", 8).unwrap_err();
        assert!(err.starts_with(DECODE_TOO_LARGE_PREFIX), "{err}");

        // 大压缩比 + 小上限（生产默认 32MiB / 测试 1KiB）同样要命中哨兵
        let big = format!(
            r#"{{"messages":[{{"content":"{}"}}]}}"#,
            "A".repeat(64 * 1024)
        );
        let mut enc = GzEncoder::new(Vec::new(), Compression::best());
        enc.write_all(big.as_bytes()).unwrap();
        let big_gz = enc.finish().unwrap();
        let err = decode_request(&big_gz, "gzip", 1024).unwrap_err();
        assert!(err.starts_with(DECODE_TOO_LARGE_PREFIX), "{err}");
    }

    /// F-04 回归：多成员 gzip 必须全部解出；`GzDecoder` 只解第一个成员。
    #[test]
    fn multi_member_gzip_is_fully_decoded() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let a = br#"{"model":"m","messages":[{"role":"user","content":"hel"#;
        let b = br#"lo"}]}"#;
        let mut e1 = GzEncoder::new(Vec::new(), Compression::default());
        e1.write_all(a).unwrap();
        let mut body = e1.finish().unwrap();
        let mut e2 = GzEncoder::new(Vec::new(), Compression::default());
        e2.write_all(b).unwrap();
        body.extend_from_slice(&e2.finish().unwrap());

        let out = decode_request(&body, "gzip", 1 << 20).unwrap().unwrap();
        assert_eq!(out.len(), a.len() + b.len(), "多成员被截断");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&out).is_ok(),
            "多成员拼出的完整 JSON 必须可解析: {:?}",
            String::from_utf8_lossy(&out)
        );

        // 累计上限按所有成员算，不是每个成员各自重置
        assert!(
            decode_request(&body, "gzip", 20).is_err(),
            "多成员累计超限必须报错"
        );

        // 第二个成员损坏 / 尾随垃圾：必须整体报错，不能返回「部分解压成功」
        let mut corrupt = gz_bytes(a);
        let mut bad = gz_bytes(b);
        let n = bad.len();
        bad[n - 3] ^= 0xff;
        corrupt.extend_from_slice(&bad);
        assert!(
            decode_request(&corrupt, "gzip", 1 << 20).is_err(),
            "后续成员损坏不得当作完整解压"
        );

        let mut trailing = gz_bytes(b"{\"a\":1}");
        trailing.extend_from_slice(b"garbage");
        assert!(
            decode_request(&trailing, "gzip", 1 << 20).is_err(),
            "尾随垃圾不得静默忽略"
        );
    }

    fn gz_bytes(b: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(b).unwrap();
        e.finish().unwrap()
    }

    /// F-05 回归：zlib 包装与裸 deflate 的超限错误都要保留 `decoded_too_large`
    /// 前缀（否则入口按 415 而不是 413 处理）。
    #[test]
    fn deflate_too_large_keeps_sentinel_for_both_formats() {
        use flate2::write::{DeflateEncoder, ZlibEncoder};
        use flate2::Compression;
        use std::io::Write;
        let big = vec![b'A'; 64 * 1024];

        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&big).unwrap();
        let zbody = z.finish().unwrap();
        let err = decode_request(&zbody, "deflate", 1024).unwrap_err();
        assert!(err.starts_with(DECODE_TOO_LARGE_PREFIX), "zlib: {err}");

        let mut r = DeflateEncoder::new(Vec::new(), Compression::default());
        r.write_all(&big).unwrap();
        let rbody = r.finish().unwrap();
        let err = decode_request(&rbody, "deflate", 1024).unwrap_err();
        assert!(err.starts_with(DECODE_TOO_LARGE_PREFIX), "raw: {err}");

        // 损坏数据仍然是解码失败，不能被误判为超限
        let err = decode_request(b"\x00\x01garbage", "deflate", 1024).unwrap_err();
        assert!(!err.starts_with(DECODE_TOO_LARGE_PREFIX), "{err}");
    }

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
