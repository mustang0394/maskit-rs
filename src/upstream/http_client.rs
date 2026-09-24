//! 上游 HTTP 客户端：连接池 / 超时 / 透传转发。
//!
//! 使用 hyper 客户端直连（PLAN §9 风险对策：reqwest 对流式回写细粒度控制不足）。

use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::Request;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use std::time::Duration;

/// 上游请求构建所需的最小信息（与 scheme/host/port 解耦，见 parse_target）。
#[derive(Debug, Clone, PartialEq)]
pub struct TargetParts {
    pub scheme: String, // "http" | "https"
    pub host: String,   // 不含端口
    pub port: u16,
    /// 上游目标自带的路径前缀（如 target=https://relay.example.com/v1 → "/v1"）
    pub path_prefix: String,
}

/// 解析 upstream.target（对齐 Python `_parse_upstream_target`）。
/// 支持 `https://host:port/base/path` 形态；缺省 scheme=https，缺省端口按 scheme。
pub fn parse_target(target: &str) -> Result<TargetParts, String> {
    let t = target.trim();
    if t.is_empty() {
        return Err("upstream.target 为空".into());
    }
    let (scheme, rest) = if let Some(r) = t.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = t.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(format!("upstream.target 缺少 scheme: {t}"));
    };
    // 分离 host[:port] 与 path
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    // IPv6 字面量 [::1]:8080
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.find(']') {
            Some(j) => {
                let h = &stripped[..j];
                let after = &stripped[j + 1..];
                let p = after
                    .strip_prefix(':')
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                (h.to_string(), p)
            }
            None => return Err(format!("非法 IPv6 authority: {authority}")),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h.to_string(), p),
                Err(_) => (
                    authority.to_string(),
                    if scheme == "https" { 443 } else { 80 },
                ),
            },
            None => (
                authority.to_string(),
                if scheme == "https" { 443 } else { 80 },
            ),
        }
    };
    if host.is_empty() {
        return Err("upstream.target host 为空".into());
    }
    let path_prefix = if path.is_empty() || path == "/" {
        String::new()
    } else {
        path.trim_end_matches('/').to_string()
    };
    Ok(TargetParts {
        scheme: scheme.into(),
        host,
        port,
        path_prefix,
    })
}

/// 上游客户端。整个进程一个实例（连接池内建）。
pub struct UpstreamClient {
    http: Client<hyper_util::client::legacy::connect::HttpConnector, http_body_util::Full<Bytes>>,
    pub target: TargetParts,
    pub extra_headers: Vec<(HeaderName, HeaderValue)>,
    connect_timeout: Duration,
}

impl UpstreamClient {
    /// 永不失败的构造：target 为空/非法时回落到不可达占位（反代路径会返回 502）。
    /// main 与测试都走这个入口，保证「未配置上游」也能起服务。
    pub fn new_or_placeholder(cfg: &crate::config::UpstreamConfig) -> Self {
        match Self::new(cfg) {
            Ok(c) => c,
            Err(_) => {
                let mut fallback = cfg.clone();
                fallback.target = "http://127.0.0.1:9".into(); // 不可达（discard 端口）
                Self::new(&fallback).expect("占位上游构建失败")
            }
        }
    }

    pub fn new(cfg: &crate::config::UpstreamConfig) -> Result<Self, String> {
        let target = parse_target(&cfg.target)?;
        let mut http_connector = HttpConnector::new();
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(cfg.connect_timeout_secs.max(1))));
        http_connector.set_nodelay(true);
        let client: Client<_, http_body_util::Full<Bytes>> = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_timer(TokioTimer::new())
            .build(http_connector);
        let extra = {
            let mut v = Vec::new();
            for (k, val) in &cfg.extra_headers {
                let name = HeaderName::from_bytes(k.as_bytes())
                    .map_err(|e| format!("extra_headers 非法头名 {k}: {e}"))?;
                let value = HeaderValue::from_str(val)
                    .map_err(|e| format!("extra_headers 非法头值 {k}: {e}"))?;
                v.push((name, value));
            }
            v
        };
        Ok(Self {
            http: client,
            target,
            extra_headers: extra,
            connect_timeout: Duration::from_secs(cfg.connect_timeout_secs.max(1)),
        })
    }

    /// 构造发往上游的请求。
    ///
    /// * `client_path` — 客户端原始 path+query（已剥除 console 前缀）
    /// * `headers` — 转发头（调用方已剔除逐跳头）
    /// * `body` — 请求体
    #[allow(clippy::too_many_arguments)]
    pub fn build_request(
        &self,
        method: &str,
        client_path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Request<http_body_util::Full<Bytes>>, String> {
        let uri = format!(
            "{}://{}:{}{}{}",
            self.target.scheme,
            self.target.host,
            self.target.port,
            self.target.path_prefix,
            client_path,
        );
        let uri: hyper::Uri = uri.parse().map_err(|e| format!("上游 URI 非法: {e}"))?;
        let body_len = body.len();
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(http_body_util::Full::new(body))
            .map_err(|e| format!("构建上游请求失败: {e}"))?;
        // 先放逐跳剔除后的客户端头，再补 Host 与逐 hop 必需头
        *req.headers_mut() = forward_headers(headers);
        let host_hdr = if self.target.port == 443 && self.target.scheme == "https"
            || self.target.port == 80 && self.target.scheme == "http"
        {
            self.target.host.clone()
        } else {
            format!("{}:{}", self.target.host, self.target.port)
        };
        if let Ok(v) = HeaderValue::from_str(&host_hdr) {
            req.headers_mut().insert(hyper::header::HOST, v);
        }
        // Full body：声明 content-length
        if body_len > 0 {
            req.headers_mut()
                .insert(hyper::header::CONTENT_LENGTH, HeaderValue::from(body_len));
        }
        for (k, v) in &self.extra_headers {
            req.headers_mut().insert(k, v.clone());
        }
        Ok(req)
    }

    /// 发送请求并返回响应。注意：响应 body 是 Incoming 流，由调用方决定
    /// 整包聚合还是流式转发。
    pub async fn send(
        &self,
        req: Request<http_body_util::Full<Bytes>>,
    ) -> Result<hyper::Response<Incoming>, String> {
        // 连接级超时通过 tokio::time::timeout 包裹（仅 connect 阶段预算严格；
        // 读取阶段读超时配置为 0 表示不限——SSE 长流需要）。
        let fut = self.http.request(req);
        match tokio::time::timeout(self.connect_timeout.max(Duration::from_secs(300)), fut).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(format!("上游请求失败: {e}")),
            Err(_) => Err("上游请求超时".into()),
        }
    }
}

/// 判定是否为凭据类请求头（PLAN §2.2 / Python `_CREDENTIAL_HEADER_NAMES`）。
/// extra_headers 注入时凭据头一律跳过——凭据归客户端所有。
#[allow(dead_code)] // M6 使用
pub fn is_credential_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "x-api-key"
            | "api-key"
            | "apikey"
            | "x-goog-api-key"
            | "x-auth-token"
            | "x-access-token"
            | "x-token"
            | "x-session-token"
            | "private-token"
            | "x-gitlab-token"
            | "x-github-token"
            | "x-amz-security-token"
            | "x-amz-credential"
            | "x-client-secret"
            | "client-secret"
    )
}

/// HTTP 逐跳头（转发时必须剔除）。
pub fn is_hop_by_hop_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// 空 body 的快捷构造。
#[allow(dead_code)] // M6+ 使用
pub fn empty_body() -> http_body_util::Full<Bytes> {
    http_body_util::Full::new(Bytes::new())
}

/// Incoming body 聚合为 Bytes（带上限）。
pub async fn read_body_limited(mut body: Incoming, limit: usize) -> Result<Bytes, String> {
    let mut buf = bytes::BytesMut::with_capacity(8 * 1024);
    while let Some(frame) = body.frame().await {
        let data = frame.map_err(|e| format!("读取 body 失败: {e}"))?;
        if let Some(slice) = data.data_ref() {
            if buf.len() + slice.len() > limit {
                return Err(crate::error::ErrorKind::BodyTooLarge.reason().to_string());
            }
            buf.extend_from_slice(slice);
        }
    }
    Ok(buf.freeze())
}

/// 从 HeaderMap 克隆转发头（剔除逐跳头）。
pub fn forward_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in headers {
        if is_hop_by_hop_header(k.as_str()) {
            continue;
        }
        out.insert(k, v.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_basic() {
        let t = parse_target("https://api.example.com").unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.host, "api.example.com");
        assert_eq!(t.port, 443);
        assert_eq!(t.path_prefix, "");

        let t = parse_target("http://127.0.0.1:8000/v1").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.port, 8000);
        assert_eq!(t.path_prefix, "/v1");

        let t = parse_target("https://relay.example.com/v1/").unwrap();
        assert_eq!(t.path_prefix, "/v1");
    }

    #[test]
    fn parse_target_ipv6() {
        let t = parse_target("http://[::1]:9000").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 9000);
    }

    #[test]
    fn parse_target_errors() {
        assert!(parse_target("").is_err());
        assert!(parse_target("api.example.com").is_err());
        assert!(parse_target("https://").is_err());
    }

    #[test]
    fn credential_header_detection() {
        assert!(is_credential_header("Authorization"));
        assert!(is_credential_header("x-api-key"));
        assert!(is_credential_header("X-GitHub-Token"));
        assert!(!is_credential_header("anthropic-version"));
        assert!(!is_credential_header("content-type"));
    }

    #[test]
    fn hop_by_hop() {
        assert!(is_hop_by_hop_header("Transfer-Encoding"));
        assert!(is_hop_by_hop_header("host"));
        assert!(!is_hop_by_hop_header("accept"));
    }
}
