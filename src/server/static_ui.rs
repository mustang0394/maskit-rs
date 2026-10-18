//! 内嵌 Web UI（M10）：单文件 HTML + 原生 JS（无构建步骤），rust-embed 打包。

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "assets/"]
struct Assets;

/// 内嵌静态资源的**内容指纹**（8 位 hex）。
///
/// 用途：`/console`、`/console/app.js` 的 URL 在二进制升级前后**完全一样** ——
/// 内嵌资源又没有 `etag` / `last-modified`，浏览器与中间代理很容易「升级后继续吃
/// 旧的 app.js」。真机表现就是「后端已经是新版了，Web 端却看不到新面板」（例如
/// 「完整报文 · 原始字节（诊断环）」四栏根本不出现）。
///
/// 把资源内容哈希进查询串（`?v=<指纹>`）后，内容一变 URL 就变，缓存自然失效。
/// 用 sha256 前 8 位（而不是 `CARGO_PKG_VERSION`）：版本号在整个 0.1.x 周期
/// 都不变，破不了缓存。
fn assets_version() -> &'static str {
    static V: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for name in ["index.html", "app.js", "style.css"] {
            h.update(name.as_bytes());
            h.update([0u8]);
            match Assets::get(name) {
                Some(f) => h.update(&f.data),
                None => h.update(b"<missing>"),
            }
        }
        // 取前 4 字节 = 8 位 hex：破缓存只需「内容一变值就变」，32 位足够。
        h.finalize()
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect()
    });
    &V
}

/// 给内嵌 HTML 里的资源引用补上 `?v=<指纹>`（破缓存）。
///
/// 在**发出去的时候**替换（而不是写死在 index.html 里）：版本号必须随资源内容
/// 自动更新，写死就总要记得手工改。
fn versioned_html(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let v = assets_version();
    text.replace("/console/app.js\"", &format!("/console/app.js?v={v}\""))
        .replace(
            "/console/style.css\"",
            &format!("/console/style.css?v={v}\""),
        )
        .into_bytes()
}

/// 内嵌资源必须显式禁用「不校验就直接用缓存」。
///
/// `no-cache` 的语义是「可以存，但每次必须回源校验」—— 配合上面的 `?v=`
/// 指纹，升级后一定能拿到新资源；而 `no-store` 会让每次翻页都重下 60KB，没必要。
const CACHE_CONTROL_NO_CACHE: &str = "no-cache, must-revalidate";

/// /console 主页。
pub async fn index() -> Response {
    html(Assets::get("index.html").map(|f| versioned_html(&f.data)))
}

/// 具名静态资源（/console/style.css、/console/app.js）。
pub async fn static_asset_named(req: axum::extract::Request) -> Response {
    let path = req.uri().path().trim_start_matches("/console/").to_string();
    static_asset(axum::extract::Path(path)).await
}

/// 静态资源（/console/app.js /console/style.css）。
pub async fn static_asset(axum::extract::Path(rest): axum::extract::Path<String>) -> Response {
    let path = rest.trim_start_matches('/').to_string();
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, mime),
                    (header::CACHE_CONTROL, CACHE_CONTROL_NO_CACHE.to_string()),
                ],
                axum::body::Body::from(content.data.to_vec()),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn html(data: Option<Vec<u8>>) -> Response {
    match data {
        Some(d) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
                (header::CACHE_CONTROL, CACHE_CONTROL_NO_CACHE.to_string()),
            ],
            axum::body::Body::from(d),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "index.html missing").into_response(),
    }
}
