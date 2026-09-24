//! 内嵌 Web UI（M10）：单文件 HTML + 原生 JS（无构建步骤），rust-embed 打包。

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "assets/"]
struct Assets;

/// /console 主页。
pub async fn index() -> Response {
    html(Assets::get("index.html").map(|f| f.data.to_vec()))
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
                [(header::CONTENT_TYPE, mime)],
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
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            axum::body::Body::from(d),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "index.html missing").into_response(),
    }
}
