//! axum 路由装配：/console（内嵌 UI + 管理 API）与其余全部路径（LLM 反代）。

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

use crate::config::ConfigCenter;

pub mod console_api;
pub mod proxy;
pub mod response;
pub mod static_ui;

use crate::mask::engine::CustomWords;
use crate::mask::session::SessionStore;
use crate::store::events::EventBus;
use crate::upstream::UpstreamClient;

/// 全局共享状态。
pub struct AppState {
    pub config: Arc<ConfigCenter>,
    pub bus: Arc<EventBus>,
    /// 上游客户端（**配置变更时热重载**：改 upstream.target 无需重启）
    upstream: std::sync::RwLock<Arc<UpstreamClient>>,
    /// 会话存储（进程唯一）
    pub sessions: &'static SessionStore,
    /// SQLite 事件库（可选：打开失败时退化为仅内存 ring）
    pub event_store: Option<Arc<crate::store::db::EventStore>>,
    /// 命令拦截引擎
    cmdblock: std::sync::RwLock<Arc<crate::cmdblock::CmdBlockEngine>>,
    /// 自定义词/正则引擎（配置变更时重建）
    custom_words: std::sync::RwLock<Arc<CustomWords>>,
}

impl AppState {
    pub fn new(
        config: Arc<ConfigCenter>,
        bus: Arc<EventBus>,
        upstream: Arc<UpstreamClient>,
        event_store: Option<Arc<crate::store::db::EventStore>>,
    ) -> Self {
        let cfg = config.get();
        let custom = Arc::new(CustomWords::build(&cfg));
        let cmdblock = Arc::new(crate::cmdblock::CmdBlockEngine::new(&cfg));
        Self {
            config,
            bus,
            upstream: std::sync::RwLock::new(upstream),
            sessions: &crate::mask::session::STORE,
            event_store,
            custom_words: std::sync::RwLock::new(custom),
            cmdblock: std::sync::RwLock::new(cmdblock),
        }
    }

    /// 取当前上游客户端。
    pub fn upstream(&self) -> Arc<UpstreamClient> {
        self.upstream.read().unwrap().clone()
    }

    /// 取命令拦截引擎。
    pub fn cmdblock(&self) -> Arc<crate::cmdblock::CmdBlockEngine> {
        self.cmdblock.read().unwrap().clone()
    }

    /// 取当前自定义词引擎（配置热更新后由 rebuild_custom_words 替换）。
    pub fn custom_words(&self) -> Arc<CustomWords> {
        self.custom_words.read().unwrap().clone()
    }

    /// 配置变更后重建运行时组件（词表 / 命令拦截 / 上游客户端）。
    ///
    /// 上游热重载是必需的：否则控制台改了 target 却不生效，用户以为配好了
    /// （真实冒烟实测：改配置后请求仍打到启动时的占位上游 → 502）。
    pub fn rebuild_runtime(&self) {
        let cfg = self.config.get();
        *self.custom_words.write().unwrap() = Arc::new(CustomWords::build(&cfg));
        *self.cmdblock.write().unwrap() = Arc::new(crate::cmdblock::CmdBlockEngine::new(&cfg));
        if let Ok(new_upstream) = UpstreamClient::new(&cfg.upstream) {
            *self.upstream.write().unwrap() = Arc::new(new_upstream);
        } else {
            // target 为空/非法：保持占位客户端（请求会得到 502 并留痕）
            *self.upstream.write().unwrap() =
                Arc::new(UpstreamClient::new_or_placeholder(&cfg.upstream));
        }
    }
}

pub type SharedState = Arc<AppState>;

pub fn build_router(state: SharedState) -> Router {
    let console = Router::new()
        // UI
        .route("/console", get(static_ui::index))
        .route("/console/", get(static_ui::index))
        .route("/console/style.css", get(static_ui::static_asset_named))
        .route("/console/app.js", get(static_ui::static_asset_named))
        // 配置
        .route("/console/api/config", get(console_api::get_config).post(console_api::put_config))
        .route("/console/api/config/patch", post(console_api::patch_config))
        // 状态与启停
        .route("/console/api/status", get(console_api::get_status))
        .route("/console/api/health", get(console_api::health))
        .route("/console/api/proxy/pause", post(console_api::pause))
        .route("/console/api/proxy/resume", post(console_api::resume))
        // 日志
        .route("/console/api/logs", get(console_api::get_logs))
        .route("/console/api/logs/detail", get(console_api::get_log_detail))
        .route("/console/api/logs/clear", post(console_api::clear_logs))
        .route("/console/api/logs/export", get(console_api::export_logs))
        // 统计
        .route("/console/api/stats/today", get(console_api::stats_today))
        .route("/console/api/stats/history", get(console_api::stats_history))
        .route("/console/api/stats/models", get(console_api::stats_models))
        // 审计
        .route("/console/api/audit/events", get(console_api::get_audit_events))
        .route("/console/api/audit/clear", post(console_api::clear_audit_events))
        // 运维
        .route("/console/api/upstream/test", post(console_api::test_upstream))
        .route("/console/api/demo/mask", post(console_api::demo_mask))
        .route("/console/api/rotate-token", post(console_api::rotate_token))
        .route("/console/api/data-dir", get(console_api::data_dir))
        .route("/console/{*rest}", get(static_ui::static_asset));

    Router::new()
        .merge(console)
        .fallback(proxy::handler)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(axum::middleware::from_fn(
            crate::server::console_api::origin_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::server::console_api::auth_middleware,
        ))
        .with_state(state)
}

/// 安全响应头（对齐 Python `security_headers` 的核心语义）。
async fn security_headers_middleware(
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if let Ok(v) = axum::http::HeaderValue::from_str("nosniff") {
        h.insert("x-content-type-options", v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str("DENY") {
        h.insert("x-frame-options", v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str("no-referrer") {
        h.insert("referrer-policy", v);
    }
    resp
}

/// 透传转发 handler（M1：body 原样转发上游，响应原样回写）。
/// M6 将替换为完整脱敏管线。
pub async fn passthrough(
    state: &SharedState,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: bytes::Bytes,
) -> Response {
    let mut fwd = crate::upstream::http_client::forward_headers(headers);
    // SSE 请求声明 identity：上游压缩会让流式接管退化（对齐 Python）
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ct.contains("json") {
        fwd.insert(
            "accept-encoding",
            axum::http::HeaderValue::from_static("identity"),
        );
    }
    let upstream = state.upstream();
    let req = match upstream.build_request(method, uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"), &fwd, body) {
        Ok(r) => r,
        Err(e) => {
            return error_response(StatusCode::BAD_GATEWAY, &format!("upstream_build_failed: {e}"));
        }
    };
    match upstream.send(req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = crate::upstream::http_client::forward_headers(resp.headers());
            let body_bytes = match crate::upstream::http_client::read_body_limited(resp.into_body(), 64 * 1024 * 1024).await {
                Ok(b) => b,
                Err(e) => return error_response(StatusCode::BAD_GATEWAY, &format!("upstream_read_failed: {e}")),
            };
            let mut out = Response::builder().status(status);
            {
                let h = out.headers_mut().unwrap();
                for (k, v) in resp_headers {
                    if let Some(name) = k {
                        h.insert(name, v);
                    }
                }
            }
            out.body(Body::from(body_bytes)).unwrap()
        }
        Err(e) => error_response(StatusCode::BAD_GATEWAY, &format!("upstream_failed: {e}")),
    }
}

/// 结构化错误响应（JSON body，对齐 Python 的 error 形态）。
pub fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "error": message });
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response()
}

/// 统一入口：M1 阶段所有反代路径走 passthrough。
/// （M6 起 proxy::handler 承接完整管线；此函数保留为模块内工具。）
#[allow(dead_code)]
pub async fn forward_all(state: SharedState, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, state.config.max_body_bytes()).await {
        Ok(b) => b,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("body_read_failed: {e}")),
    };
    let method = parts.method.as_str().to_string();
    passthrough(&state, &method, &parts.uri, &parts.headers, body_bytes).await
}
