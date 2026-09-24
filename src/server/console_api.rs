//! 管理 API（/console/api/*，M10）：配置读写 / 状态 / 日志 / 审计 / 统计 / 暂停恢复。
//!
//! 鉴权：Bearer 或 x-panel-token（`/health` 免鉴权，对齐 Python /api/health 公开语义）。

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::server::{error_response, SharedState};

/// 免鉴权路径。
const PUBLIC_PATHS: &[&str] = &["/console/api/health"];

/// Token 鉴权中间件：/console/api/* 需 Authorization: Bearer <token>。
pub async fn auth_middleware(
    State(state): State<SharedState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path();
    if !path.starts_with("/console/api/") || PUBLIC_PATHS.contains(&path) {
        return next.run(req).await;
    }
    let token = state.config.panel_token();
    let got = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get("x-panel-token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        });
    match got {
        Some(t) if t == token && !token.is_empty() => next.run(req).await,
        _ => error_response(StatusCode::UNAUTHORIZED, "invalid_token"),
    }
}

/// Origin 校验中间件（对齐 Python `api_guard` 核心语义：拒绝跨站写操作）。
pub async fn origin_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !req.uri().path().starts_with("/console/api/") {
        return next.run(req).await;
    }
    // 写方法需要 Origin/Referer 与 Host 同源（无 Origin 的 CLI 调用放行）
    let write = matches!(
        *req.method(),
        axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::DELETE
    );
    if write {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let origin = req
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .or_else(|| req.headers().get("referer").and_then(|v| v.to_str().ok()));
        if let Some(o) = origin {
            let o_host = o
                .split("://")
                .nth(1)
                .unwrap_or(o)
                .split('/')
                .next()
                .unwrap_or("");
            let same = o_host == host
                || o_host.ends_with(&format!(
                    "127.0.0.1:{}",
                    host.rsplit(':').next().unwrap_or("")
                ))
                || o_host.starts_with("http://localhost")
                || o_host.starts_with("http://127.0.0.1");
            if !same {
                return error_response(StatusCode::FORBIDDEN, "origin_rejected");
            }
        }
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

pub async fn get_config(State(state): State<SharedState>) -> Response {
    json_response(StatusCode::OK, &state.config.get())
}

pub async fn put_config(State(state): State<SharedState>, body: String) -> Response {
    let cfg: crate::config::Config = match serde_json::from_str(&body) {
        Ok(c) => c,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid_config: {e}")),
    };
    let warnings = state.config.update(cfg);
    state.rebuild_runtime();
    json_response(
        StatusCode::OK,
        &json!({
            "ok": true,
            "config": state.config.get(),
            "warnings": warnings.iter().map(|w| w.0.clone()).collect::<Vec<_>>(),
        }),
    )
}

#[derive(Debug, serde::Deserialize)]
pub struct PatchBody {
    pub path: String,
    pub value: Value,
}

pub async fn patch_config(State(state): State<SharedState>, body: String) -> Response {
    let patch: PatchBody = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid_patch: {e}")),
    };
    match state.config.patch(&patch.path, patch.value) {
        Ok(warnings) => {
            state.rebuild_runtime();
            json_response(
                StatusCode::OK,
                &json!({
                    "ok": true,
                    "config": state.config.get(),
                    "warnings": warnings.iter().map(|w| w.0.clone()).collect::<Vec<_>>(),
                }),
            )
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, &format!("patch_failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

pub async fn get_status(State(state): State<SharedState>) -> Response {
    let cfg = state.config.get();
    let counters = state.bus.counters();
    let (writer, event_db) = match &state.event_store {
        Some(es) => (
            serde_json::to_value(es.stats.lock().unwrap().clone()).unwrap_or(Value::Null),
            json!(es.path().to_string_lossy()),
        ),
        None => (Value::Null, Value::Null),
    };
    json_response(
        StatusCode::OK,
        &json!({
            "ok": true,
            "listening": true,
            "port": cfg.server.port,
            "bind": cfg.server.bind,
            "upstream_target": cfg.upstream.target,
            "paused": cfg.paused,
            "fail_closed": cfg.fail_closed,
            "protocol_detection": ["chat_completions", "responses", "anthropic"],
            "unknown_shape_policy": if cfg.fail_closed { "full_tree_mask" } else { "passthrough" },
            "config_version": state.config.version(),
            "counters": counters,
            "writer_stats": writer,
            "event_db": event_db,
            "sessions": state.sessions.sessions.len(),
        }),
    )
}

pub async fn pause(State(state): State<SharedState>) -> Response {
    let mut cfg = state.config.get();
    cfg.paused = true;
    state.config.update(cfg);
    json_response(StatusCode::OK, &json!({ "ok": true, "paused": true }))
}

pub async fn resume(State(state): State<SharedState>) -> Response {
    let mut cfg = state.config.get();
    cfg.paused = false;
    state.config.update(cfg);
    json_response(StatusCode::OK, &json!({ "ok": true, "paused": false }))
}

pub async fn health(State(state): State<SharedState>) -> Response {
    let cfg = state.config.get();
    let upstream_ok = !cfg.upstream.target.is_empty();
    json_response(
        StatusCode::OK,
        &json!({
            "ok": upstream_ok,
            "panel_port_listening": true,
            "upstream_configured": upstream_ok,
            "upstream_target": cfg.upstream.target,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    )
}

// ---------------------------------------------------------------------------
// 日志 / 统计 / 审计
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct LogsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub event_type: Option<String>,
}

fn default_limit() -> usize {
    200
}

pub async fn get_logs(State(state): State<SharedState>, Query(q): Query<LogsQuery>) -> Response {
    let limit = q.limit.clamp(1, 2000);
    // 内存 ring 优先；SQLite 兜底（ring 只留 2000 条）
    let mut events = state.bus.recent(limit.max(200));
    if events.len() < limit {
        if let Some(es) = &state.event_store {
            events = es.fetch_events(limit, q.offset);
        }
    }
    let filtered: Vec<_> = match &q.event_type {
        Some(t) => events
            .into_iter()
            .filter(|e| format!("{:?}", e.event_type).to_uppercase() == t.to_uppercase())
            .collect(),
        None => events,
    };
    json_response(StatusCode::OK, &json!({ "events": filtered }))
}

#[derive(Debug, serde::Deserialize)]
pub struct DetailQuery {
    pub id: u64,
}

pub async fn get_log_detail(
    State(state): State<SharedState>,
    Query(q): Query<DetailQuery>,
) -> Response {
    match state.bus.by_id(q.id) {
        Some(ev) => json_response(StatusCode::OK, &ev),
        None => error_response(StatusCode::NOT_FOUND, "event_not_found"),
    }
}

pub async fn clear_logs(State(state): State<SharedState>) -> Response {
    state.bus.clear();
    if let Some(es) = &state.event_store {
        if let Err(e) = es.clear_events() {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("clear_failed: {e}"),
            );
        }
    }
    json_response(StatusCode::OK, &json!({ "ok": true }))
}

pub async fn stats_today(State(state): State<SharedState>) -> Response {
    match &state.event_store {
        Some(es) => match es.today_stats() {
            Ok(v) => json_response(StatusCode::OK, &v),
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("stats_failed: {e}"),
            ),
        },
        None => {
            let c = state.bus.counters();
            json_response(
                StatusCode::OK,
                &serde_json::to_value(&c).unwrap_or(Value::Null),
            )
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_days")]
    pub days: i64,
}

fn default_days() -> i64 {
    7
}

pub async fn stats_history(
    State(state): State<SharedState>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    match &state.event_store {
        Some(es) => match es.stats_history(q.days.clamp(1, 90)) {
            Ok(v) => json_response(StatusCode::OK, &v),
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("history_failed: {e}"),
            ),
        },
        None => json_response(StatusCode::OK, &json!({ "data": [] })),
    }
}

/// 按模型的 token 用量（今日，token 总量降序）。
///
/// **只统计 token 数量，不做价格/费用计算**（用户明确要求去掉价格逻辑）。
pub async fn stats_models(State(state): State<SharedState>) -> Response {
    match &state.event_store {
        Some(es) => match es.tokens_by_model(100) {
            Ok(rows) => {
                let models: Vec<Value> = rows
                    .into_iter()
                    .map(|(model, p, c)| {
                        json!({
                            "model": model,
                            "prompt_tokens": p,
                            "completion_tokens": c,
                            "total_tokens": p + c
                        })
                    })
                    .collect();
                json_response(StatusCode::OK, &json!({ "models": models }))
            }
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("stats_models_failed: {e}"),
            ),
        },
        None => json_response(StatusCode::OK, &json!({ "models": [] })),
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

pub async fn get_audit_events(
    State(state): State<SharedState>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let events = match &state.event_store {
        Some(es) => {
            let from_db = es.fetch_audits(q.limit.clamp(1, 2000));
            if from_db.is_empty() {
                state.bus.recent_audits(q.limit.clamp(1, 2000))
            } else {
                from_db
            }
        }
        None => state.bus.recent_audits(q.limit.clamp(1, 2000)),
    };
    json_response(StatusCode::OK, &json!({ "events": events }))
}

pub async fn clear_audit_events(State(state): State<SharedState>) -> Response {
    state.bus.clear_audits();
    if let Some(es) = &state.event_store {
        if let Err(e) = es.clear_audits() {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("clear_failed: {e}"),
            );
        }
    }
    json_response(StatusCode::OK, &json!({ "ok": true }))
}

/// 导出（恒脱敏：剔除原文类字段，只留打码预览与摘要）。
pub async fn export_logs(State(state): State<SharedState>) -> Response {
    let events = match &state.event_store {
        Some(es) => es.fetch_events(2000, 0),
        None => state.bus.recent(2000),
    };
    let mut out = Vec::new();
    for e in events {
        let mut v = serde_json::to_value(&e).unwrap_or(Value::Null);
        if let Some(obj) = v.as_object_mut() {
            obj.remove("dialog");
            obj.remove("req_preview");
            obj.remove("resp_preview");
            if let Some(items) = obj.get_mut("items").and_then(|i| i.as_array_mut()) {
                for it in items.iter_mut() {
                    if let Some(o) = it.as_object_mut() {
                        o.remove("original");
                    }
                }
            }
            obj.insert("masked_export".into(), Value::Bool(true));
        }
        out.push(v);
    }
    json_response(
        StatusCode::OK,
        &json!({ "ok": true, "masked_export": true, "events": out }),
    )
}

/// 上游连通性测试。
pub async fn test_upstream(State(state): State<SharedState>) -> Response {
    let cfg = state.config.get();
    if cfg.upstream.target.is_empty() {
        return json_response(
            StatusCode::OK,
            &json!({ "ok": false, "error": "upstream_not_configured" }),
        );
    }
    let t0 = std::time::Instant::now();
    let target = crate::upstream::http_client::parse_target(&cfg.upstream.target);
    match target {
        Ok(parts) => {
            // 只做 TCP 连接测试（不消耗 token）
            let addr = format!("{}:{}", parts.host, parts.port);
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(_)) => json_response(
                    StatusCode::OK,
                    &json!({ "ok": true, "target": cfg.upstream.target,
                             "resolved": addr, "connect_ms": t0.elapsed().as_millis() }),
                ),
                Ok(Err(e)) => json_response(
                    StatusCode::OK,
                    &json!({ "ok": false, "error": format!("connect_failed: {e}"), "resolved": addr }),
                ),
                Err(_) => json_response(
                    StatusCode::OK,
                    &json!({ "ok": false, "error": "connect_timeout", "resolved": addr }),
                ),
            }
        }
        Err(e) => json_response(StatusCode::OK, &json!({ "ok": false, "error": e })),
    }
}

/// 演示脱敏（不计事件、不动会话：用独立 sid）。
pub async fn demo_mask(State(state): State<SharedState>, body: String) -> Response {
    let req: Value = serde_json::from_str(&body).unwrap_or(json!({}));
    let text = req.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let sid = "console-demo";
    state.sessions.drop_session(sid);
    state.sessions.new_session(sid);
    let custom = state.custom_words();
    let cfg = state.config.get();
    let ctx = crate::mask::engine::MaskCtx::new(&cfg, state.sessions, sid.into(), &custom);
    let masked = ctx.mask(text);
    let mut stats = crate::mask::engine::RestoreStats::default();
    let restored =
        crate::mask::engine::restore_final(&masked, sid, false, state.sessions, &mut stats);
    state.sessions.drop_session(sid);
    json_response(
        StatusCode::OK,
        &json!({ "ok": true, "masked": masked, "restored": restored, "matches": stats.restored }),
    )
}

/// 令牌轮换。
pub async fn rotate_token(State(state): State<SharedState>) -> Response {
    let mut cfg = state.config.get();
    cfg.panel_token = new_token();
    state.config.update(cfg);
    json_response(
        StatusCode::OK,
        &json!({ "ok": true, "panel_token": state.config.get().panel_token }),
    )
}

/// 打开数据目录（本机控制台提示用；不执行 shell，只回路径）。
pub async fn data_dir(State(state): State<SharedState>) -> Response {
    json_response(
        StatusCode::OK,
        &json!({ "ok": true, "data_dir": state.config.data_dir().to_string_lossy() }),
    )
}

fn new_token() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn json_response<T: serde::Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (
            status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("serialize_failed: {e}"),
        ),
    }
}

/// HeaderMap 提取工具。
#[allow(dead_code)]
pub fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_ascii_and_long_enough() {
        let t = new_token();
        assert_eq!(t.len(), 24);
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
