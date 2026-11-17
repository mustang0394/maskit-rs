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
    /// 传统点分路径（`mask.custom_words.张三`）。**键含 `.` 时不能用**。
    #[serde(default)]
    pub path: String,
    /// 路径段数组（推荐）。`["mask","custom_words","example.com"]` 键原样写入，
    /// 不做任何分隔符切分。
    #[serde(default)]
    pub segs: Vec<String>,
    pub value: Value,
}

pub async fn patch_config(State(state): State<SharedState>, body: String) -> Response {
    let patch: PatchBody = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid_patch: {e}")),
    };
    // segs 优先：点分 path 无法表达含 '.' 的键
    let patched = if !patch.segs.is_empty() {
        state.config.patch_segs(&patch.segs, patch.value)
    } else {
        state.config.patch(&patch.path, patch.value)
    };
    match patched {
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
    /// 全文搜索（路径 / 模型 / 原因 / 原文 / 占位符）
    #[serde(default)]
    pub q: Option<String>,
}

fn default_limit() -> usize {
    200
}

pub async fn get_logs(State(state): State<SharedState>, Query(q): Query<LogsQuery>) -> Response {
    let limit = q.limit.clamp(1, 2000);
    let etype = q.event_type.as_deref();
    let search = q.q.as_deref();
    match &state.event_store {
        Some(es) => {
            // 列表只取摘要（SQL 层投影），不把整条 payload 读进内存：
            // 单条 payload 含 dialog/masked_dialog（各 8000 字符）、请求头（16KiB）、
            // 命中明细（30 条原文），一页 100 条能到数 MB —— 这是「浏览器卡」的根因。
            let (mut events, db_total) = es.fetch_event_summaries(limit, q.offset, etype, search);
            // 写线程是异步的（最多 ≤500ms 入队延迟），刚发生的请求可能还没落库。
            // 首页把内存 ring 里**比库里最新 id 更新**的事件补到最前，
            // 既保证「刚发的请求立刻可见」，又不会把旧事件重复前置。
            let mut total = db_total;
            if q.offset == 0 {
                let max_db_id = events.first().map(|e| e.id).unwrap_or(0);
                let fresh: Vec<_> = state
                    .bus
                    .recent_filtered(limit, etype, search)
                    .into_iter()
                    .filter(|e| e.id > max_db_id)
                    .map(|e| crate::store::events::EventSummary::from_event(&e))
                    .collect();
                total += fresh.len();
                if !fresh.is_empty() {
                    events = fresh.into_iter().chain(events).take(limit).collect();
                }
            }
            json_response(
                StatusCode::OK,
                &json!({ "events": events, "total": total, "offset": q.offset, "limit": limit }),
            )
        }
        None => {
            let events: Vec<_> = state
                .bus
                .recent_filtered(limit, etype, search)
                .iter()
                .map(crate::store::events::EventSummary::from_event)
                .collect();
            json_response(
                StatusCode::OK,
                &json!({ "events": events, "total": events.len(), "offset": 0, "limit": limit }),
            )
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct DetailQuery {
    pub id: u64,
}

pub async fn get_log_detail(
    State(state): State<SharedState>,
    Query(q): Query<DetailQuery>,
) -> Response {
    let ev = state.bus.by_id(q.id).or_else(|| {
        // 内存 ring 只有 2000 条：更早的事件必须回 SQLite 兜底。
        // 否则列表里能看到的行点开后 404（主从详情布局下这是硬伤）。
        state
            .event_store
            .as_ref()
            .and_then(|es| es.fetch_event_by_id(q.id))
    });
    let Some(ev) = ev else {
        return error_response(StatusCode::NOT_FOUND, "event_not_found");
    };
    let mut v = serde_json::to_value(&ev).unwrap_or(Value::Null);
    if let Some(obj) = v.as_object_mut() {
        // 完整报文**不再内联返回**：它最多 4 侧 × 1MiB，塞进详情会让浏览器把
        // 几 MB 文本一次性渲染（`highlight()` 还要全量扫描）。改为只回三个标志，
        // 正文由 `/logs/trace/download` 按需下载。
        let cfg = state.config.get();
        let enabled =
            cfg.full_trace_count > 0 && crate::config::log_keeps_credential_plaintext(&cfg);
        let available = enabled
            && !ev.session_id.is_empty()
            && state
                .event_store
                .as_ref()
                .map(|es| es.has_trace(&ev.session_id))
                .unwrap_or(false);
        obj.insert("trace_enabled".into(), Value::Bool(enabled));
        obj.insert("trace_keep_count".into(), Value::from(cfg.full_trace_count));
        obj.insert("trace_available".into(), Value::Bool(available));
    }
    json_response(StatusCode::OK, &v)
}

/// 下载某条事件的完整报文（`.txt` 附件）。
///
/// 这是**唯一**能拿到完整报文的出口：详情接口只回 `trace_available`。
/// 用 `text/plain` 附件而不是 JSON，是因为报文本身就是要给人看/贴进 issue 的
/// 原始字节，`<pre>` 内联渲染几 MB 会让页面卡死（本次重构的起因）。
pub async fn download_trace(
    State(state): State<SharedState>,
    Query(q): Query<DetailQuery>,
) -> Response {
    let ev = state.bus.by_id(q.id).or_else(|| {
        state
            .event_store
            .as_ref()
            .and_then(|es| es.fetch_event_by_id(q.id))
    });
    let Some(ev) = ev else {
        return error_response(StatusCode::NOT_FOUND, "event_not_found");
    };
    let Some(es) = &state.event_store else {
        return error_response(StatusCode::NOT_FOUND, "trace_not_available");
    };
    let cfg = state.config.get();
    if cfg.full_trace_count == 0 || !crate::config::log_keeps_credential_plaintext(&cfg) {
        return error_response(StatusCode::NOT_FOUND, "trace_disabled");
    }
    let es = es.clone();
    let sid = ev.session_id.clone();
    let ev_for_render = ev.clone();
    // 最多要读 4 侧 × 单侧上限（默认 1MiB）并拼成一个大 String：放到阻塞池里做，
    // 不要压在 tokio worker 上（同进程还扛着代理转发）。
    let rendered = tokio::task::spawn_blocking(move || {
        es.fetch_trace(&sid)
            .map(|t| render_trace_text(&ev_for_render, &t))
    })
    .await
    .ok()
    .flatten();
    let Some(body) = rendered else {
        return error_response(StatusCode::NOT_FOUND, "trace_not_available");
    };
    let filename = format!("maskit-trace-{}.txt", ev.id);
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

/// Unix 秒 → `YYYY-MM-DD HH:MM:SS UTC`（仅用于导出文件的抬头）。
///
/// 项目没有 chrono 依赖，也不想为一行日志引入；这里用 Howard Hinnant 的
/// civil-from-days 算法手算（无时区库，统一标 UTC，避免「本地时间但没写时区」的歧义）。
fn fmt_utc(ts: f64) -> String {
    if !ts.is_finite() || ts < 0.0 {
        return "（时间未知）".into();
    }
    // 上限 9999-12-31：再大就没有展示意义，且 `z + 719_468` 会溢出 i64
    const MAX_TS: f64 = 253_402_300_799.0;
    if ts > MAX_TS {
        return "（时间超出可表示范围）".into();
    }
    let secs = ts as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 自 1970-01-01 起的天数 → `(年, 月, 日)`。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 把一组完整报文渲染成可读文本（分 4 节，便于贴进 issue / 邮件）。
fn render_trace_text(
    ev: &crate::store::events::Event,
    t: &crate::store::trace::TraceView,
) -> String {
    fn section(
        out: &mut String,
        idx: usize,
        title: &str,
        bytes: usize,
        truncated: bool,
        text: &str,
    ) {
        out.push_str(&format!(
            "\n═══ {idx}/4 {title} ═══  {} bytes{}\n\n",
            bytes,
            if truncated { "（已截断）" } else { "" }
        ));
        out.push_str(if text.is_empty() { "（空）" } else { text });
        out.push('\n');
    }

    let mut out = String::new();
    out.push_str("Maskit-RS 完整报文诊断\n");
    out.push_str("⚠ 本文件是诊断用的原始字节，可能含凭据 / PII 明文");
    out.push_str(
        "（取决于 mask.log_credential_plaintext）。请勿外发、贴进公开 issue 或提交到仓库。\n",
    );
    out.push_str(&format!(
        "事件 #{} · {} · {} {}\n",
        ev.id,
        fmt_utc(ev.ts),
        ev.method,
        ev.path
    ));
    out.push_str(&format!(
        "会话 sid={} · 协议 {} · 模型 {}\n",
        if ev.session_id.is_empty() {
            "（无）"
        } else {
            &ev.session_id
        },
        if ev.protocol.is_empty() {
            "unknown"
        } else {
            &ev.protocol
        },
        if ev.model.is_empty() {
            "（未知）"
        } else {
            &ev.model
        }
    ));
    section(
        &mut out,
        1,
        "原始请求（客户端发出）",
        t.req_bytes,
        t.req_truncated,
        &t.req_raw,
    );
    section(
        &mut out,
        2,
        "发给上游（已脱敏）",
        t.req_masked_bytes,
        t.req_truncated,
        &t.req_masked,
    );
    section(
        &mut out,
        3,
        "上游原始响应（占位符原样）",
        t.resp_bytes,
        t.resp_truncated,
        &t.resp_raw,
    );
    section(
        &mut out,
        4,
        "返回客户端（还原后）",
        t.resp_out_bytes,
        t.resp_truncated,
        &t.resp_out,
    );
    if t.unresolved > 0 {
        out.push_str(&format!(
            "\n⚠ 未还原占位符 {} 处：{}\n",
            t.unresolved,
            if t.unresolved_samples.is_empty() {
                "（无样本）".to_string()
            } else {
                t.unresolved_samples.join("、")
            }
        ));
    }
    out
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
///
/// **接筛选参数**：早期实现写死 `fetch_events(2000, 0)` —— 用户筛了「只看 MASK」
/// 再导出，拿到的却是全量；而且超过 2000 条静默截断，没有任何提示。
/// 现在按当前筛选导出，截断时回 `X-Maskit-Truncated: true` 并在 JSON 里标 `truncated`。
///
/// **内存上限**：单条事件最坏可有 ~80KB（两段 8000 字符 dialog + 16KiB 请求头 +
/// 30 条明细），5000 条能到数百 MB。这里按**序列化后的字节预算**（32MiB）边生成边
/// 截断，而不是先攒 `Vec<Value>` 再整体序列化（那会同时持有三份内存）。
pub async fn export_logs(State(state): State<SharedState>, Query(q): Query<LogsQuery>) -> Response {
    const EXPORT_MAX: usize = 5000;
    const EXPORT_MAX_BYTES: usize = 32 * 1024 * 1024;
    let etype = q.event_type.as_deref();
    let search = q.q.as_deref();
    let (events, total) = match &state.event_store {
        Some(es) => es.fetch_events_page(EXPORT_MAX, 0, etype, search),
        None => {
            let rows = state.bus.recent_filtered(EXPORT_MAX, etype, search);
            let n = rows.len();
            (rows, n)
        }
    };
    let mut arr: Vec<u8> = Vec::new();
    arr.push(b'[');
    let mut used = 0usize;
    let mut first = true;
    let mut budget_hit = false;
    for e in events {
        let mut v = serde_json::to_value(&e).unwrap_or(Value::Null);
        if let Some(obj) = v.as_object_mut() {
            obj.remove("dialog");
            obj.remove("req_preview");
            obj.remove("resp_preview");
            // 请求头同样属原文类：含 `authorization`/`cookie` 等，导出恒脱敏
            // （默认 `log_credential_plaintext=true` 时它们本就是明文）。
            obj.remove("request_headers");
            if let Some(items) = obj.get_mut("items").and_then(|i| i.as_array_mut()) {
                for it in items.iter_mut() {
                    if let Some(o) = it.as_object_mut() {
                        o.remove("original");
                    }
                }
            }
            obj.insert("masked_export".into(), Value::Bool(true));
        }
        let Ok(bytes) = serde_json::to_vec(&v) else {
            continue;
        };
        if used + bytes.len() > EXPORT_MAX_BYTES {
            budget_hit = true;
            break;
        }
        if !first {
            arr.push(b',');
        }
        arr.extend_from_slice(&bytes);
        used += bytes.len();
        first = false;
    }
    arr.push(b']');
    // 截断 = 命中条数上限（total 比取到的多），或命中字节预算。
    // 注意不能写成 `total > events.len()`：那是拿「筛掉坏行后的实际行数」去比，
    // 库里只要有一条坏 payload 就会恒为真，误报「已截断」。
    let truncated = budget_hit || total > EXPORT_MAX;
    let head = format!(
        "{{\"ok\":true,\"masked_export\":true,\"total\":{total},\"truncated\":{truncated},\"events\":"
    );
    let mut body = Vec::with_capacity(head.len() + arr.len() + 1);
    body.extend_from_slice(head.as_bytes());
    body.extend_from_slice(&arr);
    body.push(b'}');
    let mut resp = (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response();
    if truncated {
        resp.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-maskit-truncated"),
            axum::http::HeaderValue::from_static("true"),
        );
    }
    resp
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

/// 脱敏测试（**完全隔离**：不写全局映射、不落 SQLite）。
///
/// 与 \`demo/mask\` 的关键区别：这里用**局部** \`SessionStore\`，而 demo 复用全局
/// \`STORE\` —— 后者即使结尾 \`drop_session\`，\`recall_token\` 写入的
/// \`recent_fwd\`/\`recent_rev\` 是跨会话全局缓存，不会被 drop，测试会把占位符
/// 污染进生产映射。局部 store 在函数返回时整体析构，天然零残留。
pub async fn mask_test(State(state): State<SharedState>, body: String) -> Response {
    let req: Value = serde_json::from_str(&body).unwrap_or(json!({}));
    let text = req.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let mode = req.get("mode").and_then(|v| v.as_str()).unwrap_or("text");
    let protocol = req
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("chat_completions");
    let model = req
        .get("model")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("gpt-4o");
    if text.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "请输入待测试文本");
    }

    // ── 隔离：局部 store，全程不接触 state.sessions（全局 STORE）──
    let store = crate::mask::session::SessionStore::new();
    let sid = "mask-test";
    store.new_session(sid);
    let custom = state.custom_words();
    let cfg = state.config.get();
    custom.register_words(&store);

    let t0 = std::time::Instant::now();
    let (masked, restored) = if mode == "request" {
        // 完整请求体模式：走真实网关管线 mask_body，展示**发给上游的完整 body**
        let wrapped = wrap_request(protocol, model, text);
        let raw = wrapped.as_bytes();
        let ctx = crate::mask::engine::MaskCtx::new(&cfg, &store, sid.into(), &custom);
        match crate::mask::tree::mask_body(raw, &ctx) {
            Ok(body) => {
                let masked = body.text.clone();
                let mut st = crate::mask::engine::RestoreStats::default();
                let back = crate::mask::tree::restore_tree(
                    &serde_json::from_str::<Value>(&masked).unwrap_or(Value::Null),
                    sid,
                    &store,
                    &mut st,
                    0,
                );
                let pretty = serde_json::to_string_pretty(&back).unwrap_or_else(|_| masked.clone());
                (masked, pretty)
            }
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("构造请求体失败: {e}"))
            }
        }
    } else {
        let ctx = crate::mask::engine::MaskCtx::new(&cfg, &store, sid.into(), &custom);
        let masked = ctx.mask(text);
        let mut st = crate::mask::engine::RestoreStats::default();
        let back = crate::mask::engine::restore_final(&masked, sid, false, &store, &mut st);
        (masked, back)
    };
    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    let items = crate::server::proxy::build_event_items(&store, sid, true);
    let count = items.len();
    json_response(
        StatusCode::OK,
        &json!({
            "ok": true,
            "mode": mode,
            "masked": masked,
            "restored": restored,
            "count": count,
            "items": items,
            "elapsed_ms": (elapsed * 10.0).round() / 10.0,
            "isolated": true,
        }),
    )
    // 注意：局部 `store` 在此析构，全部映射随之消失；也不调用 save_mappings。
}

/// 把待测文本包成各协议的请求体，用于跑完整管线。
fn wrap_request(protocol: &str, model: &str, text: &str) -> String {
    match protocol {
        "responses" => json!({
            "model": model, "stream": false,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": text}]}]
        })
        .to_string(),
        "anthropic" => json!({
            "model": model, "max_tokens": 1024,
            "messages": [{"role": "user", "content": text}]
        })
        .to_string(),
        _ => json!({
            "model": model,
            "messages": [
                {"role": "system", "content": "你是一个helpful助手"},
                {"role": "user", "content": text}
            ]
        })
        .to_string(),
    }
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
