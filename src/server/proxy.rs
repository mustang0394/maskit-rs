//! 反代管线：请求侧完整流程 + fail-closed 判定矩阵（PLAN §2.2）。
//!
//! **总原则（D6）**：是否脱敏只由三个事实决定 —— 请求是否落在已配置的上游路由上、
//! `fail_closed`、body 能否被解析。`detect_protocol` 只决定「用哪套解析/还原通道 +
//! 哪套路径感知豁免表」，**不决定是否脱敏**。

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use bytes::Bytes;

use crate::config::ConfigCenter;
use crate::detect::{self, Protocol};
use crate::error::ErrorKind;
use crate::mask::engine::{CustomWords, MaskCtx};
use crate::mask::session::SessionStore;
use crate::mask::tree;
use crate::server::{error_response, SharedState};
use crate::store::events::{Event, EventBus, EventItem, EventType};

/// 只读方法（对齐 Python `_READONLY_METHODS`：不含 DELETE）。
fn is_readonly(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

/// content-type 是否声明 JSON。
fn is_json_ct(ct: &str) -> bool {
    ct.to_ascii_lowercase().contains("json")
}

/// 管线共享上下文（每次请求构造一次）。
pub struct Pipeline {
    pub config: std::sync::Arc<ConfigCenter>,
    pub bus: std::sync::Arc<EventBus>,
    pub store: &'static SessionStore,
    pub custom: std::sync::Arc<CustomWords>,
}

/// 事件构建辅助。
#[allow(clippy::too_many_arguments)]
fn emit(
    bus: &EventBus,
    event_type: EventType,
    method: &str,
    path: &str,
    status: u16,
    reason: &str,
    protocol: Protocol,
    model: &str,
    sid: &str,
    source: &RequestMeta,
) -> u64 {
    let ev = Event {
        id: 0,
        ts: 0.0,
        event_type,
        method: method.into(),
        path: path.into(),
        status,
        reason: reason.into(),
        protocol: protocol.as_str().into(),
        model: model.into(),
        session_id: sid.into(),
        mask_ms: None,
        first_byte_ms: None,
        upstream_ms: None,
        req_bytes: source.req_bytes,
        resp_bytes: 0,
        items: vec![],
        new_count: 0,
        reused_count: 0,
        unresolved: 0,
        unresolved_samples: vec![],
        unknown_shape: source.unknown_shape,
        message: source.message.clone(),
        ..Default::default()
    };
    let ev = bus.emit(ev);
    ev.id
}

/// 请求元信息（事件用）。
#[derive(Default, Clone)]
pub struct RequestMeta {
    pub req_bytes: usize,
    pub unknown_shape: bool,
    pub message: String,
    pub body_shape: Option<String>,
}

/// 反代 handler（完整管线，M6）。
/// 根路径 `/` 的代理入口（上游已配置时，`/` 属于上游资源，不劫持）。
pub async fn proxy_root(state: SharedState) -> Response {
    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .expect("build GET /");
    handler(State(state), req).await
}

pub async fn handler(State(state): State<SharedState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let method_str = method.as_str().to_string();
    let path = parts.uri.path().to_string();

    // ── 判定①：上游未配置 → 502（新单上游模型下等价 Python 的 no_reverse_route） ──
    let cfg = state.config.get();
    if cfg.upstream.target.is_empty() {
        let bus = state.bus.clone();
        emit(
            &bus,
            EventType::Block,
            &method_str,
            &path,
            502,
            "no_reverse_route",
            Protocol::Unknown,
            "",
            "",
            &RequestMeta::default(),
        );
        return error_response(StatusCode::BAD_GATEWAY, "no_reverse_route");
    }

    let max_body = state.config.max_body_bytes();

    // ── 判定⑥：读 body（超限一律 413，不看 fail_closed 与协议形态） ──
    let body_bytes = match axum::body::to_bytes(body, max_body).await {
        Ok(b) => b,
        Err(_) => {
            emit(
                &state.bus,
                EventType::Block,
                &method_str,
                &path,
                413,
                "request_too_large",
                Protocol::Unknown,
                "",
                "",
                &RequestMeta {
                    req_bytes: max_body,
                    ..Default::default()
                },
            );
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
        }
    };
    let req_bytes = body_bytes.len();

    // ── 判定②：只读方法直接转发（无请求体，无需脱敏） ──
    if is_readonly(&method) {
        let bus = state.bus.clone();
        emit(
            &bus,
            EventType::Pass,
            &method_str,
            &path,
            0,
            "readonly_method",
            Protocol::Unknown,
            "",
            "",
            &RequestMeta {
                req_bytes,
                ..Default::default()
            },
        );
        return forward_raw(&state, &method_str, &parts.uri, &parts.headers, body_bytes).await;
    }

    // ── 判定③：脱敏暂停 → 纯透传（记 BYPASS；暂停语义完整，不做任何 fail-closed 阻断） ──
    if state.config.paused() || !cfg.mask.enabled {
        let bus = state.bus.clone();
        emit(
            &bus,
            EventType::Bypass,
            &method_str,
            &path,
            0,
            "filter_disabled",
            Protocol::Unknown,
            "",
            "",
            &RequestMeta {
                req_bytes,
                ..Default::default()
            },
        );
        // 流式请求声明 identity（对齐 Python：避免压缩导致流式退化）
        let mut headers = parts.headers.clone();
        inject_identity_for_stream(&mut headers, &body_bytes);
        return forward_raw(&state, &method_str, &parts.uri, &headers, body_bytes).await;
    }

    let fail_closed = state.config.fail_closed();
    let ct = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // ── 判定④：声明非 JSON ──
    if !is_json_ct(&ct) {
        if fail_closed {
            emit(
                &state.bus,
                EventType::Block,
                &method_str,
                &path,
                503,
                "non_json_body",
                Protocol::Unknown,
                "",
                "",
                &RequestMeta {
                    req_bytes,
                    message: ct.chars().take(80).collect(),
                    ..Default::default()
                },
            );
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "non_json_body");
        }
        emit(
            &state.bus,
            EventType::Bypass,
            &method_str,
            &path,
            0,
            "non_json_body",
            Protocol::Unknown,
            "",
            "",
            &RequestMeta {
                req_bytes,
                ..Default::default()
            },
        );
        return forward_raw(&state, &method_str, &parts.uri, &parts.headers, body_bytes).await;
    }

    // ── 判定⑤：JSON 解析失败 ──
    let text = String::from_utf8_lossy(&body_bytes).to_string();
    let parsed = tree::load_json_pairs(&text);
    let Some(parsed) = parsed else {
        if fail_closed {
            emit(
                &state.bus,
                EventType::Block,
                &method_str,
                &path,
                400,
                "invalid_json",
                Protocol::Unknown,
                "",
                "",
                &RequestMeta {
                    req_bytes,
                    ..Default::default()
                },
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid_json");
        }
        emit(
            &state.bus,
            EventType::Bypass,
            &method_str,
            &path,
            0,
            "invalid_json",
            Protocol::Unknown,
            "",
            "",
            &RequestMeta {
                req_bytes,
                ..Default::default()
            },
        );
        return forward_raw(&state, &method_str, &parts.uri, &parts.headers, body_bytes).await;
    };

    // ── 判定⑦：协议探测（只选通道，不 gate 脱敏） ──
    let protocol = detect::detect_protocol(&path, Some(&parsed.value));
    let model = tree::extract_model(&parsed.value);
    let is_llm_shape = protocol != Protocol::Unknown;

    // 已路由 + 形态未知 + fail_closed=false → 透传
    if !is_llm_shape && !fail_closed {
        emit(
            &state.bus,
            EventType::Bypass,
            &method_str,
            &path,
            0,
            "non_llm_json",
            protocol,
            &model,
            "",
            &RequestMeta {
                req_bytes,
                ..Default::default()
            },
        );
        return forward_raw(&state, &method_str, &parts.uri, &parts.headers, body_bytes).await;
    }

    // ── 走脱敏管线（spawn_blocking：CPU 密集不阻塞 IO 线程） ──
    let sid = make_session_id(&parts.headers, &parsed.value);
    let store = state.sessions;
    store.new_session(&sid);
    if let Some(mut s) = store.get_mut(&sid) {
        s.model = model.clone();
        s.stream_mode = if detect::is_stream_request(Some(&parsed.value)) {
            "stream".into()
        } else {
            "non_stream".into()
        };
        s.inflight = true;
    }

    let custom = state.custom_words();
    let config = state.config.clone();
    let raw = body_bytes.clone();
    let sid2 = sid.clone();
    let unknown_shape = !is_llm_shape;
    let mask_t0 = std::time::Instant::now();
    let mask_result = tokio::task::spawn_blocking(move || {
        let cfg_ref = config.get();
        let ctx = MaskCtx::new(&cfg_ref, store, sid2.clone(), &custom);
        // 事件日志 dialog：与遮蔽同一次解析里抽出**原始**对话文本，
        // 避免为了拿全文再解一遍 JSON。
        let dialog = extract_dialog_from_raw(&raw);
        tree::mask_body(&raw, &ctx).map(|b| {
            // 同样抽一份**脱敏后**的对话文本 = 真正发给上游的内容，
            // 供控制台做「原文 / 发给上游」对照。
            let masked_dialog = extract_dialog_from_raw(b.text.as_bytes());
            (b, dialog, masked_dialog)
        })
    })
    .await;

    let (masked, req_dialog, req_masked_dialog) = match mask_result {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => {
            // ── 判定⑨：脱敏抛异常 → 503（与协议无关） ──
            store.drop_session(&sid);
            let bus = state.bus.clone();
            emit(
                &bus,
                EventType::Block,
                &method_str,
                &path,
                503,
                "mask_pipeline_failed",
                protocol,
                &model,
                &sid,
                &RequestMeta {
                    req_bytes,
                    message: e.chars().take(200).collect(),
                    ..Default::default()
                },
            );
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "shield_mask_failed");
        }
        Err(e) => {
            store.drop_session(&sid);
            emit(
                &state.bus,
                EventType::Err,
                &method_str,
                &path,
                503,
                "mask_join_failed",
                protocol,
                &model,
                &sid,
                &RequestMeta {
                    req_bytes,
                    message: e.to_string(),
                    ..Default::default()
                },
            );
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "shield_mask_failed");
        }
    };
    let mask_ms = mask_t0.elapsed().as_secs_f64() * 1000.0;

    // MASK 事件（含命中明细 + 用户消息原文）
    let keep_plaintext = crate::config::log_keeps_credential_plaintext(&state.config.get());
    let items = build_event_items(store, &sid, keep_plaintext);
    let new_count = store.get(&sid).map(|s| s.new_orig.len()).unwrap_or(0);
    let mut ev_meta = RequestMeta {
        req_bytes,
        unknown_shape,
        ..Default::default()
    };
    ev_meta.body_shape = masked.body_shape.map(str::to_string);
    let ev = Event {
        id: 0,
        ts: 0.0,
        event_type: EventType::Mask,
        method: method_str.clone(),
        path: path.clone(),
        status: 0,
        reason: String::new(),
        protocol: protocol.as_str().into(),
        model: model.clone(),
        session_id: sid.clone(),
        mask_ms: Some((mask_ms * 10.0).round() / 10.0),
        first_byte_ms: None,
        upstream_ms: None,
        req_bytes,
        resp_bytes: 0,
        // 关掉 `log_credential_plaintext` 时，凭据原文也不能从 `dialog` 漏出去
        // （此前只清了 `items[].original`，dialog 仍存全文明文 → 与文档承诺不符）。
        dialog: if keep_plaintext {
            req_dialog.clone()
        } else {
            crate::server::response::redact_credentials(&req_dialog)
        },
        // 脱敏后的文本本身已用占位符替代了敏感值，无需再洗
        masked_dialog: req_masked_dialog.clone(),
        items,
        count: new_count.max(store.get(&sid).map(|s| s.last_hits.len()).unwrap_or(0)),
        masked_total: store.get(&sid).map(|s| s.fwd.len()).unwrap_or(0),
        new_count,
        reused_count: 0,
        unresolved: 0,
        unresolved_samples: vec![],
        unknown_shape,
        message: String::new(),
        ..Default::default()
    };
    if let Some(mut s) = store.get_mut(&sid) {
        s.mask_ms = mask_ms;
    }
    // 落库交给总线内部的钩子（赋 id 之后），这里只负责发事件
    state.bus.emit(ev);

    // 映射落盘（随机后缀 → 原文）：保证进程重启后历史占位符仍可还原。
    // **必须无条件 drain**：否则事件库不可用时该集合永不回收，会泄漏。
    // 落盘本身是非阻塞入队（写线程异步执行），不影响本请求延迟。
    let pending = state.sessions.drain_pending_persist(&sid);
    if !pending.is_empty() {
        if let Some(es) = &state.event_store {
            let ttl = state.config.get().mask.mapping_ttl;
            let n = es.save_mappings(&pending, ttl);
            tracing::debug!(count = n, "占位符映射已入队落盘");
        }
    }

    // 转发（脱敏后的 body）+ 响应侧还原
    let mut headers = parts.headers.clone();
    inject_identity_for_stream(&mut headers, &body_bytes);
    let out_body = Bytes::from(masked.text.clone().into_bytes());
    // 事件日志 dialog：从**原始**请求体抽对话文本（用户消息）。
    // 这是用户实际发出去的明文，与 items[].original 合起来构成可核对的对照。
    let sess = RestoreSession {
        sid: sid.clone(),
        protocol: protocol.as_str().to_string(),
        model: model.clone(),
        req_bytes,
        req_dialog,
    };
    forward_with_restore(&state, &method_str, &parts.uri, &headers, out_body, sess).await
}

/// 从原始请求体（未经脱敏）抽对话文本；非 JSON 或抽不出时回退截断预览。
fn extract_dialog_from_raw(raw: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(raw)
        .map(|v| crate::mask::tree::extract_dialog_text(&v))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            // 非 JSON：给前 512 字符，至少让详情页有东西可看
            let t = String::from_utf8_lossy(raw);
            t.chars().take(512).collect()
        })
}

/// 流式请求声明 identity（对齐 Python：压缩会让流式接管退化）。
fn inject_identity_for_stream(headers: &mut HeaderMap, body: &[u8]) {
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !is_json_ct(ct) {
        return;
    }
    // 请求体含 "stream":true → 声明 identity
    let text = String::from_utf8_lossy(body);
    if text.contains("\"stream\"") && text.contains("true") {
        headers.insert(
            "accept-encoding",
            axum::http::HeaderValue::from_static("identity"),
        );
    }
}

/// 会话键：`<SHA-256(client_ip + 首个 user 内容) 前 8 字节 hex>` + 每请求唯一后缀。
///
/// **为什么必须每请求唯一**（对齐 Python 版的 uuid4，而非纯确定性键）：
/// 会话槽位承载的是 per-request 状态 —— `fwd`/`rev`/`last_hits`、事件命中明细，
/// 以及**流式半截占位符的 `pending` 缓冲** —— 且请求（含流）结束即
/// `drop_session`（`pipeline_tests::stream_session_is_released` 守着不泄漏）。
/// 早先把它做成纯确定性键（`hash(ip + 首条 user)`）时，两个「同 IP + 同首条
/// user 消息」的并发请求（客户端重试／并行发送是常态）会：
///   * 共用同一槽位，后到的 `new_session` **清空**前者已登记的映射；
///   * 事件命中明细互相串号；
///   * 流式 `pending` 按协议槽位（content/arguments…）索引，两路互相污染；
///   * 先结束的一路 `drop_session` 把仍在跑的另一路的会话一起删掉
///     （`drain_pending_persist` 拿不到 → 映射丢失，违背「全部落盘」）。
///
/// 确定性键的唯一收益是「日志能把同一对话归组」，用**前缀**保留：
/// `session_id = <对话摘要>-<请求 nonce>`，同一对话仍可按前缀过滤；
/// 而跨请求的占位符一致性本来就由全局 `recent_fwd`/`recent_rev` 负责，不靠 sid。
fn make_session_id(headers: &HeaderMap, body: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
    {
        h.update(ip.trim().as_bytes());
    }
    if let Some(seed) = first_user_content(body) {
        h.update(seed.as_bytes());
    }
    let out = h.finalize();
    let digest: String = out.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{digest}-{:08x}", rand::random::<u32>())
}

/// 取首个 user 内容作为会话键素材。
fn first_user_content(body: &serde_json::Value) -> Option<String> {
    let msgs = body.get("messages")?.as_array()?;
    for m in msgs {
        if m.get("role").and_then(|r| r.as_str()) == Some("user") {
            if let Some(c) = m.get("content") {
                return Some(c.to_string());
            }
        }
    }
    None
}

/// 构建 MASK 事件明细（凭据类只留 digest/preview）。
pub(crate) fn build_event_items(
    store: &SessionStore,
    sid: &str,
    keep_plaintext: bool,
) -> Vec<EventItem> {
    let Some(s) = store.get(sid) else {
        return vec![];
    };
    let mut items = Vec::new();
    let mut ordered: Vec<&String> = s
        .last_hits
        .iter()
        .filter(|o| s.fwd.contains_key(*o))
        .collect();
    ordered.sort();
    let mut rest: Vec<&String> = s.fwd.keys().filter(|o| !s.last_hits.contains(*o)).collect();
    rest.sort();
    ordered.extend(rest);
    for orig in ordered.into_iter().take(30) {
        let Some(token) = s.fwd.get(orig) else {
            continue;
        };
        let label = s.labels.get(orig).cloned().unwrap_or_default();
        let cred = crate::config::is_credential_label(&label);
        let mut item = EventItem {
            label: label.clone(),
            token: token.clone(),
            original: String::new(),
            cred,
            digest: String::new(),
            preview: crate::mask::engine::preview(orig, &label),
            length: orig.chars().count(),
            hash: crate::mask::placeholder::token_suffix(token),
            restored: false,
        };
        // 日志是否保留凭据明文由 mask.log_credential_plaintext 决定（默认全留）。
        // 摘要始终计算：即使有明文，sha256 仍是跨库/跨天的同一性对照。
        if cred {
            item.digest = crate::mask::validators::cred_digest(orig);
        }
        if keep_plaintext || !cred {
            item.original = orig.clone();
        }
        items.push(item);
    }
    items
}

/// 原样转发（无会话：只读方法/暂停/透传路径）。
async fn forward_raw(
    state: &SharedState,
    method: &str,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    forward_inner(state, method, uri, headers, body, None).await
}

/// 转发 + 响应侧还原（有会话时）。
#[allow(clippy::too_many_arguments)]
async fn forward_with_restore(
    state: &SharedState,
    method: &str,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: Bytes,
    session: RestoreSession,
) -> Response {
    forward_inner(state, method, uri, headers, body, Some(session)).await
}

/// 响应还原所需的会话上下文。
#[derive(Clone)]
pub struct RestoreSession {
    pub sid: String,
    pub protocol: String,
    pub model: String,
    pub req_bytes: usize,
    pub req_dialog: String,
}

async fn forward_inner(
    state: &SharedState,
    method: &str,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: Bytes,
    session: Option<RestoreSession>,
) -> Response {
    let fwd = crate::upstream::http_client::forward_headers(headers);
    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let upstream = state.upstream();
    // 会话必须在**所有**退出路径上释放。
    //
    // 回归：请求开始时会话被置为 `inflight = true`（防空窗被 sweep 误删），而
    // `sweep` 会**跳过** inflight 会话 —— 所以一旦某条离开路径忘了 drop，
    // 那个槽位就**永久**留在 `sessions` 里。上游不可达（连接被拒）是最常见的
    // 触发场景：实测打 12 次即残留 12 个会话，长时间跑就是无界内存泄漏。
    let release = |sess: &Option<RestoreSession>| {
        if let Some(s) = sess {
            state.sessions.drop_session(&s.sid);
        }
    };
    let req = match upstream.build_request(method, path_and_query, &fwd, body) {
        Ok(r) => r,
        Err(e) => {
            release(&session);
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream_build_failed: {e}"),
            );
        }
    };
    match upstream.send(req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = crate::upstream::http_client::forward_headers(resp.headers());
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let enc = resp
                .headers()
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            // 有会话 + 响应可还原 → 走还原管线
            if let Some(sess) = session {
                let can_restore = crate::server::response::restorable(&ct, &enc);
                if can_restore {
                    let meta = crate::server::response::StreamMeta {
                        host: uri.host().unwrap_or("").to_string(),
                        method: method.to_string(),
                        path: uri.path().to_string(),
                        model: sess.model.clone(),
                        protocol: sess.protocol.clone(),
                        status: status.as_u16(),
                        req_bytes: sess.req_bytes,
                        req_dialog: sess.req_dialog.clone(),
                        resp_dialog: String::new(), // 流式由响应侧回填
                        keep_plaintext: crate::config::log_keeps_credential_plaintext(
                            &state.config.get(),
                        ),
                    };
                    let cmdblock = state.cmdblock();
                    let store: &'static crate::mask::session::SessionStore = state.sessions;
                    if crate::server::response::is_streaming_response(&ct) {
                        let framing = crate::server::response::framing_of(&ct)
                            .unwrap_or(crate::stream::sse::Framing::Sse);
                        let bus = state.bus.clone();
                        let out_body = crate::server::response::stream_response(
                            resp.into_body(),
                            framing,
                            sess.sid.clone(),
                            store,
                            cmdblock.clone(),
                            bus,
                            meta,
                        );
                        let mut out = Response::builder().status(status);
                        {
                            let h = out.headers_mut().unwrap();
                            for (k, v) in resp_headers {
                                if let Some(name) = k {
                                    // 还原后长度变化：移除 content-length，改 chunked
                                    if name.as_str().eq_ignore_ascii_case("content-length") {
                                        continue;
                                    }
                                    h.insert(name, v);
                                }
                            }
                        }
                        return out.body(out_body).unwrap();
                    }
                    // 非流式：聚合并还原
                    match crate::stream::sse::aggregate_stream(resp.into_body()).await {
                        Ok(bytes) => {
                            let outcome = crate::server::response::process_and_emit(
                                &bytes, &ct, &sess.sid, store, &cmdblock, &state.bus, &meta,
                            );
                            // RESTORE / 审计事件的落库已收束到总线钩子（见 `AppState::new`），
                            // 这里不再自己按 id 捡 ring 尾巴——那种写法既有竞态（并发请求
                            // 会捡错事件），又因为事件 id 尚未赋定而落库 id 恒为 0。
                            // token 用量落库（只统计数量）
                            if !outcome.usage.is_empty() {
                                if let Some(es) = &state.event_store {
                                    es.add_tokens(&sess.model, outcome.usage);
                                }
                            }
                            store.drop_session(&sess.sid);
                            let mut out = Response::builder().status(if outcome.blocked {
                                StatusCode::SERVICE_UNAVAILABLE
                            } else {
                                status
                            });
                            if outcome.blocked {
                                let body = serde_json::json!({
                                    "error": {"code": "shield_command_blocked",
                                              "reason": "dangerous_command_in_response"}
                                })
                                .to_string();
                                let h = out.headers_mut().unwrap();
                                h.insert("content-type", "application/json".parse().unwrap());
                                return out.body(Body::from(body)).unwrap();
                            }
                            {
                                let h = out.headers_mut().unwrap();
                                for (k, v) in resp_headers {
                                    if let Some(name) = k {
                                        if name.as_str().eq_ignore_ascii_case("content-length") {
                                            continue;
                                        }
                                        h.insert(name, v);
                                    }
                                }
                            }
                            return out.body(Body::from(outcome.body)).unwrap();
                        }
                        Err(e) => {
                            store.drop_session(&sess.sid);
                            return error_response(
                                StatusCode::BAD_GATEWAY,
                                &format!("upstream_read_failed: {e}"),
                            );
                        }
                    }
                }
                // 不可还原（压缩体等）：透传但清理会话
                state.sessions.drop_session(&sess.sid);
            }

            let chunks = crate::stream::sse::aggregate_stream(resp.into_body()).await;
            match chunks {
                Ok(bytes) => {
                    let mut out = Response::builder().status(status);
                    {
                        let h = out.headers_mut().unwrap();
                        for (k, v) in resp_headers {
                            if let Some(name) = k {
                                h.insert(name, v);
                            }
                        }
                    }
                    out.body(Body::from(bytes)).unwrap()
                }
                Err(e) => error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("upstream_read_failed: {e}"),
                ),
            }
        }
        Err(e) => {
            release(&session);
            error_response(StatusCode::BAD_GATEWAY, &format!("upstream_failed: {e}"))
        }
    }
}

/// 事件原因码 → 是否 fail-closed 阻断（供测试断言）。
pub fn error_status_for(kind: ErrorKind) -> u16 {
    kind.status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn readonly_methods_exclude_delete() {
        assert!(is_readonly(&Method::GET));
        assert!(is_readonly(&Method::HEAD));
        assert!(is_readonly(&Method::OPTIONS));
        assert!(
            !is_readonly(&Method::DELETE),
            "DELETE 可带 body，必须走管线"
        );
    }

    #[test]
    fn json_content_type_detection() {
        assert!(is_json_ct("application/json"));
        assert!(is_json_ct("application/json; charset=utf-8"));
        assert!(is_json_ct("application/x-ndjson"));
        assert!(!is_json_ct("multipart/form-data"));
        assert!(!is_json_ct("text/plain"));
    }

    #[test]
    fn session_id_is_unique_per_request_but_groups_by_context() {
        let body = json!({"messages": [{"role": "user", "content": "hello"}]});
        let h = HeaderMap::new();
        let a = make_session_id(&h, &body);
        let b = make_session_id(&h, &body);
        // 同一对话上下文：摘要前缀相同 → 日志仍可按前缀归组
        let a_prefix = a.split('-').next().unwrap();
        let b_prefix = b.split('-').next().unwrap();
        assert_eq!(a_prefix, b_prefix);
        assert_eq!(a_prefix.len(), 16);
        // 但每请求唯一：并发/重试不会共用同一会话槽位
        assert_ne!(a, b, "每请求必须拿到独立会话槽位");
        assert_eq!(a.len(), 16 + 1 + 8);
        // 不同内容 → 不同摘要前缀
        let body2 = json!({"messages": [{"role": "user", "content": "other"}]});
        assert_ne!(
            a_prefix,
            make_session_id(&h, &body2).split('-').next().unwrap()
        );
    }

    #[test]
    fn identity_injection_only_for_stream_json() {
        let mut h = HeaderMap::new();
        h.insert("content-type", "application/json".parse().unwrap());
        inject_identity_for_stream(&mut h, br#"{"stream":true}"#);
        assert_eq!(h.get("accept-encoding").unwrap(), "identity");
        // 非流式不动
        let mut h2 = HeaderMap::new();
        h2.insert("content-type", "application/json".parse().unwrap());
        inject_identity_for_stream(&mut h2, br#"{"stream":false}"#);
        assert!(h2.get("accept-encoding").is_none());
        // 非 JSON 不动
        let mut h3 = HeaderMap::new();
        h3.insert("content-type", "multipart/form-data".parse().unwrap());
        inject_identity_for_stream(&mut h3, b"binary");
        assert!(h3.get("accept-encoding").is_none());
    }
}
