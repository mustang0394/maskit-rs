//! M10 退出标准：管理 API 端到端（鉴权 / Origin / 20 端点）+ 内嵌 UI 可达。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use maskit_rs::config::ConfigCenter;
use maskit_rs::server::{build_router, AppState};
use maskit_rs::store::db::EventStore;
use maskit_rs::store::events::EventBus;
use maskit_rs::upstream::UpstreamClient;
use std::sync::Arc;
use tower::ServiceExt;

struct Harness {
    state: Arc<AppState>,
    token: String,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let mut cfg = center.get();
        cfg.upstream.target = "https://api.example.com".into();
        center.update(cfg);
        let token = center.get().panel_token.clone();
        let upstream = Arc::new(UpstreamClient::new_or_placeholder(&center.get().upstream));
        let bus = EventBus::new();
        let store = EventStore::open(dir.path()).ok();
        let state = Arc::new(AppState::new(center, bus, upstream, store));
        Harness {
            state,
            token,
            _dir: dir,
        }
    }

    async fn req(
        &self,
        method: &str,
        path: &str,
        auth: bool,
        body: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let app = build_router(self.state.clone());
        let mut b = Request::builder().method(method).uri(path);
        if auth {
            b = b.header("authorization", format!("Bearer {}", self.token));
        }
        let body = match body {
            Some(s) => {
                b = b.header("content-type", "application/json");
                Body::from(s.to_string())
            }
            None => Body::empty(),
        };
        let resp = app.oneshot(b.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap_or_default()
            .to_vec();
        (status, bytes)
    }

    async fn json(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let (s, b) = self.req(method, path, true, body).await;
        (
            s,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
        )
    }
}

#[tokio::test]
async fn health_is_public_others_require_token() {
    let h = Harness::new();
    // health 免鉴权
    let (s, v) = h.json("GET", "/console/api/health", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["ok"], true);
    // 其他端点：无 token → 401
    let (s2, _) = h.req("GET", "/console/api/config", false, None).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    // 错 token → 401
    let app = build_router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/console/api/config")
                .header("authorization", "Bearer wrong-token-xxxxx")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // 正确 token → 200
    let (s3, _) = h.req("GET", "/console/api/config", true, None).await;
    assert_eq!(s3, StatusCode::OK);
}

#[tokio::test]
async fn x_panel_token_header_also_accepted() {
    let h = Harness::new();
    let app = build_router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/console/api/status")
                .header("x-panel-token", h.token.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn origin_check_rejects_cross_site_writes() {
    let h = Harness::new();
    // 跨站 Origin + 写方法 → 403
    let app = build_router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/api/proxy/pause")
                .header("authorization", format!("Bearer {}", h.token))
                .header("host", "127.0.0.1:18701")
                .header("origin", "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // 同源 → 放行
    let app2 = build_router(h.state.clone());
    let resp2 = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/api/proxy/pause")
                .header("authorization", format!("Bearer {}", h.token))
                .header("host", "127.0.0.1:18701")
                .header("origin", "http://127.0.0.1:18701")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    // 无 Origin（CLI 调用）→ 放行
    let app3 = build_router(h.state.clone());
    let resp3 = app3
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/api/proxy/resume")
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
}

#[tokio::test]
async fn all_console_endpoints_respond() {
    let h = Harness::new();
    let gets = [
        "/console/api/config",
        "/console/api/status",
        "/console/api/logs",
        "/console/api/stats/today",
        "/console/api/stats/history",
        "/console/api/audit/events",
        "/console/api/data-dir",
        "/console/api/health",
    ];
    for p in gets {
        let (s, _) = h.req("GET", p, true, None).await;
        assert_eq!(s, StatusCode::OK, "GET {p}");
    }
    let posts: [(&str, Option<&str>); 6] = [
        ("/console/api/proxy/pause", None),
        ("/console/api/proxy/resume", None),
        ("/console/api/logs/clear", None),
        ("/console/api/audit/clear", None),
        ("/console/api/upstream/test", None),
        (
            "/console/api/config/patch",
            Some(r#"{"path":"mask.session_ttl","value":900}"#),
        ),
    ];
    for (p, b) in posts {
        let (s, _) = h.req("POST", p, true, b).await;
        assert_eq!(s, StatusCode::OK, "POST {p}");
    }
    // 演示脱敏
    let (s, v) = h
        .json(
            "POST",
            "/console/api/demo/mask",
            Some(r#"{"text":"电话13800138000"}"#),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!v["masked"].as_str().unwrap().contains("13800138000"));
    assert_eq!(v["restored"], "电话13800138000");
}

#[tokio::test]
async fn config_patch_and_toggle_persist() {
    let h = Harness::new();
    let (s, v) = h
        .json(
            "POST",
            "/console/api/config/patch",
            Some(r#"{"path":"mask.custom_words.张三","value":"人名"}"#),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["config"]["mask"]["custom_words"]["张三"], "人名");
    // 规则开关
    let (s2, v2) = h
        .json(
            "POST",
            "/console/api/config/patch",
            Some(r#"{"path":"mask.builtin_rules.JWT","value":true}"#),
        )
        .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(v2["config"]["mask"]["builtin_rules"]["JWT"], true);
    // 读回确认
    let (_, cfg) = h.json("GET", "/console/api/config", None).await;
    assert_eq!(cfg["mask"]["custom_words"]["张三"], "人名");
    // 持久化：新开一个 ConfigCenter 读同一目录
    let (center2, _) = ConfigCenter::load_or_init(h.state.config.data_dir()).unwrap();
    assert_eq!(center2.get().mask.custom_words["张三"], "人名");
}

#[tokio::test]
async fn token_rotation_and_old_token_rejected() {
    let h = Harness::new();
    let (s, v) = h.json("POST", "/console/api/rotate-token", None).await;
    assert_eq!(s, StatusCode::OK);
    let new_token = v["panel_token"].as_str().unwrap().to_string();
    assert_ne!(new_token, h.token);
    assert!(new_token.len() >= 16);
    // 旧 token 失效
    let app = build_router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/console/api/config")
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "旧令牌必须失效");
    // 新 token 可用
    let app2 = build_router(h.state.clone());
    let resp2 = app2
        .oneshot(
            Request::builder()
                .uri("/console/api/config")
                .header("authorization", format!("Bearer {new_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
}

#[tokio::test]
async fn embedded_ui_is_served() {
    let h = Harness::new();
    // HTML
    let (s, body) = h.req("GET", "/console", false, None).await;
    assert_eq!(s, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Maskit"), "内嵌 UI 必须可达");
    assert!(html.contains("/console/app.js"));
    assert!(html.contains("概览") && html.contains("设置"), "5 页 UI");
    // CSS
    let (s2, css) = h.req("GET", "/console/style.css", false, None).await;
    assert_eq!(s2, StatusCode::OK);
    assert!(String::from_utf8_lossy(&css).contains("--bg"));
    // JS
    let (s3, js) = h.req("GET", "/console/app.js", false, None).await;
    assert_eq!(s3, StatusCode::OK);
    let js = String::from_utf8_lossy(&js);
    assert!(js.contains("/console/api"), "JS 必须调用管理 API");
    assert!(js.contains("builtin_rules") && js.contains("custom_words"));
    // 未知静态资源 404
    let (s4, _) = h.req("GET", "/console/nope.txt", false, None).await;
    assert_eq!(s4, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn exported_logs_never_contain_plaintext() {
    let h = Harness::new();
    // 造一条带凭据与 PII 的事件
    let ev = maskit_rs::store::events::Event {
        event_type: maskit_rs::store::events::EventType::Mask,
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        dialog: "【用户】\n电话13800138000 key sk-abcdefghijklmnopqrstuvwxyz012345".into(),
        items: vec![
            maskit_rs::store::events::EventItem {
                label: "PHONE".into(),
                token: "{{PHONE_bcdfgh}}".into(),
                original: "13800138000".into(),
                cred: false,
                digest: String::new(),
                preview: "13****".into(),
                length: 11,
                hash: "bcdfgh".into(),
                restored: false,
            },
            maskit_rs::store::events::EventItem {
                label: "API_KEY".into(),
                token: "{{APIKEY_kkmmnp}}".into(),
                original: String::new(),
                cred: true,
                digest: "abcdef1234567890".into(),
                preview: "sk-1…2345".into(),
                length: 38,
                hash: "kkmmnp".into(),
                restored: false,
            },
        ],
        ..Default::default()
    };
    h.state.bus.emit(ev.clone());
    if let Some(es) = &h.state.event_store {
        es.enqueue(ev);
        std::thread::sleep(std::time::Duration::from_millis(700));
    }
    let (s, body) = h.req("GET", "/console/api/logs/export", true, None).await;
    assert_eq!(s, StatusCode::OK);
    let blob = String::from_utf8_lossy(&body);
    assert!(!blob.contains("13800138000"), "导出不得含 PII 原文");
    assert!(
        !blob.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
        "导出不得含凭据原文"
    );
    assert!(!blob.contains("\"original\""));
    assert!(!blob.contains("\"dialog\""));
    assert!(
        blob.contains("abcdef1234567890"),
        "摘要保留（可对照同一性）"
    );
    assert!(blob.contains("\"masked_export\":true"));
}

/// 回归：控制台改 upstream.target 必须**立即生效**（无需重启）。
/// 早期实现启动时创建 UpstreamClient 后不再重建 → 改了 target 仍打旧地址。
#[tokio::test]
async fn upstream_target_hot_reloads() {
    let h = Harness::new();
    // 初始指向 api.example.com（不该被真的请求到）
    let before = h.state.upstream().target.host.clone();
    assert_eq!(before, "api.example.com");
    // 改为本机 mock 上游
    let (s, _) = h
        .json(
            "POST",
            "/console/api/config/patch",
            Some(r#"{"path":"upstream.target","value":"http://127.0.0.1:18977"}"#),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let after = h.state.upstream().target.host.clone();
    assert_eq!(after, "127.0.0.1", "上游客户端必须热重载");
    assert_eq!(h.state.upstream().target.port, 18977);
    // 清空 target → 退化为占位客户端（请求 502，不崩溃）
    let (s2, _) = h
        .json(
            "POST",
            "/console/api/config/patch",
            Some(r#"{"path":"upstream.target","value":""}"#),
        )
        .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        h.state.upstream().target.port,
        9,
        "空 target 退化为占位（不可达）"
    );
}

#[tokio::test]
async fn security_headers_present() {
    let h = Harness::new();
    let app = build_router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
}

// ===========================================================================
// token 用量统计（只统计数量，无价格计算）
// ===========================================================================

#[tokio::test]
async fn token_usage_lands_in_daily_tokens() {
    let h = Harness::new();
    // 直接走 store 层：响应管线在 M7 接的是同一个 EventStore
    let es = h.state.event_store.clone().expect("event_store");
    es.add_tokens(
        "gpt-4o",
        maskit_rs::store::usage::Usage {
            prompt_tokens: 100,
            completion_tokens: 40,
        },
    );
    es.add_tokens(
        "gpt-4o",
        maskit_rs::store::usage::Usage {
            prompt_tokens: 20,
            completion_tokens: 5,
        },
    );
    es.add_tokens(
        "claude-sonnet-4",
        maskit_rs::store::usage::Usage {
            prompt_tokens: 7,
            completion_tokens: 3,
        },
    );
    // 空的 usage 不应写库
    es.add_tokens("gpt-4o", maskit_rs::store::usage::Usage::default());

    // /api/stats/models
    let (s, v) = h.json("GET", "/console/api/stats/models", None).await;
    assert_eq!(s, StatusCode::OK);
    let models = v["models"].as_array().expect("models 数组");
    assert_eq!(models.len(), 2, "空 usage 不应产生行");
    let gpt = models
        .iter()
        .find(|m| m["model"] == "gpt-4o")
        .expect("gpt-4o");
    assert_eq!(gpt["prompt_tokens"], 120, "同模型多次请求应累加");
    assert_eq!(gpt["completion_tokens"], 45);
    assert_eq!(gpt["total_tokens"], 165);
    let claude = models
        .iter()
        .find(|m| m["model"] == "claude-sonnet-4")
        .unwrap();
    assert_eq!(claude["total_tokens"], 10);

    // /api/stats/today 应带 token 汇总
    let (_, today) = h.json("GET", "/console/api/stats/today", None).await;
    assert_eq!(today["tokens_prompt"], 127);
    assert_eq!(today["tokens_completion"], 48);
    assert_eq!(today["tokens_total"], 175);
}

#[tokio::test]
async fn no_price_fields_anywhere_in_config() {
    // 用户要求：去掉价格计算。配置与接口都不应再出现价格概念。
    let h = Harness::new();
    let (_, cfg) = h.json("GET", "/console/api/config", None).await;
    let blob = serde_json::to_string(&cfg).unwrap().to_lowercase();
    for forbidden in ["price", "cost", "model_prices", "price_sync"] {
        assert!(
            !blob.contains(forbidden),
            "配置里不应残留价格相关字段：{forbidden}"
        );
    }
    let (_, st) = h.json("GET", "/console/api/stats/today", None).await;
    let blob = serde_json::to_string(&st).unwrap().to_lowercase();
    assert!(
        !blob.contains("price") && !blob.contains("cost"),
        "统计接口不应含价格字段"
    );
    // 审计配置也不再有主动探针位
    assert!(
        cfg["audit"].get("active_probes").is_none(),
        "主动探针配置位应已移除"
    );
}
