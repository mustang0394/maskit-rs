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

    /// 需要直接检查 SQLite 落盘时用（自带事件库）。
    /// 调用方需把 TempDir 的所有权交进来，以便跨请求保留。
    fn with_owned_dir(dir: tempfile::TempDir) -> Self {
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let mut cfg = center.get();
        cfg.upstream.target = "https://api.example.com".into();
        center.update(cfg);
        let token = center.get().panel_token.clone();
        let upstream = Arc::new(UpstreamClient::new_or_placeholder(&center.get().upstream));
        let bus = EventBus::new();
        let store = EventStore::open(dir.path()).unwrap();
        let state = Arc::new(AppState::new(center, bus, upstream, Some(store)));
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
    // HTML 文档必须带 CSP（纵深防御：控制台被注入时挡住凭据外发）
    let csp = resp
        .headers()
        .get("content-security-policy")
        .expect("HTML 响应必须有 CSP")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("script-src 'self'"),
        "CSP 必须限制脚本源：{csp}"
    );
    assert!(csp.contains("frame-ancestors 'none'"));
}

/// 控制台 API 的响应不得被缓存（含 panel_token 与日志原文）。
#[tokio::test]
async fn api_responses_are_not_cacheable() {
    let h = Harness::new();
    let app = build_router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/console/api/status")
                .header("authorization", format!("Bearer {}", h.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store",
        "/console/api/* 必须 no-store"
    );
}

/// 回归：`app.js` 必须整体包在**一个** IIFE 里。
///
/// 曾把 `})();` 提前闭合在「脱敏测试」段之前，后半段代码被甩到全局作用域，
/// 引用了 IIFE 内部的 `$`/`api`/`toast` → 脚本在加载期直接抛
/// `ReferenceError: $ is not defined`，测试页全部按钮失效。
/// 当时的 console_tests 只做「文本里包含某字符串」的断言，全绿通过。
#[tokio::test]
async fn app_js_is_a_single_iife() {
    let h = Harness::new();
    let (_, b) = h.req("GET", "/console/app.js", false, None).await;
    let js = String::from_utf8_lossy(&b);
    assert!(js.contains("(function () {"), "app.js 必须是 IIFE");
    assert_eq!(
        js.matches("})();").count(),
        1,
        "app.js 只能有一处 IIFE 闭合；提前闭合会把后续代码甩到全局作用域 → ReferenceError"
    );
    assert!(js.trim_end().ends_with("})();"), "IIFE 必须在文件末尾闭合");
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

// ── 自定义词批量录入 / 含 '.' 的词 / 删除 ─────────────────────────

/// 回归：Web UI 曾用 `{"path":"mask.custom_words.<词>"}` 逐词 patch。
/// 词含 `.`（如 example.com、Dr. Smith）会被点分切成多段，写成嵌套结构，
/// 导致 custom_words 的值类型从 string 变 object，匹配逻辑错乱。
/// 新增 `segs` 入口后键原样写入。
#[tokio::test]
async fn patch_segs_keeps_dotted_word_flat() {
    let h = Harness::new();
    for word in ["example.com", "Dr. Smith", "ACME/Inc"] {
        let body = serde_json::json!({
            "segs": ["mask", "custom_words", word],
            "value": "ORG"
        })
        .to_string();
        let (s, v) = h
            .json("POST", "/console/api/config/patch", Some(&body))
            .await;
        assert_eq!(s, StatusCode::OK, "词 {word:?} 应添加成功");
        assert_eq!(
            v["config"]["mask"]["custom_words"][word], "ORG",
            "词 {word:?} 应为扁平键"
        );
        assert!(
            v["config"]["mask"]["custom_words"][word].is_string(),
            "词 {word:?} 的值必须是字符串（不是嵌套对象）"
        );
    }
    // 切勿出现被切开的子键（GET /config 直接返回 Config 本体，无 config 包装）
    let (_, v) = h.json("GET", "/console/api/config", None).await;
    let cw = &v["mask"]["custom_words"];
    assert!(cw["example"].is_null(), "不应产生子键 example");
    assert!(cw["com"].is_null(), "不应产生子键 com");
    assert_eq!(cw.as_object().unwrap().len(), 3, "应恰好 3 个扁平键");
}

/// 批量录入：一次 patch 写入整张词表（UI 行为），含 '.' 的词不受影响。
#[tokio::test]
async fn batch_add_words_in_one_patch() {
    let h = Harness::new();
    let words = serde_json::json!({
        "张三": "PERSON", "李四": "PERSON", "王五": "PERSON", "example.com": "DOMAIN"
    });
    let body = serde_json::json!({
        "segs": ["mask", "custom_words"], "value": words
    })
    .to_string();
    let (s, v) = h
        .json("POST", "/console/api/config/patch", Some(&body))
        .await;
    assert_eq!(s, StatusCode::OK);
    let cw = &v["config"]["mask"]["custom_words"];
    // 一个分类下多个词 —— 数据模型原生支持
    assert_eq!(cw["张三"], "PERSON");
    assert_eq!(cw["李四"], "PERSON");
    assert_eq!(cw["王五"], "PERSON");
    assert_eq!(cw["example.com"], "DOMAIN");
    assert_eq!(cw.as_object().unwrap().len(), 4);
}

/// 删除单个词（含 '.' 的）：`value: null` = 删除键，不影响同类其他词。
#[tokio::test]
async fn delete_word_with_dot_keeps_others() {
    let h = Harness::new();
    let body = serde_json::json!({
        "segs": ["mask", "custom_words"],
        "value": {"example.com": "DOMAIN", "张三": "PERSON", "李四": "PERSON"}
    })
    .to_string();
    h.json("POST", "/console/api/config/patch", Some(&body))
        .await;
    // 删 example.com
    let del = serde_json::json!({
        "segs": ["mask", "custom_words", "example.com"], "value": null
    })
    .to_string();
    let (s, v) = h
        .json("POST", "/console/api/config/patch", Some(&del))
        .await;
    assert_eq!(s, StatusCode::OK);
    let cw = &v["config"]["mask"]["custom_words"];
    assert!(cw["example.com"].is_null(), "含 '.' 的词应被准确删除");
    assert_eq!(cw["张三"], "PERSON", "同分类其他词不受影响");
    assert_eq!(cw["李四"], "PERSON");
    assert_eq!(cw.as_object().unwrap().len(), 2);
}

/// segs 优先于 path；两者都空则报错而非静默写坏。
#[tokio::test]
async fn patch_rejects_empty_path() {
    let h = Harness::new();
    let (s, _) = h
        .json(
            "POST",
            "/console/api/config/patch",
            Some(r#"{"value":"X"}"#),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "空路径必须拒绝");
}

/// 回归：日志/审计的**主从双栏**必须齐全 —— 列表容器 + 详情容器 + 过滤/分页控件。
///
/// 历史：日志/审计表曾是**空壳 table**（`<table id="logList">` 里没有 thead），
/// JS 直接往 table 塞 `<tr><td>`，用户看到一堆无法解读的单元格。现在改成列表 +
/// 详情面板后，这类「渲染目标与容器对不上」的问题仍要用结构断言守住。
#[tokio::test]
async fn log_and_audit_split_panes_exist() {
    let h = Harness::new();
    let (s, body) = h.req("GET", "/console", false, None).await;
    assert_eq!(s, StatusCode::OK);
    let html = String::from_utf8_lossy(&body);
    for id in [
        "logList",
        "logDetail",
        "auditList",
        "auditDetail",
        "logType",
        "logSearch",
        "logPrev",
        "logNext",
        "auditSev",
        "auditSearch",
    ] {
        assert!(
            html.contains(&format!(r#"id="{id}""#)),
            "/console 缺少 #{id}"
        );
    }
    let js = {
        let (_, b) = h.req("GET", "/console/app.js", false, None).await;
        String::from_utf8_lossy(&b).to_string()
    };
    // 详情必须同时给出「原文」与「发给上游」两个对照面
    assert!(js.contains("原文（客户端发出）"), "详情缺原文面板");
    assert!(js.contains("发给上游（已脱敏）"), "详情缺「发给上游」面板");
    assert!(
        js.contains("masked_dialog"),
        "详情应使用 masked_dialog 字段"
    );
    // 老事件兜底：没有 masked_dialog 时按命中明细推算
    assert!(js.contains("按命中明细推算"), "缺老事件兜底");
    // 禁止再出现旧的裸 table 渲染目标
    assert!(
        !js.contains(r#"colspan="7""#),
        "不应再有 7 列表格渲染（已改为列表 + 详情）"
    );
}

/// 回归：日志明细必须同时展示**原文**与**占位符（加密后）**。
/// 之前 JS 只取 `it.preview`（打码预览），且字段名用错 —— 后端序列化成
/// `tok`（serde rename），JS 从未读取，两个关键值都不显示。
#[tokio::test]
async fn log_items_show_original_and_placeholder() {
    let h = Harness::new();
    let (_, b) = h.req("GET", "/console/app.js", false, None).await;
    let js = String::from_utf8_lossy(&b);
    // 必须读 tok（并兼容 token）
    assert!(
        js.contains("it.tok || it.token"),
        "渲染必须读取后端序列化的 tok 字段"
    );
    // 原文 / 占位符的对照列
    assert!(
        js.contains("cmp-orig") && js.contains("cmp-tok"),
        "缺少原文 → 占位符对照列"
    );
    // 原文不得被 preview 短路；凭据类才回退到打码预览
    assert!(js.contains("it.original"), "必须渲染原文");
    assert!(
        !js.contains("it.preview || it.original"),
        "原文不得被 preview 短路"
    );
    assert!(
        js.contains("凭据类不存明文"),
        "凭据类应显式说明无明文，而不是留空让人以为坏了"
    );
    // 详情视图要回源 /logs/detail
    assert!(js.contains("/logs/detail?id="), "详情视图必须回源单条事件");
    assert!(js.contains("logDetailHtml"), "详情渲染函数缺失");
    // 统计字段要真的渲染出来
    for f in ["e.count", "e.restored", "e.unresolved"] {
        assert!(js.contains(f), "统计字段 {f} 未被渲染");
    }
}

// ── 脱敏测试端点（隔离：零落库、零内存残留）─────────────────────

/// 测试占位符**绝不能**进入生产映射表。
///
/// 回归风险：旧 `demo/mask` 复用全局 `STORE`，结尾虽调 `drop_session`，但
/// `recall_token` 写入的 `recent_fwd`/`recent_rev` 是跨会话全局缓存，不会被
/// 清理 —— 测一次就把占位符污染进生产映射。新端点改用局部 store 规避。
#[tokio::test]
async fn mask_test_does_not_pollute_global_store() {
    let h = Harness::new();
    let store = h.state.sessions;
    let before_fwd = store.recent_fwd.len();
    let before_rev = store.recent_rev.len();

    let (s, v) = h
        .json(
            "POST",
            "/console/api/mask/test",
            Some(
                r#"{"text":"电话13800138000，邮箱zhangsan@example.com，key sk-abcdefghijklmnop"}"#,
            ),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let masked = v["masked"].as_str().unwrap();
    assert!(masked.contains("{{"), "应产出占位符：{masked}");
    assert!(!masked.contains("13800138000"), "原文不应残留：{masked}");
    assert_eq!(v["isolated"], true);
    assert!(v["count"].as_u64().unwrap() >= 3, "应命中 3 类");

    // 核心断言：全局映射表零增长
    assert_eq!(
        store.recent_fwd.len(),
        before_fwd,
        "测试不得写入全局 recent_fwd"
    );
    assert_eq!(
        store.recent_rev.len(),
        before_rev,
        "测试不得写入全局 recent_rev"
    );
    assert!(
        store.get("mask-test").is_none(),
        "不应在全局 store 留下测试会话"
    );
    // 跑 20 次仍不增长（防「第一次恰好没写」的假阴性）
    for _ in 0..20 {
        h.json(
            "POST",
            "/console/api/mask/test",
            Some(r#"{"text":"再测一次 13900139000"}"#),
        )
        .await;
    }
    assert_eq!(store.recent_fwd.len(), before_fwd, "重复测试仍不得污染");
    assert_eq!(store.recent_rev.len(), before_rev, "重复测试仍不得污染");
}

/// 测试结果不写 SQLite。
#[tokio::test]
async fn mask_test_writes_nothing_to_db() {
    let h = Harness::with_owned_dir(tempfile::tempdir().unwrap());
    for _ in 0..5 {
        h.json(
            "POST",
            "/console/api/mask/test",
            Some(r#"{"text":"电话13800138000"}"#),
        )
        .await;
    }
    h.state.event_store.as_ref().unwrap().sync();
    let es = h.state.event_store.as_ref().unwrap();
    assert_eq!(es.fetch_events(100, 0).len(), 0, "测试不应产生任何事件记录");
    assert_eq!(es.mappings_count(), 0, "测试不应写入映射表");
}

/// 纯文本模式：脱敏 + 还原往返一致。
#[tokio::test]
async fn mask_test_roundtrip_text_mode() {
    let h = Harness::new();
    let (_, v) = h
        .json(
            "POST",
            "/console/api/mask/test",
            Some(r#"{"text":"请联系张三，手机13800138000"}"#),
        )
        .await;
    let masked = v["masked"].as_str().unwrap();
    let restored = v["restored"].as_str().unwrap();
    assert!(masked.contains("{{"), "应脱敏：{masked}");
    assert_eq!(restored, "请联系张三，手机13800138000", "还原应完全一致");
    // 命中明细应含原文与占位符
    let items = v["items"].as_array().unwrap();
    assert!(!items.is_empty());
    let first = &items[0];
    assert!(first["tok"].is_string(), "明细须带占位符（tok）");
    assert!(first["label"].is_string());
}

/// 完整请求体模式：输出应是可直接发给上游的 JSON body。
#[tokio::test]
async fn mask_test_request_mode_emits_valid_json() {
    let h = Harness::new();
    for proto in ["chat_completions", "responses", "anthropic"] {
        let body = serde_json::json!({
            "text": "电话13800138000，邮箱zhangsan@example.com",
            "mode": "request", "protocol": proto
        })
        .to_string();
        let (s, v) = h.json("POST", "/console/api/mask/test", Some(&body)).await;
        assert_eq!(s, StatusCode::OK, "{proto}");
        let masked = v["masked"].as_str().unwrap();
        assert!(
            !masked.contains("13800138000"),
            "{proto} 原文残留：{masked}"
        );
        // 必须是合法 JSON（这就是「发给上游的内容」）
        let parsed: serde_json::Value = serde_json::from_str(masked)
            .unwrap_or_else(|e| panic!("{proto} 输出非合法 JSON: {e}\n{masked}"));
        assert!(parsed.get("model").is_some(), "{proto} 应保留 model 字段");
    }
}

/// 空输入应报 400。
#[tokio::test]
async fn mask_test_rejects_empty_text() {
    let h = Harness::new();
    let (s, _) = h
        .json("POST", "/console/api/mask/test", Some(r#"{"text":"  "}"#))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

/// 测试页必须在导航里，且「不落库」这一关键约束要写在界面上。
#[tokio::test]
async fn test_page_exists_and_declares_isolation() {
    let h = Harness::new();
    let (_, body) = h.req("GET", "/console", false, None).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains(r#"data-page="test""#), "导航缺少「测试」页签");
    assert!(html.contains(r#"id="page-test""#), "缺少测试页面");
    assert!(html.contains(r#"id="testInput""#) && html.contains(r#"id="testResult""#));
    assert!(html.contains(r#"id="btnRunTest""#));
    // 隔离承诺必须显式告知用户
    assert!(
        html.contains("不写入数据库") && html.contains("不进入内存映射"),
        "页面必须声明测试不落库、不进内存映射"
    );
    let (_, js) = h.req("GET", "/console/app.js", false, None).await;
    let js = String::from_utf8_lossy(&js);
    assert!(js.contains("/mask/test"), "前端必须调用隔离测试端点");
    assert!(js.contains("TEST_PRESETS"), "缺少示例文本");
}

/// 回归：落库事件的 id 必须非 0、详情必须可取回、且带「发给上游」的脱敏文本。
///
/// 早期调用方在 `bus.emit` **之前** enqueue（id 由 `emit` 内部才赋），于是
/// SQLite 里的事件 id 恒为 0：列表能看、点开必然 404，且所有行 id 相同。
/// 同时流式路径的 RESTORE 事件完全没人落库。
#[tokio::test]
async fn persisted_events_have_real_ids_and_masked_dialog() {
    let dir = tempfile::tempdir().unwrap();
    let h = Harness::with_owned_dir(dir);
    // 上游不可达（api.example.com），但 MASK 事件在转发**之前**就已产生
    let (status, _) = h
        .req(
            "POST",
            "/v1/chat/completions",
            false,
            Some(
                r#"{"model":"gpt-4o","messages":[{"role":"user","content":"我的电话是13800138000"}]}"#,
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    let es = h.state.event_store.as_ref().expect("自带事件库");
    es.sync(); // 屏障：确保已入队 == 已落盘

    let (events, total) = es.fetch_events_page(10, 0, Some("MASK"), None);
    assert!(total >= 1, "MASK 事件必须落库");
    let ev = &events[0];
    assert!(ev.id > 0, "落库事件 id 不得为 0（否则详情页点不开）");
    assert!(
        es.fetch_event_by_id(ev.id).is_some(),
        "按 id 必须能取回（详情页的 SQLite 兜底路径）"
    );
    // 「原文 / 发给上游」两份文本
    assert!(ev.dialog.contains("13800138000"), "原文必须保留");
    assert!(
        ev.masked_dialog.contains("{{PHONE_"),
        "必须带发给上游的脱敏文本：{:?}",
        ev.masked_dialog
    );
    assert!(
        !ev.masked_dialog.contains("13800138000"),
        "发给上游的文本里不得出现原文"
    );
    // 全文搜索（路径 / 原文两个维度）
    let (_, n) = es.fetch_events_page(10, 0, None, Some("13800138000"));
    assert!(n >= 1, "搜索应能命中原文");
    let (_, n2) = es.fetch_events_page(10, 0, None, Some("chat/completions"));
    assert!(n2 >= 1, "搜索应能命中路径");
    // 类型过滤
    let (_, n3) = es.fetch_events_page(10, 0, Some("RESTORE"), None);
    assert_eq!(n3, 0, "本次请求没有 RESTORE 事件");
}

/// 回归：审计事件 id 非 0，且每条 finding 只触发一次落库钩子。
///
/// 此前是「每个请求结束后把 ring 里最近 20 条重新 enqueue」，于是同一条审计
/// 会被反复写进 SQLite（N 个请求 → N 份重复行）。
#[test]
fn audit_hook_fires_once_per_finding_with_unique_ids() {
    use maskit_rs::audit::{Finding, Severity};
    use maskit_rs::store::events::{AuditEvent, EventBus};
    use std::sync::{Arc, Mutex};

    let bus = EventBus::new();
    let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(vec![]));
    let sink = seen.clone();
    bus.set_hooks(
        Arc::new(|_e| {}),
        Arc::new(move |a: &AuditEvent| sink.lock().unwrap().push(a.id)),
    );
    let f = Finding {
        signal: "response_poison".into(),
        severity: Severity::High,
        evidence: "CANARY_0_a1b2c3d4".into(),
        kind: "poison".into(),
    };
    bus.emit_audit(&f, "sid", "h", "POST", "/x");
    bus.emit_audit(&f, "sid", "h", "POST", "/x");
    let ids = seen.lock().unwrap().clone();
    assert_eq!(
        ids.len(),
        2,
        "两条 finding 应各触发一次钩子（不得重复入队）"
    );
    assert!(ids.iter().all(|i| *i > 0), "审计 id 不得为 0：{ids:?}");
    assert_ne!(ids[0], ids[1], "审计 id 必须唯一");
}

/// 回归：`/favicon.ico` 必须被接管（204），不能当反代流量转发给上游。
///
/// 浏览器每次加载控制台都会请求它。此前会被转发给上游并在事件日志里刷一条
/// PASS —— 实测**一次页面加载就是一条**，把用户想看的真实事件冲得看不见。
#[tokio::test]
async fn favicon_is_answered_locally_not_proxied() {
    let h = Harness::new();
    let app = build_router(h.state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/favicon.ico")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "favicon 应本地 204");
    assert!(resp.headers().get("cache-control").is_some(), "应带缓存头");
    // 且不得产生事件（上游不可达时若被转发就会留下 ERR/PASS 事件）
    assert!(
        h.state.bus.recent(10).is_empty(),
        "favicon 不应进入事件管线"
    );
}
