//! Maskit-RS：本地 LLM 敏感信息脱敏网关（Rust 重构版）。
//!
//! 单端口单上游：Web 控制台（/console）+ 管理 API（/console/api/*）
//! 与 LLM 反代管线共用一个端口；非 console 路径全部进入反代管线。

use maskit_rs::{config, server, store, upstream};
use std::sync::Arc;

fn main() {
    // `--health-check`：容器 HEALTHCHECK 用（distroless 镜像里没有 curl/wget）。
    // 读本地配置 → 请求自己的 /console/api/health → 按结果退出。
    if std::env::args().any(|a| a == "--health-check") {
        std::process::exit(health_check());
    }
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("maskit-rs {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!(
            "maskit-rs {}\n\n用法：\n  maskit-rs                 启动网关（监听地址见 config.json）\n  maskit-rs --health-check  健康检查（容器 HEALTHCHECK 用）\n  maskit-rs --version        打印版本\n\n环境变量：\n  MASKIT_RS_DATA_DIR  数据目录（默认 ./data）\n  RUST_LOG            日志级别（默认 info）",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    // tracing 初始化
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // 数据目录：环境变量优先，默认 ./data
    let data_dir = std::env::var("MASKIT_RS_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("data"));

    let (config_center, warnings) = match config::ConfigCenter::load_or_init(&data_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[maskit-rs] 数据目录初始化失败（{data_dir:?}）: {e}");
            std::process::exit(1);
        }
    };
    for w in &warnings {
        tracing::warn!("[config] {}", w.0);
    }
    let cfg = config_center.get();

    if cfg.upstream.target.is_empty() {
        tracing::warn!(
            "[config] upstream.target 未配置：反代路径将返回 502。\
             请在控制台 设置 → 上游 填入目标地址（如 https://api.your-relay.com）"
        );
    }

    // 上游客户端：target 未配置或非法时也不退出（反代路径返回 502）
    let upstream = Arc::new(upstream::UpstreamClient::new_or_placeholder(&cfg.upstream));

    // 事件总线
    let bus = store::events::EventBus::new();

    let port = cfg.server.port;
    let bind = cfg.server.bind.clone();
    let token = cfg.panel_token.clone();

    // SQLite 事件库（与 Python 版同 schema，可直接互读写）
    let event_store = match store::db::EventStore::open(&data_dir) {
        Ok(s) => {
            tracing::info!("事件库: {:?}", s.path());
            Some(s)
        }
        Err(e) => {
            tracing::warn!("事件库打开失败（{e}），退化为仅内存事件 ring");
            None
        }
    };

    // token 用量落库（只统计数量，不做价格计算）
    if let Some(es) = event_store.clone() {
        server::response::set_usage_hook(Box::new(move |model: &str, u: &store::usage::Usage| {
            es.add_tokens(model, *u);
        }));
    }

    let state = std::sync::Arc::new(server::AppState::new(
        config_center.clone(),
        bus.clone(),
        upstream,
        event_store.clone(),
    ));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    tracing::info!("Maskit-RS 启动: http://{}:{}  数据目录: {:?}", bind, port, data_dir);
    tracing::info!("控制台: http://{}:{}/console  （令牌见 config.json panel_token）", bind, port);
    tracing::info!("客户端 base_url: http://127.0.0.1:{}/<原路径>", port);
    tracing::debug!(token = %token, "panel token");

    // 后台维护任务：会话 sweep + 事件保留期清理
    if let Some(es) = event_store.clone() {
        let cfg2 = cfg.clone();
        let store_static: &'static maskit_rs::mask::session::SessionStore = &maskit_rs::mask::session::STORE;
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            store_static.sweep(cfg2.mask.session_ttl as f64);
            es.prune(cfg2.log_retention_days as i64);
        });
    }

    let app = server::build_router(state);
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind((bind.as_str(), port))
            .await
            .expect("绑定端口失败");
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("收到退出信号，优雅关闭…");
        };
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .expect("服务器运行失败");
    });
}


/// 容器健康检查：请求本机 `/console/api/health`（免鉴权端点）。
///
/// 实现说明：distroless 镜像没有 curl/wget，Rust 标准库也没有 HTTP 客户端，
/// 因此这里手写一个最小 HTTP/1.1 GET —— 目标固定为 127.0.0.1，不接受外部输入。
fn health_check() -> i32 {
    let data_dir = std::env::var("MASKIT_RS_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("data"));
    // 端口取配置（读不到就用默认 18701）
    let port = std::fs::read_to_string(data_dir.join("config.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v.get("server")
                .and_then(|s| s.get("port"))
                .and_then(|p| p.as_u64())
        })
        .unwrap_or(18701);

    use std::io::{Read, Write};
    let mut stream = match std::net::TcpStream::connect(("127.0.0.1", port as u16)) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
    let req = format!(
        "GET /console/api/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return 1;
    }
    let mut buf = [0u8; 256];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return 1,
    };
    let head = String::from_utf8_lossy(&buf[..n]);
    if head.contains(" 200 ") {
        0
    } else {
        1
    }
}
