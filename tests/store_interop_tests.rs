//! M9 退出标准：与 Python 版事件库**互读写**验证。
//!
//! 验证方式：用 rusqlite 直接按 Python schema 写入一条「Python 版形态」的事件行，
//! 再由 Rust 侧 `EventStore` 读回并校验字段；反向亦然。

use maskit_rs::store::db::{init_schema, EventStore};
use maskit_rs::store::events::{AuditEvent, Event, EventItem, EventType};
use rusqlite::{params, Connection};

/// Python 版事件 payload 的真实形态（字段名与 event_store.py 一致）。
fn python_style_payload() -> String {
    serde_json::json!({
        "ts": 1758600000.123,
        "type": "MASK",
        "host": "api.openai.com",
        "method": "POST",
        "path": "/v1/chat/completions",
        "sid": "abc123def4567890",
        "count": 2,
        "new_count": 1,
        "masked_total": 2,
        "items": [
            {"tok": "{{PHONE_bcdfgh}}", "label": "PHONE", "original": "13800138000",
             "preview": "13****", "length": 11},
            {"tok": "{{APIKEY_kkmmnp}}", "label": "API_KEY", "preview": "sk-1…qrst",
             "length": 38, "cred": true, "digest": "a1b2c3d4e5f60718"}
        ],
        "dialog": "【用户】\n电话{{PHONE_bcdfgh}}",
        "stream_mode": "non_stream",
        "mask_ms": 0.8,
        "upstream": "openai"
    })
    .to_string()
}

#[test]
fn schema_is_compatible_with_python() {
    // 两种建表路径产出的表集合必须一致（Python schema 的 9 张表）
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("py.sqlite3");
    init_schema(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    for t in [
        "audit_events",
        "daily_models",
        "daily_prefix",
        "daily_stats",
        "daily_status",
        "daily_tokens",
        "daily_words",
        "events",
        "meta",
    ] {
        assert!(tables.contains(&t.to_string()), "缺表 {t}");
    }
    // events 表列名与 Python 一致（id/ts/type/payload）
    let mut stmt2 = conn.prepare("PRAGMA table_info(events)").unwrap();
    let cols: Vec<String> = stmt2
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    assert_eq!(cols, vec!["id", "ts", "type", "payload"]);
}

#[test]
fn rust_reads_python_written_events() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shield-events.sqlite3");
    // 模拟 Python 版写入
    init_schema(&path).unwrap();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO events (ts, type, payload) VALUES (?1, ?2, ?3)",
            params![1758600000.123, "MASK", python_style_payload()],
        )
        .unwrap();
        // Python 侧还会写摘要表
        conn.execute(
            "INSERT INTO daily_stats (day, key, cnt) VALUES (date('now'), 'mask_events', 5)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO daily_words (day, label, word, cnt) VALUES (date('now'), 'PHONE', '13****', 5)",
            [],
        )
        .unwrap();
    }
    // Rust 侧读取
    let store = EventStore::open(dir.path()).unwrap();
    // 注意：EventStore::open 会 init_schema（IF NOT EXISTS，安全）
    let raw: Vec<String> = {
        let conn = Connection::open(store.path()).unwrap();
        let mut stmt = conn.prepare("SELECT payload FROM events").unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };
    assert_eq!(raw.len(), 1);
    // payload 能被 Rust 的 Event 结构解析（字段兼容性验证）
    let parsed: Result<Event, _> = serde_json::from_str(&raw[0]);
    assert!(
        parsed.is_ok(),
        "Rust 必须能解析 Python 写的 payload: {:?}",
        parsed.err()
    );
    let ev = parsed.unwrap();
    assert_eq!(ev.method, "POST");
    assert_eq!(ev.path, "/v1/chat/completions");
    assert_eq!(ev.items.len(), 2);
    // 凭据项：Python 侧也不落原文
    let cred = ev.items.iter().find(|i| i.label == "API_KEY").unwrap();
    assert!(cred.cred);
    assert!(cred.original.is_empty(), "凭据原文不落库");
    assert_eq!(cred.digest, "a1b2c3d4e5f60718");
    // Python 写的摘要表 Rust 能读
    let st = store.today_stats().unwrap();
    assert_eq!(st["mask_events"], 5);
    assert_eq!(st["by_label"]["PHONE"], 5);
}

#[test]
fn python_can_read_rust_written_events() {
    let dir = tempfile::tempdir().unwrap();
    let store = EventStore::open(dir.path()).unwrap();
    // Rust 侧写入
    let ev = Event {
        id: 0,
        ts: 1758600001.0,
        event_type: EventType::Mask,
        method: "POST".into(),
        path: "/v1/messages".into(),
        status: 200,
        reason: String::new(),
        protocol: "anthropic".into(),
        model: "claude-sonnet-4".into(),
        session_id: "rust123".into(),
        mask_ms: Some(1.2),
        first_byte_ms: None,
        upstream_ms: None,
        req_bytes: 200,
        resp_bytes: 0,
        items: vec![EventItem {
            label: "EMAIL".into(),
            token: "{{EMAIL_bcdfgh}}".into(),
            original: "a@example.com".into(),
            cred: false,
            digest: String::new(),
            preview: "a***@example.com".into(),
            length: 13,
            hash: "bcdfgh".into(),
            restored: false,
        }],
        new_count: 1,
        reused_count: 0,
        unresolved: 0,
        unresolved_samples: vec![],
        unknown_shape: false,
        message: String::new(),
        ..Default::default()
    };
    store.enqueue(ev);
    store.sync(); // 屏障：确保已落盘（下面用裸 SQL 模拟 Python 侧读取）

    // 模拟 Python 读取：按 Python 的 SQL 与字段访问方式
    let conn = Connection::open(store.path()).unwrap();
    let (ts, etype, payload): (f64, String, String) = conn
        .query_row(
            "SELECT ts, type, payload FROM events ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(etype, "MASK", "type 用大写（Python 版口径）");
    assert!((ts - 1758600001.0).abs() < 0.01);
    let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
    // Python 侧读的字段名
    assert_eq!(v["method"], "POST");
    assert_eq!(v["path"], "/v1/messages");
    assert_eq!(v["items"][0]["label"], "EMAIL");
    assert_eq!(v["items"][0]["original"], "a@example.com");
    assert_eq!(v["stream_mode"], "");
    // Python 的 today_stats 查询口径（daily_stats + daily_words）
    let day: String = conn
        .query_row("SELECT date('now')", [], |r| r.get(0))
        .unwrap();
    let mask_events: i64 = conn
        .query_row(
            "SELECT cnt FROM daily_stats WHERE day = ?1 AND key = 'mask_events'",
            params![day],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(mask_events, 1, "Python 版 today_stats 能读到 Rust 写的聚合");
    let word_cnt: i64 = conn
        .query_row(
            "SELECT cnt FROM daily_words WHERE day = ?1 AND label = 'EMAIL'",
            params![day],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(word_cnt, 1);
}

#[test]
fn audit_events_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = EventStore::open(dir.path()).unwrap();
    store.enqueue_audit(AuditEvent {
        id: 0,
        ts: 1758600002.0,
        signal_type: "response_poison".into(),
        severity: "HIGH".into(),
        evidence: "exfil_url host=evil.example len=120 sha256=abcdef1234567890".into(),
        sid: "s1".into(),
        host: "h".into(),
        method: "POST".into(),
        path: "/v1/chat".into(),
    });
    store.sync(); // 屏障：确保已落盘（下面用裸 SQL 模拟 Python 侧读取）
                  // Python 侧读法：signal_type/severity/evidence 列 + payload
    let conn = Connection::open(store.path()).unwrap();
    let (sig, sev, evi): (String, String, String) = conn
        .query_row(
            "SELECT signal_type, severity, evidence FROM audit_events LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(sig, "response_poison");
    assert_eq!(sev, "HIGH");
    assert!(evi.contains("sha256="), "证据带不可逆摘要（Python 口径）");
    // Rust 读回
    let audits = store.fetch_audits(10);
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].signal_type, "response_poison");
}

// ── 占位符映射表：异步落盘 / 兜底查询 / TTL 清理 ──────────────────

#[test]
fn mapping_save_lookup_prune_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let store = EventStore::open(dir.path()).unwrap();

    // 入队（异步写线程）；轮询等待落盘可见
    let pairs = vec![
        (
            "{{PHONE_kqmzbv}}".to_string(),
            "13800138000".to_string(),
            "PHONE".to_string(),
        ),
        (
            "{{EMAIL_aaaaaa}}".to_string(),
            "a@b.com".to_string(),
            "EMAIL".to_string(),
        ),
    ];
    assert_eq!(store.save_mappings(&pairs, 86400), 2, "应全部入队");

    store.sync(); // 屏障：确保已入队 == 已落盘
    let (tok, label) = store
        .lookup_mapping("13800138000")
        .expect("落盘后应能查到映射");
    assert_eq!(tok, "{{PHONE_kqmzbv}}");
    assert_eq!(label, "PHONE");
    assert_eq!(
        store.lookup_mapping("a@b.com").map(|(t, _)| t),
        Some("{{EMAIL_aaaaaa}}".to_string())
    );
    assert!(store.lookup_mapping("不存在@x.com").is_none());

    // TTL=0 → 立即过期 → 查不到（验证 expires_at 生效）
    let expiring = vec![(
        "{{PHONE_bbbbbb}}".to_string(),
        "13900139000".to_string(),
        "PHONE".to_string(),
    )];
    assert_eq!(store.save_mappings(&expiring, 0), 1);
    store.sync();
    assert!(
        store.lookup_mapping("13900139000").is_none(),
        "TTL 到期的映射不应被查到"
    );

    // 清理：prune 后过期行消失，存活行保留
    store.prune_mappings();
    store.sync();
    assert!(
        store.lookup_mapping("13800138000").is_some(),
        "未过期映射应保留"
    );
    let back = store.load_mappings(10);
    assert_eq!(back.len(), 2, "load_mappings 只应返回未过期项");
}

#[test]
fn mapping_save_is_idempotent_upsert() {
    let dir = tempfile::tempdir().unwrap();
    let store = EventStore::open(dir.path()).unwrap();
    let tok = "{{APIKEY_zzzzzz}}".to_string();
    // 同一 token 重复写（幂等，不应产生重复行 / 不应报错）
    for _ in 0..5 {
        store.save_mappings(
            &[(tok.clone(), "sk-secret".to_string(), "API_KEY".to_string())],
            86400,
        );
    }
    store.sync();
    let all = store.load_mappings(100);
    let n = all.iter().filter(|(t, _, _)| *t == tok).count();
    assert_eq!(n, 1, "同一 token 只应保留 1 行，实际 {n}");
    assert_eq!(store.lookup_mapping("sk-secret").map(|(t, _)| t), Some(tok));
}

#[test]
fn mapping_db_file_is_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let _store = EventStore::open(dir.path()).unwrap();
    let db = dir.path().join("shield-events.sqlite3");
    assert!(db.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "库内含明文凭据，权限应为 0600，实际 {mode:o}");
    }
}
