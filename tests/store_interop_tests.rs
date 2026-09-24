//! M9 退出标准：与 Python 版事件库**互读写**验证。
//!
//! 验证方式：用 rusqlite 直接按 Python schema 写入一条「Python 版形态」的事件行，
//! 再由 Rust 侧 `EventStore` 读回并校验字段；反向亦然。

use rusqlite::{params, Connection};
use maskit_rs::store::db::{init_schema, EventStore};
use maskit_rs::store::events::{AuditEvent, Event, EventItem, EventType};

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
        "audit_events", "daily_models", "daily_prefix", "daily_stats", "daily_status",
        "daily_tokens", "daily_words", "events", "meta",
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
    assert!(parsed.is_ok(), "Rust 必须能解析 Python 写的 payload: {:?}", parsed.err());
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
    std::thread::sleep(std::time::Duration::from_millis(800));

    // 模拟 Python 读取：按 Python 的 SQL 与字段访问方式
    let conn = Connection::open(store.path()).unwrap();
    let (ts, etype, payload): (f64, String, String) = conn
        .query_row("SELECT ts, type, payload FROM events ORDER BY id DESC LIMIT 1", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
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
    let day: String = conn.query_row("SELECT date('now')", [], |r| r.get(0)).unwrap();
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
    std::thread::sleep(std::time::Duration::from_millis(800));
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
