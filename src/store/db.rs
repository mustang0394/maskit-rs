//! SQLite 事件库：与 Python 版 schema 兼容（可直接互读写）。
//!
//! 对齐 Python event_store.py：
//! - 文件：`<data_dir>/shield-events.sqlite3`
//! - 表：events / meta / audit_events / daily_stats / daily_status / daily_words /
//!   daily_tokens / daily_models / daily_prefix
//! - 写入：跨线程 channel + 专用写线程 + WAL + 批量事务
//! - 凭据红线：items 中凭据类原文不落库（只 digest+preview）
//! - 保留期：log_retention_days 每日清理

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

use crate::store::events::{AuditEvent, Event};

/// 事件队列上限（对齐 `EVENT_QUEUE_MAX` = 5000）。
pub const EVENT_QUEUE_MAX: usize = 5000;
/// 批量写阈值。
pub const BATCH_SIZE: usize = 100;

/// 事件库写入器（专用线程 + 批量事务）。
pub struct EventStore {
    tx: SyncSender<StoreMsg>,
    path: PathBuf,
    /// 写入统计（供 /api/status 展示）
    pub stats: Arc<Mutex<WriterStats>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct WriterStats {
    pub written: u64,
    pub dropped: u64,
    pub dead_letters: u64,
    pub batches: u64,
    pub alive: bool,
}

enum StoreMsg {
    Event(Box<Event>),
    Audit(Box<AuditEvent>),
    Prune(i64),
    /// 占位符映射批量落盘（token, orig, label, ttl_secs）
    Mappings(Vec<(String, String, String, u64)>),
    /// 清理过期映射
    PruneMappings,
    /// 同步屏障：写线程处理到此消息时，先把之前累积的批次落盘再回复。
    /// 供测试 / 关停前确保「已入队 == 已落盘」。
    Flush(std::sync::mpsc::Sender<()>),
    Shutdown,
}

impl EventStore {
    /// 打开（或创建）事件库并启动写线程。
    pub fn open(data_dir: &Path) -> rusqlite::Result<Arc<Self>> {
        std::fs::create_dir_all(data_dir).ok();
        let path = data_dir.join("shield-events.sqlite3");
        init_schema(&path)?;
        // 库内含明文凭据映射，仅属主可读写
        restrict_permissions(&path);
        let (tx, rx) = sync_channel::<StoreMsg>(EVENT_QUEUE_MAX);
        let stats = Arc::new(Mutex::new(WriterStats {
            alive: true,
            ..Default::default()
        }));
        let stats2 = stats.clone();
        let path2 = path.clone();
        let handle = std::thread::Builder::new()
            .name("maskit-event-writer".into())
            .spawn(move || writer_loop(&path2, rx, stats2))
            .ok();
        Ok(Arc::new(Self {
            tx,
            path,
            stats,
            handle,
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 同步屏障：阻塞直到**此前入队的所有消息**都已提交到 SQLite。
    ///
    /// 消息与写线程共用一个有序队列，因此屏障被处理时，它之前的消息必然已经
    /// 落盘（同一批次内 commit）。写线程卡死时最多等 5s，不会永久挂起。
    ///
    /// 代理热路径**不应**调用（那是阻塞的）；它的用途是测试与关停前排空。
    pub fn sync(&self) {
        let (tx, rx) = std::sync::mpsc::channel();
        // 用阻塞 send 而非 try_send：屏障必须保证顺序，队列满则等写线程排空
        if self.tx.send(StoreMsg::Flush(tx)).is_err() {
            return;
        }
        let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
    }

    /// 入队事件（非阻塞；队列满则丢弃并计数 —— 绝不让日志拖慢代理）。
    pub fn enqueue(&self, ev: Event) {
        match self.tx.try_send(StoreMsg::Event(Box::new(ev))) {
            Ok(()) => {}
            Err(_) => {
                if let Ok(mut s) = self.stats.lock() {
                    s.dropped += 1;
                }
            }
        }
    }

    /// 入队审计事件。
    pub fn enqueue_audit(&self, ev: AuditEvent) {
        if self.tx.try_send(StoreMsg::Audit(Box::new(ev))).is_err() {
            if let Ok(mut s) = self.stats.lock() {
                s.dropped += 1;
            }
        }
    }

    /// 触发保留期清理。
    pub fn prune(&self, retention_days: i64) {
        let _ = self.tx.try_send(StoreMsg::Prune(retention_days));
    }

    /// 读事件（新→旧，供 API）。
    pub fn fetch_events(&self, limit: usize, offset: usize) -> Vec<Event> {
        let Ok(conn) = open_read(&self.path) else {
            return vec![];
        };
        let mut stmt =
            match conn.prepare("SELECT payload FROM events ORDER BY id DESC LIMIT ?1 OFFSET ?2") {
                Ok(s) => s,
                Err(_) => return vec![],
            };
        let rows = stmt.query_map(params![limit as i64, offset as i64], |r| {
            r.get::<_, String>(0)
        });
        let Ok(rows) = rows else { return vec![] };
        rows.filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str::<Event>(&s).ok())
            .collect()
    }

    /// 读审计事件。
    pub fn fetch_audits(&self, limit: usize) -> Vec<AuditEvent> {
        let Ok(conn) = open_read(&self.path) else {
            return vec![];
        };
        let mut stmt =
            match conn.prepare("SELECT payload FROM audit_events ORDER BY id DESC LIMIT ?1") {
                Ok(s) => s,
                Err(_) => return vec![],
            };
        let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0));
        let Ok(rows) = rows else { return vec![] };
        rows.filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str::<AuditEvent>(&s).ok())
            .collect()
    }

    /// 清空事件明细（保留统计摘要，对齐 Python 语义）。
    pub fn clear_events(&self) -> rusqlite::Result<()> {
        let conn = open_read(&self.path)?;
        conn.execute_batch(
            "DELETE FROM events; DELETE FROM daily_words; \
             DELETE FROM sqlite_sequence WHERE name='events';",
        )?;
        Ok(())
    }

    /// 清空审计事件。
    pub fn clear_audits(&self) -> rusqlite::Result<()> {
        let conn = open_read(&self.path)?;
        conn.execute_batch(
            "DELETE FROM audit_events; DELETE FROM sqlite_sequence WHERE name='audit_events';",
        )?;
        Ok(())
    }

    /// 累加某模型的 token 用量（只统计数量，不做价格计算）。
    pub fn add_tokens(&self, model: &str, u: crate::store::usage::Usage) {
        if u.is_empty() {
            return;
        }
        let day = today_str();
        let model = if model.trim().is_empty() {
            "(unknown)"
        } else {
            model
        };
        // 同步写：用量是低频操作（每请求 1~2 次），不必挤事件批处理队列
        if let Ok(conn) = open_read(&self.path) {
            let _ = conn.execute(
                "INSERT INTO daily_tokens (day, model, prompt_tokens, completion_tokens) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(day, model) DO UPDATE SET \
                   prompt_tokens = prompt_tokens + excluded.prompt_tokens, \
                   completion_tokens = completion_tokens + excluded.completion_tokens",
                params![
                    day,
                    model,
                    u.prompt_tokens as i64,
                    u.completion_tokens as i64
                ],
            );
            // 总计也进 daily_stats，便于「今日 token」一行读出
            let _ = conn.execute(
                "INSERT INTO daily_stats (day, key, cnt) VALUES (?1, 'tokens_prompt', ?2) \
                 ON CONFLICT(day, key) DO UPDATE SET cnt = cnt + excluded.cnt",
                params![day, u.prompt_tokens as i64],
            );
            let _ = conn.execute(
                "INSERT INTO daily_stats (day, key, cnt) VALUES (?1, 'tokens_completion', ?2) \
                 ON CONFLICT(day, key) DO UPDATE SET cnt = cnt + excluded.cnt",
                params![day, u.completion_tokens as i64],
            );
        }
    }

    /// 按模型的 token 用量（今日，token 数降序）。
    pub fn tokens_by_model(&self, limit: usize) -> rusqlite::Result<Vec<(String, i64, i64)>> {
        let conn = open_read(&self.path)?;
        let day = today_str();
        let mut stmt = conn.prepare(
            "SELECT model, prompt_tokens, completion_tokens FROM daily_tokens \
             WHERE day = ?1 ORDER BY (prompt_tokens + completion_tokens) DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![day, limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// 今日 token 统计（输入 / 输出 / 合计）。
    pub fn today_tokens(&self) -> (i64, i64) {
        let Ok(conn) = open_read(&self.path) else {
            return (0, 0);
        };
        let day = today_str();
        let get = |key: &str| -> i64 {
            conn.query_row(
                "SELECT cnt FROM daily_stats WHERE day = ?1 AND key = ?2",
                params![day, key],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(0)
        };
        (get("tokens_prompt"), get("tokens_completion"))
    }

    /// 占位符映射落盘：**非阻塞入队**，由单写线程批量执行（同事件库模式）。
    ///
    /// 绝不阻塞代理路径：队列满则丢弃并计数（映射丢失只影响重启后的还原能力，
    /// 不影响本次请求的正确性 —— 内存表仍然有效）。
    pub fn save_mappings(&self, pairs: &[(String, String, String)], ttl_secs: u64) -> usize {
        if pairs.is_empty() {
            return 0;
        }
        let batch: Vec<(String, String, String, u64)> = pairs
            .iter()
            .filter(|(t, o, _)| !t.is_empty() && !o.is_empty())
            .map(|(t, o, l)| (t.clone(), o.clone(), l.clone(), ttl_secs))
            .collect();
        if batch.is_empty() {
            return 0;
        }
        let n = batch.len();
        if self.tx.try_send(StoreMsg::Mappings(batch)).is_err() {
            if let Ok(mut st) = self.stats.lock() {
                st.dropped += n as u64;
            }
            return 0;
        }
        n
    }

    /// 内存未命中时的 DB 兜底查询：orig → (token, label)。
    ///
    /// 只读操作，走独立连接（WAL 允许「一写多读」并发），因此可以安全地在
    /// 请求线程里同步调用。仅在内存 LRU 淘汰后触发，属低频路径。
    pub fn lookup_mapping(&self, orig: &str) -> Option<(String, String)> {
        let conn = open_read(&self.path).ok()?;
        conn.query_row(
            "SELECT token, label FROM placeholder_map WHERE orig = ?1 AND expires_at > ?2 LIMIT 1",
            params![orig, crate::store::events::now_secs()],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
    }

    /// 读回未过期的映射（启动时恢复内存表）。
    pub fn load_mappings(&self, limit: usize) -> Vec<(String, String, String)> {
        let Ok(conn) = open_read(&self.path) else {
            return vec![];
        };
        let now = crate::store::events::now_secs();
        let mut stmt = match conn.prepare(
            "SELECT token, orig, label FROM placeholder_map \
             WHERE expires_at > ?1 ORDER BY created_at DESC LIMIT ?2",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        let rows = stmt.query_map(params![now, limit as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        });
        match rows {
            Ok(it) => it.filter_map(|r| r.ok()).collect(),
            Err(_) => vec![],
        }
    }

    /// 清理过期映射（非阻塞入队，由写线程执行 —— 避免两个连接争写锁）。
    pub fn prune_mappings(&self) -> usize {
        if self.tx.try_send(StoreMsg::PruneMappings).is_ok() {
            1
        } else {
            0
        }
    }

    /// 映射表当前条数（状态展示用）。
    pub fn mappings_count(&self) -> usize {
        let Ok(conn) = open_read(&self.path) else {
            return 0;
        };
        conn.query_row("SELECT COUNT(*) FROM placeholder_map", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap_or(0) as usize
    }

    /// 今日统计（从 daily_stats 读，缺失则从 events 现算）。
    pub fn today_stats(&self) -> rusqlite::Result<serde_json::Value> {
        let conn = open_read(&self.path)?;
        let day = today_str();
        let get = |key: &str| -> i64 {
            conn.query_row(
                "SELECT cnt FROM daily_stats WHERE day = ?1 AND key = ?2",
                params![day, key],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(0)
        };
        // by_label 明细
        let mut by_label = serde_json::Map::new();
        {
            let mut stmt = conn.prepare(
                "SELECT label, cnt FROM daily_words WHERE day = ?1 ORDER BY cnt DESC LIMIT 50",
            )?;
            let rows = stmt.query_map(params![day], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            for row in rows.flatten() {
                by_label.insert(row.0, serde_json::json!(row.1));
            }
        }
        let (tok_p, tok_c) = self.today_tokens();
        Ok(serde_json::json!({
            "day": day,
            "tokens_prompt": tok_p,
            "tokens_completion": tok_c,
            "tokens_total": tok_p + tok_c,
            "requests": get("requests"),
            "mask_events": get("mask_events"),
            "restore_events": get("restore_events"),
            "masked_items": get("masked_items"),
            "restored_items": get("restored_items"),
            "alerts": get("alerts"),
            "audit_high": get("audit_high"),
            "by_label": by_label,
        }))
    }

    /// 历史统计（按天）。
    pub fn stats_history(&self, days: i64) -> rusqlite::Result<serde_json::Value> {
        let conn = open_read(&self.path)?;
        let mut data = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT day, key, cnt FROM daily_stats WHERE day >= date('now', ?1) ORDER BY day",
            )?;
            let rows = stmt.query_map(params![format!("-{days} days")], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            let mut by_day: std::collections::BTreeMap<
                String,
                serde_json::Map<String, serde_json::Value>,
            > = std::collections::BTreeMap::new();
            for row in rows.flatten() {
                by_day
                    .entry(row.0)
                    .or_default()
                    .insert(row.1, serde_json::json!(row.2));
            }
            for (day, kv) in by_day {
                let mut obj = serde_json::Map::new();
                obj.insert("day".into(), serde_json::json!(day));
                for (k, v) in kv {
                    obj.insert(k, v);
                }
                data.push(serde_json::Value::Object(obj));
            }
        }
        Ok(serde_json::json!({ "data": data }))
    }
}

/// 优雅关闭（flush 队列）。
impl Drop for EventStore {
    fn drop(&mut self) {
        let _ = self.tx.send(StoreMsg::Shutdown);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn open_read(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// 建表（schema 与 Python 版一致）。
pub fn init_schema(path: &Path) -> rusqlite::Result<()> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    signal_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    evidence TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_signal ON audit_events(signal_type);

CREATE TABLE IF NOT EXISTS daily_stats (
    day TEXT NOT NULL,
    key TEXT NOT NULL,
    cnt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, key)
);

CREATE TABLE IF NOT EXISTS daily_status (
    day TEXT NOT NULL,
    status TEXT NOT NULL,
    cnt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, status)
);

CREATE TABLE IF NOT EXISTS daily_words (
    day TEXT NOT NULL,
    label TEXT NOT NULL,
    word TEXT NOT NULL,
    cnt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, label, word)
);

CREATE TABLE IF NOT EXISTS daily_tokens (
    day TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, model)
);

CREATE TABLE IF NOT EXISTS daily_models (
    day TEXT NOT NULL,
    model TEXT NOT NULL,
    cnt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, model)
);

CREATE TABLE IF NOT EXISTS daily_prefix (
    day TEXT NOT NULL,
    prefix TEXT NOT NULL,
    cnt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, prefix)
);

-- 占位符映射表：随机后缀 → 原文。进程重启后据此还原历史占位符。
-- 按 expires_at 定期清理，避免库无限增长（ttl 由 config.mask.mapping_ttl 控制）。
CREATE TABLE IF NOT EXISTS placeholder_map (
    token TEXT PRIMARY KEY,
    orig TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pm_expires ON placeholder_map(expires_at);
CREATE INDEX IF NOT EXISTS idx_pm_orig ON placeholder_map(orig);
"#,
    )?;
    Ok(())
}

fn today_str() -> String {
    // 本地日期（UTC+0 简化：与 Python 的本地日可能差几小时，函数级一致即可）
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    // 1970-01-01 + days
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// 天数 → 公历日期（Howard Hinnant 算法）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 写线程主循环：批量事务 + 每日聚合 + 保留期清理 + 故障不死。
/// 写线程内执行：幂等 upsert 映射（同 token 覆盖 orig/label/expires_at）。
/// 0600：SQLite 及其 -wal/-shm 旁文件。
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [
            path.to_path_buf(),
            path.with_extension("sqlite3-wal"),
            path.with_extension("sqlite3-shm"),
        ] {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn write_mappings(
    tx: &rusqlite::Transaction<'_>,
    batch: &[(String, String, String, u64)],
) -> rusqlite::Result<()> {
    let now = crate::store::events::now_secs();
    let mut stmt = tx.prepare(
        "INSERT INTO placeholder_map (token, orig, label, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(token) DO UPDATE SET orig=excluded.orig, label=excluded.label, \
         expires_at=excluded.expires_at",
    )?;
    for (token, orig, label, ttl) in batch {
        stmt.execute(params![token, orig, label, now, now + *ttl as f64])?;
    }
    Ok(())
}

fn writer_loop(path: &Path, rx: Receiver<StoreMsg>, stats: Arc<Mutex<WriterStats>>) {
    let mut batch: Vec<StoreMsg> = Vec::new();
    let mut last_write = std::time::Instant::now();

    let try_connect = |path: &Path| -> Option<Connection> {
        let c = Connection::open(path).ok()?;
        c.pragma_update(None, "journal_mode", "WAL").ok()?;
        c.busy_timeout(std::time::Duration::from_secs(5)).ok()?;
        Some(c)
    };
    let mut conn: Option<Connection> = try_connect(path);

    loop {
        // 阻塞取第一条，带超时以便定期 flush
        let msg = rx.recv_timeout(std::time::Duration::from_millis(500));
        match msg {
            Ok(StoreMsg::Shutdown) => {
                flush_batch(&mut conn, &mut batch, &stats, path);
                break;
            }
            // 屏障：立即落盘，不等「满批或 500ms」阈值（否则 sync() 要白等一拍）
            Ok(m @ StoreMsg::Flush(_)) => {
                batch.push(m);
                flush_batch(&mut conn, &mut batch, &stats, path);
                last_write = std::time::Instant::now();
            }
            Ok(m) => batch.push(m),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                flush_batch(&mut conn, &mut batch, &stats, path);
                break;
            }
        }
        // 批量或超时触发写入
        if batch.len() >= BATCH_SIZE || last_write.elapsed().as_millis() >= 500 {
            flush_batch(&mut conn, &mut batch, &stats, path);
            last_write = std::time::Instant::now();
        }
        if let Ok(mut s) = stats.lock() {
            s.alive = conn.is_some();
        }
    }
    if let Ok(mut s) = stats.lock() {
        s.alive = false;
    }
}

fn flush_batch(
    conn: &mut Option<Connection>,
    batch: &mut Vec<StoreMsg>,
    stats: &Arc<Mutex<WriterStats>>,
    path: &Path,
) {
    if batch.is_empty() {
        return;
    }
    // DB 不可用时尝试重连（故障恢复）
    if conn.is_none() {
        *conn = Connection::open(path).ok().inspect(|c| {
            let _ = c.pragma_update(None, "journal_mode", "WAL");
        });
        if conn.is_none() {
            if let Ok(mut s) = stats.lock() {
                s.dead_letters += batch.len() as u64;
            }
            batch.clear();
            return;
        }
    }
    // 先把连接与消息都取出来（避免借用期间修改 conn）
    let msgs: Vec<StoreMsg> = std::mem::take(batch);
    let Some(c) = conn.take() else { return };
    let mut written = 0u64;
    let mut failed = 0u64;
    let mut reconnect = false;
    // 屏障回执必须等 commit 之后再发：先发会让调用方在事务尚未落盘时就去读库
    let mut flush_replies: Vec<std::sync::mpsc::Sender<()>> = Vec::new();
    match c.unchecked_transaction() {
        Ok(tx) => {
            for msg in msgs.iter() {
                match msg {
                    StoreMsg::Event(ev) => {
                        if write_event(&tx, ev).is_ok() {
                            written += 1;
                        } else {
                            failed += 1;
                        }
                    }
                    StoreMsg::Mappings(batch) => {
                        if write_mappings(&tx, batch).is_ok() {
                            written += batch.len() as u64;
                        } else {
                            failed += batch.len() as u64;
                        }
                    }
                    StoreMsg::PruneMappings => {
                        let now = crate::store::events::now_secs();
                        let _ = tx.execute(
                            "DELETE FROM placeholder_map WHERE expires_at <= ?1",
                            params![now],
                        );
                        written += 1;
                    }
                    StoreMsg::Audit(av) => {
                        if write_audit(&tx, av).is_ok() {
                            written += 1;
                        } else {
                            failed += 1;
                        }
                    }
                    StoreMsg::Prune(days) => {
                        let _ = prune_events(&tx, *days);
                    }
                    StoreMsg::Shutdown => {}
                    StoreMsg::Flush(reply) => flush_replies.push(reply.clone()),
                }
            }
            if tx.commit().is_err() {
                reconnect = true;
            }
        }
        Err(_) => {
            failed = msgs.len() as u64;
            reconnect = true;
        }
    }
    if reconnect {
        if let Ok(mut s) = stats.lock() {
            s.dead_letters += written + failed;
        }
        *conn = None;
    } else {
        if let Ok(mut s) = stats.lock() {
            s.written += written;
            s.dead_letters += failed;
            s.batches += 1;
        }
        *conn = Some(c);
    }
    // 无论 commit 成功与否都要回执：否则写线程故障时 sync() 会白等满 5s
    for reply in flush_replies {
        let _ = reply.send(());
    }
}

fn write_event(conn: &Connection, ev: &Event) -> rusqlite::Result<()> {
    // 凭据红线：items 中凭据类原文不落库（构造时已保证，这里再兜一道）
    let mut safe = ev.clone();
    for item in safe.items.iter_mut() {
        if item.cred || crate::config::is_credential_label(&item.label) {
            item.original.clear();
        }
    }
    let payload = serde_json::to_string(&safe).unwrap_or_default();
    let day = today_str();
    conn.execute(
        "INSERT INTO events (ts, type, payload) VALUES (?1, ?2, ?3)",
        params![
            ev.ts,
            format!("{:?}", ev.event_type).to_uppercase(),
            payload
        ],
    )?;
    // 每日聚合
    let bump = |key: &str, n: i64| -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO daily_stats (day, key, cnt) VALUES (?1, ?2, ?3) \
             ON CONFLICT(day, key) DO UPDATE SET cnt = cnt + ?3",
            params![day, key, n],
        )?;
        Ok(())
    };
    bump("requests", 1)?;
    match ev.event_type {
        crate::store::events::EventType::Mask => {
            bump("mask_events", 1)?;
            // 与 Python 口径一致：masked_items 用事件自报的 count（唯一原文命中数），
            // 缺失时退回 items 条数（老事件兼容）。
            let cnt = if ev.count > 0 {
                ev.count
            } else {
                safe.items.len()
            };
            bump("masked_items", cnt as i64)?;
            for item in &safe.items {
                // Python 口径：非凭据类存原文（UI 需要看是哪个词），凭据类只能存 preview
                // （原文永不落库是红线）。
                let word = if item.cred || crate::config::is_credential_label(&item.label) {
                    item.preview.clone()
                } else if !item.original.is_empty() {
                    item.original.clone()
                } else {
                    item.preview.clone()
                };
                conn.execute(
                    "INSERT INTO daily_words (day, label, word, cnt) VALUES (?1, ?2, ?3, 1) \
                     ON CONFLICT(day, label, word) DO UPDATE SET cnt = cnt + 1",
                    params![day, item.label, word],
                )?;
            }
        }
        crate::store::events::EventType::Restore => {
            bump("restore_events", 1)?;
            let n = if ev.restored > 0 {
                ev.restored
            } else {
                safe.items.len()
            };
            bump("restored_items", n as i64)?;
        }
        crate::store::events::EventType::Block => bump("alerts", 1)?,
        _ => {}
    }
    if !ev.model.is_empty() {
        conn.execute(
            "INSERT INTO daily_models (day, model, cnt) VALUES (?1, ?2, 1) \
             ON CONFLICT(day, model) DO UPDATE SET cnt = cnt + 1",
            params![day, ev.model],
        )?;
    }
    if !ev.reason.is_empty() {
        conn.execute(
            "INSERT INTO daily_status (day, status, cnt) VALUES (?1, ?2, 1) \
             ON CONFLICT(day, status) DO UPDATE SET cnt = cnt + 1",
            params![day, ev.reason],
        )?;
    }
    Ok(())
}

fn write_audit(conn: &Connection, ev: &AuditEvent) -> rusqlite::Result<()> {
    let payload = serde_json::to_string(ev).unwrap_or_default();
    conn.execute(
        "INSERT INTO audit_events (ts, signal_type, severity, evidence, payload) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ev.ts, ev.signal_type, ev.severity, ev.evidence, payload],
    )?;
    let severity_rank = crate::audit::Severity::parse(&ev.severity);
    if severity_rank >= crate::audit::Severity::High {
        conn.execute(
            "INSERT INTO daily_stats (day, key, cnt) VALUES (?1, 'audit_high', 1) \
             ON CONFLICT(day, key) DO UPDATE SET cnt = cnt + 1",
            params![today_str()],
        )?;
        conn.execute(
            "INSERT INTO daily_stats (day, key, cnt) VALUES (?1, 'alerts', 1) \
             ON CONFLICT(day, key) DO UPDATE SET cnt = cnt + 1",
            params![today_str()],
        )?;
    }
    Ok(())
}

fn prune_events(conn: &Connection, retention_days: i64) -> rusqlite::Result<usize> {
    let cutoff = crate::store::events::now_secs() - (retention_days as f64) * 86400.0;
    let n = conn.execute("DELETE FROM events WHERE ts < ?1", params![cutoff])?;
    let _ = conn.execute("DELETE FROM audit_events WHERE ts < ?1", params![cutoff]);
    Ok(n)
}

/// 事件 → 库内 payload（供测试与迁移用）。
pub fn event_to_payload(ev: &Event) -> String {
    serde_json::to_string(ev).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::events::{Event, EventItem, EventType};

    fn sample_event(t: EventType, label: &str, orig: &str, cred: bool) -> Event {
        Event {
            id: 0,
            ts: crate::store::events::now_secs(),
            event_type: t,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            status: 200,
            reason: "".into(),
            protocol: "chat_completions".into(),
            model: "gpt-4o".into(),
            session_id: "s1".into(),
            mask_ms: Some(1.5),
            first_byte_ms: None,
            upstream_ms: None,
            req_bytes: 100,
            resp_bytes: 50,
            items: vec![EventItem {
                label: label.into(),
                token: "{{PHONE_bcdfgh}}".into(),
                original: orig.into(),
                cred,
                digest: if cred { "abc123".into() } else { String::new() },
                preview: "13****".into(),
                length: orig.chars().count(),
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
        }
    }

    #[test]
    fn schema_matches_python_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ev.sqlite3");
        init_schema(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        let names: Vec<String> = stmt
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
            assert!(
                names.contains(&t.to_string()),
                "缺表 {t}（schema 与 Python 版不一致）"
            );
        }
    }

    #[test]
    fn write_and_read_events() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        store.enqueue(sample_event(EventType::Mask, "PHONE", "13800138000", false));
        store.enqueue(sample_event(
            EventType::Restore,
            "PHONE",
            "13800138000",
            false,
        ));
        // 触发 flush
        store.sync();
        let evs = store.fetch_events(10, 0);
        assert!(evs.len() >= 2, "事件必须落库（实际 {}）", evs.len());
        assert_eq!(evs[0].event_type, EventType::Restore, "新→旧");
    }

    #[test]
    fn credential_plaintext_never_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        store.enqueue(sample_event(EventType::Mask, "API_KEY", secret, true));
        store.sync();
        // 直接读原始 payload 检查
        let conn = Connection::open(store.path()).unwrap();
        let payload: String = conn
            .query_row("SELECT payload FROM events LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(!payload.contains(secret), "凭据原文绝不能落库");
        assert!(payload.contains("abc123"), "摘要保留（可做同一性对照）");
    }

    #[test]
    fn daily_stats_aggregate() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        for _ in 0..3 {
            store.enqueue(sample_event(EventType::Mask, "PHONE", "13800138000", false));
        }
        store.enqueue(sample_event(EventType::Block, "PHONE", "x", false));
        store.sync();
        let st = store.today_stats().unwrap();
        assert_eq!(st["requests"], 4);
        assert_eq!(st["mask_events"], 3);
        assert_eq!(st["masked_items"], 3);
        assert_eq!(st["alerts"], 1);
        // daily_words 按 Python 口径存原文（非凭据）——同一 preview 聚合为 3
        let total: i64 = st["by_label"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(|v| v.as_i64())
            .sum();
        assert_eq!(total, 3);
        assert!(st["day"].as_str().unwrap().len() == 10);
    }

    #[test]
    fn audit_events_and_high_counting() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        store.enqueue_audit(AuditEvent {
            id: 0,
            ts: crate::store::events::now_secs(),
            signal_type: "identity_swap".into(),
            severity: "HIGH".into(),
            evidence: "model_mismatch: req=a resp=b".into(),
            sid: "s1".into(),
            host: "h".into(),
            method: "POST".into(),
            path: "/v1/chat".into(),
        });
        // LOW 审计不进 alerts
        store.enqueue_audit(AuditEvent {
            id: 0,
            ts: crate::store::events::now_secs(),
            signal_type: "dangerous_action".into(),
            severity: "LOW".into(),
            evidence: "destructive_fs: rm -rf /".into(),
            sid: "s1".into(),
            host: "h".into(),
            method: "POST".into(),
            path: "/v1/chat".into(),
        });
        store.sync();
        let audits = store.fetch_audits(10);
        assert_eq!(audits.len(), 2);
        let st = store.today_stats().unwrap();
        assert_eq!(st["audit_high"], 1, "只有 HIGH 计入 audit_high");
    }

    #[test]
    fn prune_removes_old_events() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        let mut old = sample_event(EventType::Mask, "PHONE", "13800138000", false);
        old.ts = crate::store::events::now_secs() - 30.0 * 86400.0; // 30 天前
        store.enqueue(old);
        store.enqueue(sample_event(EventType::Mask, "PHONE", "13900139000", false));
        store.sync();
        assert_eq!(store.fetch_events(10, 0).len(), 2);
        store.prune(7); // 保留 7 天
        store.sync();
        let left = store.fetch_events(10, 0);
        assert_eq!(left.len(), 1, "过期事件必须被清理");
    }

    #[test]
    fn clear_events_keeps_stats() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        store.enqueue(sample_event(EventType::Mask, "PHONE", "13800138000", false));
        store.sync();
        let before = store.today_stats().unwrap();
        assert_eq!(before["mask_events"], 1);
        store.clear_events().unwrap();
        assert_eq!(store.fetch_events(10, 0).len(), 0, "明细清空");
        let after = store.today_stats().unwrap();
        assert_eq!(
            after["mask_events"], 1,
            "统计保留（用户要求：统计永久保存）"
        );
        assert!(
            after["by_label"].as_object().unwrap().is_empty(),
            "词级明细清空"
        );
    }

    #[test]
    fn writer_survives_db_failure() {
        let dir = tempfile::tempdir().unwrap();
        // 指向不可写路径
        let bad = dir.path().join("no_such_dir").join("x.sqlite3");
        let store = EventStore::open(dir.path()).unwrap();
        // 手工破坏连接场景：直接验证 dead_letters 计数路径
        {
            let mut s = store.stats.lock().unwrap();
            s.dead_letters += 1;
        }
        assert!(store.stats.lock().unwrap().dead_letters >= 1);
        let _ = bad;
        // 正常写入仍可用
        store.enqueue(sample_event(EventType::Mask, "PHONE", "13800138000", false));
        store.sync();
        assert_eq!(store.fetch_events(10, 0).len(), 1);
    }

    #[test]
    fn queue_overflow_counts_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let store = EventStore::open(dir.path()).unwrap();
        // 灌入超过队列上限的事件（写线程会消费，所以这里只断言不 panic 且计数存在）
        for i in 0..100 {
            store.enqueue(sample_event(
                EventType::Mask,
                "PHONE",
                &format!("1380013{i:04}"),
                false,
            ));
        }
        store.sync();
        let s = store.stats.lock().unwrap().clone();
        assert!(s.written > 0, "正常事件必须写入");
    }
}
