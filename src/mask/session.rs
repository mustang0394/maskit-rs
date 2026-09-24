//! 会话映射 + TTL 复用表 + 后缀索引（对齐 Python sessions/_RECENT_*/_RECENT_SUFFIX）。

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::placeholder;

/// 会话内映射（对齐 Python `_new_session` 的 fwd/rev/labels/pending）。
#[derive(Default)]
pub struct Session {
    /// orig → token
    pub fwd: HashMap<String, String>,
    /// token → orig
    pub rev: HashMap<String, String>,
    /// orig → label
    pub labels: HashMap<String, String>,
    /// 流式通道 → 半截占位符缓冲（channel → pending text）
    pub pending: HashMap<String, String>,
    /// 流式通道 → 最后一个该通道事件的 JSON 模板（收尾补发用）
    pub flush_tmpl: HashMap<String, String>,
    /// 本次请求命中且已登记的唯一原文（累积，跨叶子）
    pub last_hits: std::collections::HashSet<String>,
    /// 本次请求新增原文
    pub new_orig: std::collections::HashSet<String>,
    /// 还原计数 / 未还原计数 / 宽松兜底还原计数
    pub restored: u64,
    pub unresolved: u64,
    pub degraded: u64,
    /// 还原过的 token 集合
    pub restored_tokens: std::collections::HashSet<String>,
    /// 还原过的原文集合（响应侧 PII 扫描防误报）
    pub restored_origs: std::collections::HashSet<String>,
    /// 未还原占位符样本（≤5）
    pub unresolved_samples: Vec<String>,
    /// 危险命令命中（槽位级）
    pub cmd_hits: Vec<CmdHit>,
    pub cmd_blocked: bool,
    /// 回声基线（惰性构建）
    pub cmd_req_window: Option<Vec<u8>>,
    pub cmd_req_snippets: Option<std::collections::HashSet<String>>,
    pub cmd_reason_snippets: std::collections::HashSet<String>,
    pub cmd_pend: HashMap<String, String>,
    /// 本次会话新建的映射（待持久化到 SQLite；由调用方 drain 后入队落盘）
    pub pending_persist: std::collections::HashSet<String>,
    /// 请求侧命令窗口切片
    /// 时间戳
    pub ts: f64,
    pub req_ts: f64,
    pub req_t0: f64,
    pub mask_ms: f64,
    pub resp_ts: Option<f64>,
    pub first_byte_ms: Option<f64>,
    /// 请求已发出、响应未到（防 sweep 误删）
    pub inflight: bool,
    /// 模型名 / 流式标记
    pub model: String,
    pub stream_mode: String,
    /// 后缀是否沿用复用表（诊断）
    pub suffix_reused: bool,
}

#[derive(Debug, Clone)]
pub struct CmdHit {
    pub kind: String,
    pub channel: String,
    pub snippet: String,
    pub ts: f64,
    pub blocked: bool,
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl Session {
    pub fn new() -> Self {
        let t = now();
        Session {
            ts: t,
            req_ts: t,
            req_t0: t,
            ..Default::default()
        }
    }
}

/// 复用表条目 [token_or_orig, label, ts]
#[derive(Clone)]
pub struct RecentEntry {
    pub token: String,
    pub label: String,
    pub ts: f64,
}

/// 内存映射缓存容量上限（超出按最旧 LRU 淘汰；淘汰后由 DB 兜底回填）。
pub const RECENT_MAX: usize = 10000;
/// 清理水位余量：只有超过 `RECENT_MAX + PRUNE_SLACK` 才做全表清理。
///
/// 摊还的关键 —— 见 [`SessionStore::maybe_prune_recent`]。
pub const PRUNE_SLACK: usize = RECENT_MAX / 8;
/// 映射 TTL：全局 24h。内存表与 SQLite 映射表同口径，
/// 避免「内存还能还原、但 DB 已过期导致重启后还原不回来」的不一致窗口。
pub const RECENT_TTL: u64 = 24 * 3600;

/// 全局会话表。
pub struct SessionStore {
    pub sessions: DashMap<String, Session>,
    /// orig → (token, label, ts)
    pub recent_fwd: DashMap<String, RecentEntry>,
    /// token → (orig, label, ts)
    pub recent_rev: DashMap<String, RecentEntry>,
    /// 6位辅音后缀 → token（或 Ambiguous）
    pub recent_suffix: DashMap<String, SuffixIndexValue>,
    /// 自定义词永久映射 orig → token
    pub custom_fwd: DashMap<String, String>,
    /// 自定义词永久映射 token → (orig, label)
    pub custom_rev: DashMap<String, RecentEntry>,
    /// 复用表 TTL（可跟 session_ttl 放大）
    pub ttl_secs: std::sync::atomic::AtomicU64,
    /// 内存未命中时的 DB 兜底查询：orig → (token, label)。
    ///
    /// 内存表只是 SQLite 映射表前面的一层**缓存**（LRU 10000 条 + 24h TTL）。
    /// 被 LRU 挤掉时若不回查 DB，同一敏感值会拿到新随机后缀，
    /// 上游请求前缀变化 → prompt cache 失效。回查命中则回填内存，占位符保持稳定。
    lookup_hook: std::sync::RwLock<Option<MappingLookupHook>>,
}

/// DB 兜底查询钩子：orig → (token, label)
pub type MappingLookupHook =
    std::sync::Arc<dyn Fn(&str) -> Option<(String, String)> + Send + Sync + 'static>;

#[derive(Clone, PartialEq)]
pub enum SuffixIndexValue {
    Token(String),
    Ambiguous,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            recent_fwd: DashMap::new(),
            recent_rev: DashMap::new(),
            recent_suffix: DashMap::new(),
            custom_fwd: DashMap::new(),
            custom_rev: DashMap::new(),
            ttl_secs: std::sync::atomic::AtomicU64::new(RECENT_TTL),
            lookup_hook: std::sync::RwLock::new(None),
        }
    }

    /// 注入 DB 兜底查询钩子（AppState 构造时调用）。
    pub fn set_lookup_hook(&self, hook: MappingLookupHook) {
        if let Ok(mut g) = self.lookup_hook.write() {
            *g = Some(hook);
        }
    }

    fn db_lookup(&self, orig: &str) -> Option<(String, String)> {
        let g = self.lookup_hook.read().ok()?;
        let hook = g.as_ref()?;
        hook(orig)
    }

    /// 把 DB 查回的映射回填进内存两张表 + 后缀索引。
    fn rehydrate(&self, orig: &str, token: &str, label: &str) {
        let now = now();
        self.recent_fwd.insert(
            orig.to_string(),
            RecentEntry {
                token: token.to_string(),
                label: label.to_string(),
                ts: now,
            },
        );
        self.recent_rev.insert(
            token.to_string(),
            RecentEntry {
                token: orig.to_string(),
                label: label.to_string(),
                ts: now,
            },
        );
        self.suffix_index_add(token);
    }

    pub fn set_ttl(&self, session_ttl_secs: u64) {
        self.ttl_secs.store(
            RECENT_TTL.max(session_ttl_secs),
            std::sync::atomic::Ordering::Release,
        );
    }

    pub fn recent_ttl(&self) -> u64 {
        self.ttl_secs.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn new_session(&self, sid: &str) {
        self.sessions.insert(sid.to_string(), Session::new());
    }

    pub fn get(&self, sid: &str) -> Option<dashmap::mapref::one::Ref<'_, String, Session>> {
        self.sessions.get(sid)
    }

    pub fn get_mut(&self, sid: &str) -> Option<dashmap::mapref::one::RefMut<'_, String, Session>> {
        self.sessions.get_mut(sid)
    }

    pub fn touch(&self, sid: &str) {
        if let Some(mut s) = self.sessions.get_mut(sid) {
            s.ts = now();
        }
    }

    pub fn drop_session(&self, sid: &str) {
        self.sessions.remove(sid);
    }

    /// 会话过期清理（对齐 `_sweep`：按 ts + TTL，inflight 跳过）。
    pub fn sweep(&self, ttl_secs: f64) {
        let now = now();
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|kv| {
                let s = kv.value();
                !s.inflight && (now - s.ts) > ttl_secs
            })
            .map(|kv| kv.key().clone())
            .collect();
        for sid in expired {
            self.sessions.remove(&sid);
        }
    }

    /// 为自定义敏感词播种**确定性**占位符（对齐 Python `_sync_custom_word_mappings`）。
    ///
    /// 幂等：每次配置热更新/启动都会调用；已登记且 label 未变的词保持原映射（后缀稳定），
    /// label 变了则重新派生并注销旧 token。
    ///
    /// 必须调用：否则 custom_fwd 永远为空，自定义词的占位符每次重启都变，
    /// 长任务跨重启后历史占位符还原不回来（用户看到裸 {{TERM_xxx}}）。
    pub fn seed_custom_words(&self, words: &[(String, String)]) {
        // 1) 清理已移除/禁用的词
        let active: std::collections::HashSet<&str> =
            words.iter().map(|(w, _)| w.as_str()).collect();
        let stale: Vec<String> = self
            .custom_fwd
            .iter()
            .filter(|kv| !active.contains(kv.key().as_str()))
            .map(|kv| kv.key().clone())
            .collect();
        for w in stale {
            // 先 get 再 remove：避开 DashMap::remove<Q> 的泛型重载在链式调用下的类型误推
            let tok: Option<String> = self.custom_fwd.get(w.as_str()).map(|r| r.clone());
            if let Some(tok) = tok {
                self.custom_fwd.remove(w.as_str());
                self.custom_rev.remove(tok.as_str());
                self.suffix_index_del(tok.as_str());
            }
        }
        // 2) 避让集合：自定义词已有后缀 + 全局活跃后缀
        let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
        for kv in self.custom_rev.iter() {
            let sfx = super::placeholder::token_suffix(kv.key());
            if !sfx.is_empty() {
                used.insert(sfx);
            }
        }
        for kv in self.recent_suffix.iter() {
            if let super::session::SuffixIndexValue::Token(t) = kv.value() {
                let sfx = super::placeholder::token_suffix(t);
                if !sfx.is_empty() {
                    used.insert(sfx);
                }
            }
        }
        let now = now();
        // 3) 逐词播种（label 未变则保留旧映射）
        for (word, label) in words {
            let lab = super::placeholder::safe_label(label);
            if let Some(tok) = self.custom_fwd.get(word.as_str()).map(|r| r.clone()) {
                // 映射稳定：占位符标签未变（safe_label 归一后相等）→ 只刷新时间戳。
                // 注意：即使占位符不变，custom_rev 里的**原始 label** 也要更新，
                // 否则还原后取到的分类是过期的。
                if self
                    .custom_rev
                    .get(&tok)
                    .map(|r| super::placeholder::safe_label(&r.label) == lab)
                    .unwrap_or(false)
                {
                    if let Some(mut r) = self.custom_rev.get_mut(&tok) {
                        r.label = label.clone();
                        r.ts = now;
                    }
                    continue;
                }
                // 占位符标签变了：注销旧记录，重新派生
                self.custom_fwd.remove(word.as_str());
                self.custom_rev.remove(tok.as_str());
                self.suffix_index_del(tok.as_str());
            }
            let suffix = super::placeholder::deterministic_suffix(word, &mut used);
            let token = format!("{{{{{lab}_{suffix}}}}}");
            self.custom_fwd.insert(word.clone(), token.clone());
            self.custom_rev.insert(
                token.clone(),
                RecentEntry {
                    token: word.clone(),
                    label: label.clone(),
                    ts: now,
                },
            );
            self.suffix_index_add(&token);
        }
    }

    /// 该原文是否属于启用的自定义词（永久豁免 TTL/LRU）。
    pub fn is_custom_word_orig(&self, orig: &str) -> bool {
        if let Some(tok) = self.custom_fwd.get(orig) {
            return self.custom_rev.contains_key(tok.as_str());
        }
        false
    }

    /// 该占位符是否属于自定义词的永久映射（对齐 Python `_is_custom_word_token`）。
    pub fn is_custom_word_token(&self, token: &str) -> bool {
        self.custom_rev.contains_key(token)
    }

    /// 取该原文的占位符：TTL 内复用旧的，否则新建并登记（对齐 `_recall_token`）。
    /// `taken(token, suffix)` 由调用方提供后缀冲突检查。
    pub fn recall_token(
        &self,
        orig: &str,
        label: &str,
        taken: &dyn Fn(&str, &str) -> bool,
    ) -> (String, bool) {
        // 安全防套娃：orig 自身是占位符 → 原样返回
        if super::placeholder::placeholder_rx().is_match(orig) {
            return (orig.to_string(), false);
        }
        // 自定义词永久映射
        if let Some(tok) = self.custom_fwd.get(orig) {
            let tok = tok.clone();
            self.touch_recent(&tok, orig);
            self.suffix_index_add(&tok);
            return (tok, false);
        }
        let now = now();
        let ttl = self.recent_ttl() as f64;
        if let Some(hit) = self.recent_fwd.get(orig) {
            let is_custom = self.is_custom_word_orig(orig);
            if is_custom || now - hit.ts <= ttl {
                let token = hit.token.clone();
                drop(hit);
                // 幂等补登记
                self.suffix_index_add(&token);
                if let Some(mut e) = self.recent_fwd.get_mut(orig) {
                    e.ts = now;
                }
                if let Some(mut e) = self.recent_rev.get_mut(&token) {
                    e.ts = now;
                }
                return (token, true);
            }
        }
        // 内存未命中（LRU 淘汰或 TTL 过期）→ 查 SQLite 映射表兜底。
        // 命中则回填内存并复用原占位符：**同一敏感值始终得到同一后缀**，
        // 保证上游请求前缀稳定（prompt cache 不失效）。
        if let Some((token, label)) = self.db_lookup(orig) {
            self.rehydrate(orig, &token, &label);
            return (token, true);
        }
        let token = placeholder::new_token(label, &taken);
        // 旧映射过期：注销 REV / 后缀索引再覆盖 FWD
        if let Some(prev) = self.recent_fwd.get(orig) {
            if prev.token != token {
                self.recent_rev.remove(&prev.token.clone());
                self.suffix_index_del(&prev.token.clone());
            }
        }
        self.recent_fwd.insert(
            orig.to_string(),
            RecentEntry {
                token: token.clone(),
                label: label.to_string(),
                ts: now,
            },
        );
        self.recent_rev.insert(
            token.clone(),
            RecentEntry {
                token: orig.to_string(),
                label: label.to_string(),
                ts: now,
            },
        );
        self.suffix_index_add(&token);
        self.maybe_prune_recent();
        (token, false)
    }

    /// 登记原文→占位符；返回是否沿用复用表旧 token（对齐 `_remember`）。
    pub fn remember(
        &self,
        session: &mut Session,
        orig: &str,
        label: &str,
        taken: &dyn Fn(&str, &str) -> bool,
    ) -> bool {
        if !session.fwd.contains_key(orig) {
            let (token, reused) = self.recall_token(orig, label, taken);
            session.fwd.insert(orig.to_string(), token.clone());
            session.labels.insert(orig.to_string(), label.to_string());
            session.rev.insert(token, orig.to_string());
            // 每次新建都登记（HashSet O(1) 去重；标签从 session.labels 取）
            session.pending_persist.insert(orig.to_string());
            return reused;
        }
        false
    }

    /// 取走并清空「待持久化」集合，返回 (token, orig, label) 列表。
    ///
    /// 必须在**每条走完 mask 的请求**上调用（无论事件库是否可用），
    /// 否则该集合会随会话增长而永不回收。
    pub fn drain_pending_persist(&self, sid: &str) -> Vec<(String, String, String)> {
        let Some(mut s) = self.sessions.get_mut(sid) else {
            return vec![];
        };
        let pending = std::mem::take(&mut s.pending_persist);
        pending
            .into_iter()
            .filter_map(|orig| {
                let tok = s.fwd.get(&orig)?.clone();
                let label = s.labels.get(&orig).cloned().unwrap_or_default();
                Some((tok, orig, label))
            })
            .collect()
    }

    fn touch_recent(&self, token: &str, orig: &str) {
        let now = now();
        if let Some(mut e) = self.recent_rev.get_mut(token) {
            e.ts = now;
        }
        if let Some(mut e) = self.recent_fwd.get_mut(orig) {
            e.ts = now;
        }
    }

    /// 后缀索引登记。撞车即置 Ambiguous（对齐 `_suffix_index_add`）。
    pub fn suffix_index_add(&self, token: &str) {
        let sfx = placeholder::token_suffix(token);
        if !placeholder::suffix_indexable(&sfx) {
            return;
        }
        match self.recent_suffix.get(&sfx) {
            None => {
                self.recent_suffix
                    .insert(sfx, SuffixIndexValue::Token(token.to_string()));
            }
            Some(cur) => {
                let cur = cur.clone();
                if cur != SuffixIndexValue::Token(token.to_string()) {
                    self.recent_suffix.insert(sfx, SuffixIndexValue::Ambiguous);
                }
            }
        }
    }

    /// 后缀索引注销（只删确实指向本 token 的条目）。
    pub fn suffix_index_del(&self, token: &str) {
        let sfx = placeholder::token_suffix(token);
        if sfx.is_empty() {
            return;
        }
        if let Some(v) = self.recent_suffix.get(&sfx) {
            if *v == SuffixIndexValue::Token(token.to_string()) {
                drop(v);
                self.recent_suffix.remove(&sfx);
            }
        }
    }

    /// 按后缀反查真实 token（对齐 `_suffix_real_token`：标签归一化后必须相等）。
    pub fn suffix_real_token(&self, token: &str) -> Option<String> {
        let rx = placeholder::any_braced_suffix_rx();
        let caps = rx.captures(token)?;
        let label_raw = caps.get(1)?.as_str();
        let sfx = caps.get(2)?.as_str().to_lowercase();
        let real = match self.recent_suffix.get(&sfx).map(|v| v.clone()) {
            Some(SuffixIndexValue::Token(t)) => t,
            Some(SuffixIndexValue::Ambiguous) | None => return None,
        };
        if real == token {
            return None;
        }
        let real_label = placeholder::token_label(&real);
        if placeholder::safe_label(label_raw) != placeholder::safe_label(&real_label) {
            return None;
        }
        Some(real)
    }

    /// 占位符 → 原文（对齐 `_lookup`：本会话 → 复用表 → 自定义词 → 套娃解包）。
    pub fn lookup(&self, token: &str, sid: &str) -> Option<String> {
        let mut hit: Option<String> = None;
        if let Some(s) = self.sessions.get(sid) {
            if let Some(orig) = s.rev.get(token) {
                hit = Some(orig.clone());
            }
        }
        if hit.is_none() {
            if let Some(rec) = self.recent_rev.get(token) {
                let orig = rec.token.clone();
                let is_custom = self.is_custom_word_orig(&orig) || self.is_custom_word_token(token);
                let fresh = now() - rec.ts <= self.recent_ttl() as f64;
                drop(rec);
                // TTL 判据必须与 Python `_lookup` 一致：自定义词永久，其余按 24h 窗口。
                //
                // 回归：早期这里额外放行了 `suffix_indexable(token_suffix(token))`，
                // 而**所有**新签发的占位符都是 6 位纯辅音后缀、必然满足它 ——
                // 于是 24h「原文保留窗口」契约对现代占位符完全失效（永不按 TTL 过期），
                // 且与下方嵌套解包分支的判据自相矛盾。
                if is_custom || fresh {
                    self.touch_recent(token, &orig);
                    hit = Some(orig);
                }
            }
        }
        if hit.is_none() {
            if let Some(rec) = self.custom_rev.get(token) {
                hit = Some(rec.token.clone());
            }
        }
        // 防套娃解包（≤5 层）
        let mut depth = 0usize;
        let mut cur = hit;
        let rx = placeholder::placeholder_rx();
        while let Some(h) = cur.clone() {
            if !rx.is_match(&h) || depth >= 5 {
                break;
            }
            depth += 1;
            let mut inner: Option<String> = None;
            if let Some(s) = self.sessions.get(sid) {
                if let Some(o) = s.rev.get(&h) {
                    inner = Some(o.clone());
                }
            }
            if inner.is_none() {
                if let Some(rec) = self.recent_rev.get(&h) {
                    let is_custom = self.is_custom_word_orig(&rec.token.clone())
                        || self.is_custom_word_token(&h);
                    if is_custom || now() - rec.ts <= self.recent_ttl() as f64 {
                        inner = Some(rec.token.clone());
                    }
                }
            }
            if inner.is_none() {
                if let Some(rec) = self.custom_rev.get(&h) {
                    inner = Some(rec.token.clone());
                }
            }
            cur = match inner {
                Some(i) if i != h => Some(i),
                _ => break,
            };
        }
        match cur.clone() {
            Some(h) if rx.is_match(&h) => None, // 最终仍是占位符 = 无真实明文
            other => other,
        }
    }

    /// 摊还版清理：只在超过水位时做一次全表 `prune_recent`。
    ///
    /// 为什么需要：`prune_recent` 会 collect 全表（每条形如
    /// `(key.clone(), token.clone(), ts)`，两份 String）并在超限时排序，成本
    /// O(n log n)。它原先在**每签发一个新占位符**时都跑一次，于是「一个请求里
    /// N 个互不相同的敏感值」= O(N²)。release 实测：200 个唯一值 64ms、
    /// 1000 个 112ms、**3000 个 1130ms**（约 10x 于 1000，典型二次方；
    /// 51KB 的 body 即可触发 1.1s CPU）。
    ///
    /// 批式摊还后：每 `PRUNE_SLACK` 次插入才付一次全表成本，且一次清理把长度
    /// 降到 `RECENT_MAX`，之后的插入都走 O(1) 快路径。
    ///
    /// `prune_recent` 本身保持「精确清理」语义，供批量预热与测试直接调用。
    fn maybe_prune_recent(&self) {
        if self.recent_fwd.len() <= RECENT_MAX + PRUNE_SLACK {
            return;
        }
        self.prune_recent();
    }

    /// TTL + 条数上限清理复用表（对齐 `_prune_recent`）。
    pub fn prune_recent(&self) {
        let now = now();
        let ttl = self.recent_ttl() as f64;
        let stale: Vec<String> = self
            .recent_fwd
            .iter()
            .filter(|kv| !self.is_custom_word_orig(kv.key()) && now - kv.value().ts > ttl)
            .map(|kv| kv.key().clone())
            .collect();
        for k in stale {
            if let Some(entry) = self.recent_fwd.get(&k) {
                let tok = entry.token.clone();
                drop(entry);
                self.recent_fwd.remove(&k);
                self.recent_rev.remove(&tok);
                self.suffix_index_del(&tok);
            }
        }
        let evictable: Vec<(String, String, f64)> = self
            .recent_fwd
            .iter()
            .filter(|kv| !self.is_custom_word_orig(kv.key()))
            .map(|kv| (kv.key().clone(), kv.value().token.clone(), kv.value().ts))
            .collect();
        if evictable.len() > RECENT_MAX {
            let over = evictable.len() - RECENT_MAX;
            let mut oldest: Vec<(String, String, f64)> = evictable;
            oldest.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));
            for (k, tok, _ts) in oldest.into_iter().take(over) {
                self.recent_fwd.remove(&k);
                self.recent_rev.remove(&tok);
                self.suffix_index_del(&tok);
            }
        }
    }

    /// 从事件库预热复用表（对齐 Python `_warmup_recent_from_db`）。
    ///
    /// 为什么需要：普通敏感值的后缀是**随机**的（防上游枚举反推，安全红线），
    /// 映射只存在于内存。进程重启后 AI 若复述历史里的 `{{PHONE_xxx}}`，
    /// 查不到映射就会把裸占位符返回给用户。
    /// 事件库里已经存了非凭据 PII 的 `tok`/`original`/`label`（凭据类只存摘要，
    /// 天然无法也**不应**还原），启动时回读即可重建。
    ///
    /// 安全约束（与 Python 一致）：
    /// - 凭据类同样回读（映射表已全类型落盘，行为保持一致）
    /// - 跳过原文本身是占位符的脏数据
    /// - 按「事件 id 倒序 → 去重 → 正序写入」，保证超容量淘汰时先删最旧
    ///
    /// 返回实际恢复的条数。
    pub fn warmup_from_events(&self, records: Vec<(String, String, String)>) -> usize {
        let now = now();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut collected: Vec<(String, String, String)> = Vec::new();
        for (token, orig, label) in records {
            if token.is_empty() || orig.is_empty() {
                continue;
            }
            // 原文本身是占位符 → 脏数据，跳过
            if super::placeholder::placeholder_rx().is_match(&orig) {
                continue;
            }
            if seen.insert(orig.clone()) {
                collected.push((token, orig, label));
            }
        }
        // 正序写入（collected 已是「最新事件优先」的反序收集，这里翻回来）
        for (token, orig, label) in collected.iter().rev() {
            self.recent_fwd.insert(
                orig.clone(),
                RecentEntry {
                    token: token.clone(),
                    label: label.clone(),
                    ts: now,
                },
            );
            self.recent_rev.insert(
                token.clone(),
                RecentEntry {
                    token: orig.clone(),
                    label: label.clone(),
                    ts: now,
                },
            );
            self.suffix_index_add(token);
        }
        self.prune_recent();
        collected.len()
    }
}

/// 全局会话存储（进程唯一）。
pub static STORE: Lazy<SessionStore> = Lazy::new(SessionStore::new);

/// 后缀占用检查（new_token 的 taken 回调：查 REV 表与后缀索引）。
pub fn token_taken() -> impl Fn(&str, &str) -> bool {
    |token: &str, suffix: &str| {
        STORE.recent_rev.contains_key(token)
            || STORE.custom_rev.contains_key(token)
            || STORE.recent_suffix.contains_key(suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::placeholder::placeholder_rx;

    fn fresh_store() -> SessionStore {
        SessionStore::new()
    }

    #[test]
    fn remember_and_lookup() {
        let store = fresh_store();
        store.new_session("s1");
        let taken = token_taken_static(&store);
        {
            let mut s = store.get_mut("s1").unwrap();
            store.remember(&mut s, "张三", "NAME", &taken);
        }
        let token = store.get("s1").unwrap().fwd["张三"].clone();
        assert!(placeholder_rx().is_match(&token));
        assert_eq!(store.lookup(&token, "s1"), Some("张三".to_string()));
        // 未知 token → None
        assert_eq!(store.lookup("{{NAME_bcdfgh}}", "s1"), None);
    }

    // 让测试拿到基于具体 store 的 taken 闭包
    fn token_taken_static<'a>(store: &'a SessionStore) -> impl Fn(&str, &str) -> bool + 'a {
        move |token: &str, suffix: &str| {
            store.recent_rev.contains_key(token)
                || store.custom_rev.contains_key(token)
                || store.recent_suffix.contains_key(suffix)
        }
    }

    #[test]
    fn same_orig_reuses_token_across_sessions() {
        let store = fresh_store();
        let taken = token_taken_static(&store);
        store.new_session("a");
        store.new_session("b");
        let t1 = {
            let mut s = store.get_mut("a").unwrap();
            store.remember(&mut s, "13812345678", "PHONE", &taken);
            s.fwd["13812345678"].clone()
        };
        let t2 = {
            let mut s = store.get_mut("b").unwrap();
            store.remember(&mut s, "13812345678", "PHONE", &taken);
            s.fwd["13812345678"].clone()
        };
        assert_eq!(t1, t2, "TTL 内同一原文必须复用同一占位符（多轮一致性）");
    }

    #[test]
    fn suffix_lookup_rescues_rewritten_label() {
        let store = fresh_store();
        store.new_session("s");
        let taken = token_taken_static(&store);
        {
            let mut s = store.get_mut("s").unwrap();
            store.remember(&mut s, "192.168.1.1", "IP_PRIVATE", &taken);
        }
        let real = store.get("s").unwrap().fwd["192.168.1.1"].clone();
        // 模型把 {{IPPRIVATE_x}} 改写成 {{IP_PRIVATE_x}} → 按后缀救回
        let suffix = placeholder::token_suffix(&real);
        let rewritten = format!("{{{{IP_PRIVATE_{suffix}}}}}");
        let rescued = store.suffix_real_token(&rewritten);
        assert_eq!(rescued, Some(real.clone()));
        assert_eq!(store.lookup(&real, "s"), Some("192.168.1.1".to_string()));
        // 标签整体换名（{{HOST_x}}）不认
        let bad = format!("{{{{HOST_{suffix}}}}}");
        assert_eq!(store.suffix_real_token(&bad), None);
    }

    #[test]
    fn custom_word_permanent_mapping() {
        let store = fresh_store();
        store.new_session("s");
        let taken = token_taken_static(&store);
        store
            .custom_fwd
            .insert("张三".into(), "{{TERM_zzwkkk}}".into());
        store.custom_rev.insert(
            "{{TERM_zzwkkk}}".into(),
            RecentEntry {
                token: "张三".into(),
                label: "NAME".into(),
                ts: 0.0, // 很旧也不淘汰
            },
        );
        {
            let mut s = store.get_mut("s").unwrap();
            store.remember(&mut s, "张三", "NAME", &taken);
        }
        assert_eq!(store.get("s").unwrap().fwd["张三"], "{{TERM_zzwkkk}}");
        // TTL 过期仍可还原（永久映射）
        assert_eq!(
            store.lookup("{{TERM_zzwkkk}}", "s"),
            Some("张三".to_string())
        );
    }

    #[test]
    fn sweep_drops_expired_not_inflight() {
        let store = fresh_store();
        store.new_session("old");
        store.new_session("live");
        {
            let mut s = store.get_mut("old").unwrap();
            s.ts = now() - 10000.0;
        }
        {
            let mut s = store.get_mut("live").unwrap();
            s.ts = now() - 10000.0;
            s.inflight = true;
        }
        store.sweep(600.0);
        assert!(store.get("old").is_none());
        assert!(store.get("live").is_some());
    }

    #[test]
    fn prune_keeps_custom_and_evicts_oldest() {
        let store = fresh_store();
        let taken = token_taken_static(&store);
        // 自定义词
        store
            .custom_fwd
            .insert("永久词".into(), "{{TERM_pwwkkk}}".into());
        store.custom_rev.insert(
            "{{TERM_pwwkkk}}".into(),
            RecentEntry {
                token: "永久词".into(),
                label: "T".into(),
                ts: 0.0,
            },
        );
        // 灌满 2010 条普通条目
        for i in 0..2010 {
            let mut fake = Session::new();
            store.remember(&mut fake, &format!("orig{i}"), "TERM", &taken);
            // remember 用的是 fake session 的 fwd；还要真正进复用表 —— recall_token 已写入
        }
        store.prune_recent();
        let normal_count = store
            .recent_fwd
            .iter()
            .filter(|kv| !store.is_custom_word_orig(kv.key()))
            .count();
        assert!(
            normal_count <= RECENT_MAX,
            "普通条目数 {normal_count} 应 ≤ {RECENT_MAX}"
        );
        // 自定义词不被淘汰
        assert!(store.custom_fwd.contains_key("永久词"));
    }
}
