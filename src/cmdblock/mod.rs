//! 命令拦截：探测 / 改写 / 阻断三模式 + echo 抑制 + 有界前瞻缓冲（M7）。
//!
//! 对齐 Python `_cmd_process` / `_cmd_find` / `_cmd_rewrite_text` / `_cmd_flush_frames`:
//! - 内置 7 条规则（rm -rf /、rm -rf ~、del 盘符、format/mkfs、DROP DB、dd、fork 炸弹）
//! - observe（默认，零改写）/ rewrite（换 no-op 说明）/ block（停止下发）
//! - echo 抑制：请求体里已有的命令既不记也不改
//! - 通道：tool（工具参数）/ text（正文，需显式 opt-in）/ reason（思考，恒排除但留痕）

use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;

use crate::config::{CmdBlockMode, Config};
use crate::mask::session::{CmdHit, SessionStore};

/// 无界前瞻缓冲上限（对齐 `CMD_HOLD_MAX` = 64）。
pub const CMD_HOLD_MAX: usize = 64;
/// 命令扫描窗口（对齐 `CMD_SCAN_MAX` = 8192）。
pub const CMD_SCAN_MAX: usize = 8192;

/// 单会话的通道缓冲条目上限（防御：恶意/异常流可造出无界 channel 名）。
const MAX_PEND_CHANNELS: usize = 256;

/// 改写文本（**固定字符串，绝不拼入任何变量**——拼原文等于用改写文本重新引入命令）。
pub const CMD_BLOCK_NOTICE: &str =
    "echo '[Maskit] 已阻止高危删除命令，本条为占位说明，未执行任何操作'";

/// 命令规则正则（D7 第 6 条：用户可编辑正则走双通道）。
pub enum CmdRegex {
    Linear(Regex),
    Fancy(fancy_regex::Regex),
}

impl CmdRegex {
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            CmdRegex::Linear(r) => r.is_match(text),
            CmdRegex::Fancy(r) => r.is_match(text).unwrap_or(false),
        }
    }
    /// 首个命中的片段。
    pub fn find_str(&self, text: &str) -> Option<String> {
        match self {
            CmdRegex::Linear(r) => r.find(text).map(|m| m.as_str().to_string()),
            CmdRegex::Fancy(r) => r.find(text).ok().flatten().map(|m| m.as_str().to_string()),
        }
    }
    pub fn find_iter_strings(&self, text: &str) -> Vec<String> {
        match self {
            CmdRegex::Linear(r) => r.find_iter(text).map(|m| m.as_str().to_string()).collect(),
            CmdRegex::Fancy(r) => r
                .find_iter(text)
                .filter_map(|m| m.ok())
                .map(|m| m.as_str().to_string())
                .collect(),
        }
    }
    pub fn replace_all_literal(&self, text: &str, repl: &str) -> String {
        match self {
            // 字面量替换（不用替换模板，避免反向引用解释）
            CmdRegex::Linear(r) => r.replace_all(text, repl).to_string(),
            CmdRegex::Fancy(r) => r.replace_all(text, repl).to_string(),
        }
    }
}

/// 内置规则的**可序列化形态**（供 `Config` 默认值播种）。
///
/// 与 `builtin_patterns()`（编译后、供引擎直接用）一一对应，
/// 保证「落进 config.json 的」与「引擎实际跑的」是同一批规则。
pub fn default_builtin_patterns() -> Vec<crate::config::CmdPattern> {
    specs()
        .into_iter()
        .map(|(id, label, regex)| crate::config::CmdPattern {
            id: id.to_string(),
            label: label.to_string(),
            regex: regex.to_string(),
            enabled: true,
            builtin: true,
        })
        .collect()
}

/// 内置规则的 (id, label, regex) 规格（唯一定义源）。
fn specs() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "builtin-rm-root",
            "递归删除根目录",
            r"(?i)\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:/|/\*)(?:\s|$|;|&|\|)",
        ),
        (
            "builtin-rm-home",
            "递归删除家目录",
            r"(?i)\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+~(?:/\*?)?(?=\s|$|;|&|\|)",
        ),
        (
            "builtin-del-win",
            "Windows 全盘删除",
            r#"(?i)(?:^|[\s;&|])(?:del|erase)\s+/[sq]\b[^\n]{0,40}[A-Za-z]:[\\/]?(?:\s|$)|\bRemove-Item\b[^\n]{0,60}-Recurse\b[^\n]{0,40}-Force\b[^\n]{0,20}[A-Za-z]:\\(?:\s|$|")"#,
        ),
        (
            "builtin-format",
            "格式化磁盘/块设备",
            r"(?i)(?:\bformat\s+[A-Za-z]:|\bmkfs(?:\.\w+)?\s+/dev/)",
        ),
        (
            "builtin-drop-db",
            "删除数据库/表",
            r"(?i)(?:\bdrop\s+(?:database|schema)\b|\bdrop\s+table\b|\btruncate\s+table\b)",
        ),
        (
            "builtin-dd",
            "dd 直写块设备",
            r"(?i)\bdd\s+[^\n]{0,60}\bof=/dev/(?:sd[a-z]|nvme\d|disk\d)",
        ),
        (
            "builtin-forkbomb",
            "fork 炸弹",
            r":\(\)\s*\{\s*:\|\s*:&\s*\}\s*;\s*:",
        ),
    ]
}

/// 编译命令规则（regex 优先，失败回退 fancy —— 内置规则含 lookahead）。
pub fn compile_cmd(pat: &str) -> Option<CmdRegex> {
    if let Ok(r) = Regex::new(pat) {
        return Some(CmdRegex::Linear(r));
    }
    if let Ok(r) = fancy_regex::Regex::new(pat) {
        return Some(CmdRegex::Fancy(r));
    }
    None
}

/// 内置 7 条危害命令规则（对齐 `BUILTIN_COMMAND_BLOCK_PATTERNS`）。
pub fn builtin_patterns() -> Vec<(String, String, CmdRegex)> {
    // 双通道编译（含 lookahead 的规则走 fancy-regex，D7 第 6 条）
    specs()
        .into_iter()
        .filter_map(|(id, label, pat)| {
            compile_cmd(pat).map(|rx| (id.to_string(), label.to_string(), rx))
        })
        .collect()
}

/// 编译后的规则集。
pub struct CmdBlockEngine {
    pub mode: CmdBlockMode,
    pub channels: HashSet<String>,
    pub patterns: Vec<(String, String, CmdRegex)>,
    pub allow: Vec<Regex>,
    /// 超预算被停用的规则 id
    pub disabled: std::sync::Mutex<HashSet<String>>,
}

impl CmdBlockEngine {
    pub fn new(cfg: &Config) -> Self {
        let cb = &cfg.command_block;
        let mut patterns: Vec<(String, String, CmdRegex)> = Vec::new();
        for p in &cb.patterns {
            if !p.enabled {
                continue;
            }
            if let Some(rx) = compile_cmd(&p.regex) {
                patterns.push((p.id.clone(), p.label.clone(), rx));
            }
        }
        let allow = cb
            .allow_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();
        Self {
            mode: cb.mode,
            channels: cb.channels.iter().cloned().collect(),
            patterns,
            allow,
            disabled: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// 空引擎（关闭命令拦截）。
    pub fn empty() -> Self {
        Self {
            mode: CmdBlockMode::Observe,
            channels: HashSet::new(),
            patterns: vec![],
            allow: vec![],
            disabled: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// 通道名 → 类型（对齐 `_cmd_channel_kind`）。
    pub fn channel_kind(channel: &str) -> &'static str {
        let ch = channel.to_ascii_lowercase();
        const REASON: &[&str] = &[".reason", ".reason2", ".think", "thinking", "reasoning"];
        const TOOL: &[&str] = &[
            ".tool",
            ".fcall",
            ".pj",
            ".args",
            "arguments",
            "partial_json",
        ];
        if REASON.iter().any(|m| ch.contains(m)) {
            return "reason";
        }
        if TOOL.iter().any(|m| ch.contains(m)) {
            return "tool";
        }
        "text"
    }

    /// 在文本里找第一条命中的启用规则（白名单优先）。
    pub fn find(&self, text: &str) -> Option<(String, String, String)> {
        if self.patterns.is_empty() || text.is_empty() {
            return None;
        }
        let window: &str = if text.len() > CMD_SCAN_MAX {
            &text[..CMD_SCAN_MAX]
        } else {
            text
        };
        let disabled = self.disabled.lock().unwrap();
        for (id, label, rx) in &self.patterns {
            if disabled.contains(id) {
                continue;
            }
            if let Some(found) = rx.find_str(window) {
                let hit = found.trim().to_string();
                if hit.is_empty() {
                    continue;
                }
                if self.allow.iter().any(|a| a.is_match(&hit)) {
                    continue;
                }
                return Some((hit.chars().take(120).collect(), id.clone(), label.clone()));
            }
        }
        None
    }

    /// 该片段是否已在请求体里出现（回声抑制）。
    pub fn is_echo(&self, sid: &str, snippet: &str, store: &SessionStore) -> bool {
        let Some(s) = store.get(sid) else {
            return false;
        };
        if let Some(set) = &s.cmd_req_snippets {
            return set.contains(snippet);
        }
        // 惰性构建回声中（只算一次）
        let win = s.cmd_req_window.clone();
        drop(s);
        let mut found = HashSet::new();
        if let Some(win) = win {
            let text = String::from_utf8_lossy(&win).to_string();
            for (_id, _l, rx) in &self.patterns {
                for g in rx.find_iter_strings(&text) {
                    let g = g.trim();
                    if !g.is_empty() {
                        found.insert(g.chars().take(120).collect::<String>());
                    }
                }
            }
        }
        if let Some(mut s) = store.get_mut(sid) {
            s.cmd_req_window = None;
            s.cmd_req_snippets = Some(found.clone());
        }
        found.contains(snippet)
    }

    /// 记录请求期窗口切片（惰性回声基线，对齐 `_remember_request_cmd_snippets`）。
    pub fn remember_request_window(&self, sid: &str, content: &[u8], store: &SessionStore) {
        if self.patterns.is_empty() {
            return;
        }
        if let Some(mut s) = store.get_mut(sid) {
            let take = content.len().min(CMD_SCAN_MAX);
            s.cmd_req_window = Some(content[..take].to_vec());
        }
    }

    /// 记录命中（去重 + blocked 升级，对齐 `_cmd_record`）。
    pub fn record(
        &self,
        sid: &str,
        hit: &(String, String, String),
        channel_kind: &str,
        blocked: bool,
        store: &SessionStore,
    ) {
        let (snippet, pid, label) = hit;
        let clean: String = crate::server::response::redact_credentials(snippet)
            .chars()
            .take(120)
            .collect();
        let kind = format!(
            "{}{}",
            pid,
            if label.is_empty() {
                String::new()
            } else {
                format!(" {label}")
            }
        );
        if let Some(mut s) = store.get_mut(sid) {
            for it in s.cmd_hits.iter_mut() {
                if it.kind == kind && it.snippet == clean && it.channel == channel_kind {
                    if blocked {
                        it.blocked = true;
                    }
                    return;
                }
            }
            s.cmd_hits.push(CmdHit {
                kind,
                channel: channel_kind.into(),
                snippet: clean,
                ts: crate::store::events::now_secs(),
                blocked,
            });
        }
    }

    /// 逐槽位处理（返回改写后文本）。
    ///
    /// 语义（对齐 Python）：
    /// - observe：零改写，不做前瞻缓冲
    /// - rewrite/block：有界前瞻（可能被切开的命令拼回来再判）
    pub fn process(
        &self,
        text: &str,
        channel: &str,
        sid: &str,
        store: &SessionStore,
        final_channel: bool,
    ) -> (String, bool) {
        if self.patterns.is_empty() {
            return (text.to_string(), false);
        }
        let kind = Self::channel_kind(channel);
        // 思考通道：既不记也不改，只留片段（供审计去噪）
        if kind == "reason" {
            if let Some(h) = self.find(text) {
                if let Some(mut s) = store.get_mut(sid) {
                    s.cmd_reason_snippets.insert(h.0);
                }
            }
            return (text.to_string(), false);
        }
        if !self.channels.contains(kind) {
            return (text.to_string(), false);
        }
        // block 已命中：剩余内容不再下发
        if store.get(sid).map(|s| s.cmd_blocked).unwrap_or(false) {
            return (String::new(), true);
        }
        if self.mode == CmdBlockMode::Observe {
            if let Some(hit) = self.find(text) {
                if !self.is_echo(sid, &hit.0, store) {
                    self.record(sid, &hit, kind, false, store);
                }
            }
            return (text.to_string(), false);
        }
        // rewrite / block：拼回前瞻尾巴
        let pending = store
            .get(sid)
            .and_then(|s| s.cmd_pend.get(channel).cloned())
            .unwrap_or_default();
        if let Some(mut s) = store.get_mut(sid) {
            s.cmd_pend.remove(channel);
        }
        let mut combined = format!("{pending}{text}");
        let mut keep = String::new();
        if !final_channel && combined.len() > CMD_HOLD_MAX {
            let split = combined.len() - CMD_HOLD_MAX;
            // 按字符边界切
            let mut sp = split;
            while sp > 0 && !combined.is_char_boundary(sp) {
                sp -= 1;
            }
            keep = combined[sp..].to_string();
            combined = combined[..sp].to_string();
        } else if !final_channel && !combined.is_empty() {
            // 整段短于 hold → 全部暂留
            // 通道数有界：超过上限直接放行（宁可不拦这一条，也不让内存被撑爆）
            if store.get(sid).map(|s| s.cmd_pend.len()).unwrap_or(0) < MAX_PEND_CHANNELS {
                if let Some(mut s) = store.get_mut(sid) {
                    s.cmd_pend.insert(channel.to_string(), combined.clone());
                }
                return (String::new(), false);
            }
            // 超上限：把这一段当作已确认文本直接下发，不进入缓冲
        }
        let mut hit = self.find(&combined);
        if let Some(h) = &hit {
            if self.is_echo(sid, &h.0, store) {
                hit = None;
            }
        }
        let mut blocked = false;
        let result = match hit {
            Some(h) => {
                blocked = self.mode == CmdBlockMode::Block;
                self.record(sid, &h, kind, blocked, store);
                if blocked {
                    if let Some(mut s) = store.get_mut(sid) {
                        s.cmd_blocked = true;
                    }
                    String::new()
                } else {
                    self.rewrite(&combined)
                }
            }
            None => combined,
        };
        if !keep.is_empty() {
            if let Some(mut s) = store.get_mut(sid) {
                s.cmd_pend.insert(channel.to_string(), keep);
            }
        }
        (result, blocked)
    }

    /// 把文本里所有命中替换为无害 no-op 说明。
    pub fn rewrite(&self, text: &str) -> String {
        let mut out = text.to_string();
        let disabled = self.disabled.lock().unwrap();
        for (id, _, rx) in &self.patterns {
            if disabled.contains(id) {
                continue;
            }
            out = rx.replace_all_literal(&out, CMD_BLOCK_NOTICE);
        }
        out
    }

    /// JSON 树处理（非流式：通道由键名判定，final=true）。
    pub fn process_tree(
        &self,
        mut v: Value,
        sid: &str,
        store: &SessionStore,
        blocked: &mut bool,
    ) -> Value {
        if self.patterns.is_empty() {
            return v;
        }
        walk_tree(&mut v, None, self, sid, store, blocked);
        v
    }

    /// 流式字节处理（逐帧还原后的明文；按帧内 JSON 槽位无法拆分时走整体判定）。
    pub fn process_stream_bytes(
        &self,
        bytes: &[u8],
        sid: &str,
        store: &SessionStore,
        final_chunk: bool,
    ) -> (Vec<u8>, bool) {
        if self.patterns.is_empty() || bytes.is_empty() {
            return (bytes.to_vec(), false);
        }
        // SSE/NDJSON 帧：按 channel="text" 兜底处理（工具通道在槽位层已分派）
        let text = String::from_utf8_lossy(bytes).to_string();
        let (out, blocked) = self.process(&text, "c0.content", sid, store, final_chunk);
        (out.into_bytes(), blocked)
    }

    /// 流末补发前瞻缓冲（对齐 `_cmd_flush_frames`）。
    pub fn flush(
        &self,
        sid: &str,
        store: &SessionStore,
        framing: crate::stream::sse::Framing,
    ) -> String {
        if self.patterns.is_empty() {
            return String::new();
        }
        if store.get(sid).map(|s| s.cmd_blocked).unwrap_or(false) {
            if let Some(mut s) = store.get_mut(sid) {
                s.cmd_pend.clear();
            }
            return String::new();
        }
        let pend: Vec<(String, String)> = store
            .get(sid)
            .map(|s| {
                s.cmd_pend
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if pend.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for (channel, leftover) in pend {
            if let Some(mut s) = store.get_mut(sid) {
                s.cmd_pend.remove(&channel);
            }
            if leftover.is_empty() {
                continue;
            }
            let (restored, _) = self.process(&leftover, &channel, sid, store, true);
            if restored.is_empty() {
                continue;
            }
            out.push_str(&match framing {
                crate::stream::sse::Framing::Ndjson => {
                    format!("{}\n", serde_json::json!({"text": restored}))
                }
                crate::stream::sse::Framing::Sse => {
                    format!("data: {}\n\n", serde_json::json!({"text": restored}))
                }
            });
        }
        out
    }
}

fn walk_tree(
    v: &mut Value,
    key: Option<&str>,
    engine: &CmdBlockEngine,
    sid: &str,
    store: &SessionStore,
    blocked: &mut bool,
) {
    match v {
        Value::String(s) => {
            let channel = key.unwrap_or("");
            let (out, b) = engine.process(s, channel, sid, store, true);
            if b {
                *blocked = true;
            }
            *s = out;
        }
        Value::Array(arr) => {
            for item in arr {
                walk_tree(item, key, engine, sid, store, blocked);
            }
        }
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                walk_tree(val, Some(k), engine, sid, store, blocked);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CmdPattern, Config};

    fn cfg_with(mode: CmdBlockMode, channels: &[&str]) -> Config {
        let mut cfg = Config::default();
        cfg.command_block.mode = mode;
        cfg.command_block.channels = channels.iter().map(|s| s.to_string()).collect();
        cfg.command_block.patterns = builtin_patterns()
            .into_iter()
            .map(|(id, label, _)| CmdPattern {
                id,
                label,
                regex: String::new(), // 由 engine 用内置表补充
                enabled: true,
                builtin: true,
            })
            .collect();
        cfg
    }

    fn engine(mode: CmdBlockMode, channels: &[&str]) -> CmdBlockEngine {
        let mut cfg = cfg_with(mode, channels);
        // 直接用内置表（不经 config 的 regex 字段）
        let e = CmdBlockEngine {
            mode,
            channels: channels.iter().map(|s| s.to_string()).collect(),
            patterns: builtin_patterns(),
            allow: vec![],
            disabled: std::sync::Mutex::new(HashSet::new()),
        };
        let _ = &mut cfg;
        e
    }

    /// 回归：默认配置必须**开箱即用**地装载 7 条内置规则。
    /// 曾因 `CommandBlockConfig::default()` 用 `patterns: []`，
    /// 新装实例一条规则都不跑，`rm -rf /` 完全不拦（Python 版是拦的）。
    #[test]
    fn default_config_seeds_builtin_patterns() {
        let cfg = crate::config::Config::default();
        assert_eq!(
            cfg.command_block.patterns.len(),
            7,
            "默认配置必须播种 7 条内置命令规则"
        );
        let e = CmdBlockEngine::new(&cfg);
        assert_eq!(e.patterns.len(), 7, "引擎必须实际装载全部内置规则");
        // 每条都能检出对应危害形态
        for (hazard, expect_id) in [
            ("rm -rf /", "builtin-rm-root"),
            ("rm -rf ~", "builtin-rm-home"),
            ("mkfs.ext4 /dev/sda1", "builtin-format"),
            ("DROP DATABASE prod;", "builtin-drop-db"),
            ("dd if=/dev/zero of=/dev/sda", "builtin-dd"),
            (":(){ :|:& };:", "builtin-forkbomb"),
        ] {
            let hit = e.find(hazard);
            assert!(hit.is_some(), "内置规则漏检：{hazard}");
            assert_eq!(hit.unwrap().1, expect_id, "{hazard} 归到了错误的规则");
        }
        // 序列化形态与编译形态同源（落进 config.json 的和引擎跑的是同一批）
        let seeded = crate::cmdblock::default_builtin_patterns();
        assert_eq!(seeded.len(), 7);
        assert!(seeded.iter().all(|p| p.enabled && p.builtin));
        for p in &seeded {
            let rx = compile_cmd(&p.regex);
            assert!(
                rx.is_some(),
                "内置规则 regex 编译失败：{} {}",
                p.id,
                p.regex
            );
        }
    }

    /// 用户显式清空（`patterns: []`）必须被尊重，不重新播种。
    #[test]
    fn explicit_empty_patterns_is_respected() {
        let mut cfg = crate::config::Config::default();
        cfg.command_block.patterns = vec![];
        let e = CmdBlockEngine::new(&cfg);
        assert!(e.patterns.is_empty(), "用户显式清空后不得重新播种");
        assert!(e.find("rm -rf /").is_none());
    }

    #[test]
    fn channel_kind_mapping() {
        assert_eq!(CmdBlockEngine::channel_kind("c0.tool0"), "tool");
        assert_eq!(CmdBlockEngine::channel_kind("a0.pj"), "tool");
        assert_eq!(CmdBlockEngine::channel_kind("arguments"), "tool");
        assert_eq!(CmdBlockEngine::channel_kind("c0.content"), "text");
        assert_eq!(CmdBlockEngine::channel_kind("c0.reason"), "reason");
        assert_eq!(CmdBlockEngine::channel_kind("thinking"), "reason");
    }

    #[test]
    fn observe_mode_never_alters_bytes() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        for text in ["rm -rf /", "正常回复", "a".repeat(500).as_str()] {
            let (out, blocked) = e.process(text, "c0.tool0", "t", &store, false);
            assert_eq!(out, text, "observe 必须零改写");
            assert!(!blocked);
        }
    }

    #[test]
    fn observe_records_hit_with_dedup() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        for _ in 0..5 {
            e.process(
                "执行 rm -rf / --no-preserve-root",
                "c0.tool0",
                "t",
                &store,
                false,
            );
        }
        let s = store.get("t").unwrap();
        assert_eq!(s.cmd_hits.len(), 1, "同一命令去重");
        assert!(s.cmd_hits[0].kind.contains("builtin-rm-root"));
    }

    #[test]
    fn reason_channel_excluded() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let text = "我在考虑要不要 rm -rf / 但这样会删系统";
        let (out, _) = e.process(text, "c0.reason", "t", &store, false);
        assert_eq!(out, text, "思考通道零改写");
        let s = store.get("t").unwrap();
        assert!(s.cmd_hits.is_empty(), "思考通道不产生条目");
        assert!(!s.cmd_reason_snippets.is_empty(), "但留痕供审计去噪");
    }

    #[test]
    fn text_channel_requires_opt_in() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        e.process("rm -rf /", "c0.content", "t", &store, false);
        assert!(store.get("t").unwrap().cmd_hits.is_empty(), "正文默认不拦");
        let e2 = engine(CmdBlockMode::Observe, &["tool", "text"]);
        let store2 = SessionStore::new();
        store2.new_session("t");
        e2.process("rm -rf /", "c0.content", "t", &store2, false);
        assert_eq!(store2.get("t").unwrap().cmd_hits.len(), 1);
    }

    #[test]
    fn echo_suppression() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        // 预置回声基线
        if let Some(mut s) = store.get_mut("t") {
            s.cmd_req_snippets = Some(["rm -rf /".to_string()].into_iter().collect());
        }
        let (out, _) = e.process("rm -rf / 很危险", "c0.tool0", "t", &store, true);
        assert!(out.contains("rm -rf /"), "回声不改写");
        assert!(!out.contains("Maskit"));
        assert!(store.get("t").unwrap().cmd_hits.is_empty());
    }

    #[test]
    fn cross_chunk_split_command_rewritten() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let mut out = String::new();
        // 注意块间要有空白：`xxxrm -rf /` 里 `\brm` 不匹配（测的就不是跨块缓冲了）
        let pad = format!("{} ", "x".repeat(100));
        for chunk in [pad.as_str(), "rm -r", "f /", " 完成"] {
            let (o, _) = e.process(chunk, "c0.tool0", "t", &store, false);
            out.push_str(&o);
        }
        let (tail, _) = e.process("", "c0.tool0", "t", &store, true);
        out.push_str(&tail);
        assert!(out.contains("Maskit"), "跨块命令必须改写：{out}");
        assert!(!out.contains("rm -rf /"));
        assert!(out.contains("完成"), "命令之后的正文不能被吞");
    }

    #[test]
    fn rewrite_uses_fixed_notice() {
        assert!(CMD_BLOCK_NOTICE.starts_with("echo '"));
        assert!(!CMD_BLOCK_NOTICE.contains('{'));
        assert_eq!(
            CMD_BLOCK_NOTICE.matches('\'').count(),
            2,
            "固定 no-op，引号闭合"
        );
    }

    #[test]
    fn block_mode_stops_output() {
        let e = engine(CmdBlockMode::Block, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let long = format!("rm -rf / {}", "z".repeat(200));
        let (out, blocked) = e.process(&long, "c0.tool0", "t", &store, false);
        assert!(blocked);
        assert!(out.is_empty(), "block 模式命中即停止下发");
        assert!(store.get("t").unwrap().cmd_blocked);
        // 后续内容也不下发
        let (out2, _) = e.process("之后的正常内容", "c0.tool0", "t", &store, false);
        assert!(out2.is_empty());
    }

    #[test]
    fn whitelist_priority() {
        let mut e = engine(CmdBlockMode::Observe, &["tool"]);
        e.allow = vec![Regex::new(r"rm\s+-rf\s+dist").unwrap()];
        assert!(e.find("rm -rf dist").is_none(), "白名单优先");
        assert!(e.find("rm -rf /").is_some());
    }

    #[test]
    fn daily_commands_not_matched() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        for cmd in [
            "npm run build",
            "rm -rf node_modules",
            "rm -rf ./dist",
            "git push --force-with-lease",
            "SELECT * FROM users WHERE id = 1",
        ] {
            assert!(e.find(cmd).is_none(), "日常命令误伤：{cmd}");
        }
    }

    #[test]
    fn every_builtin_matches_hazard() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let cases = [
            ("rm -rf /", "builtin-rm-root"),
            ("rm -rf ~", "builtin-rm-home"),
            ("mkfs.ext4 /dev/sda1", "builtin-format"),
            ("DROP DATABASE prod;", "builtin-drop-db"),
            ("TRUNCATE TABLE users", "builtin-drop-db"),
            ("dd if=/dev/zero of=/dev/sda bs=1M", "builtin-dd"),
            (":(){ :|:& };:", "builtin-forkbomb"),
        ];
        for (cmd, expect) in cases {
            let hit = e.find(cmd);
            assert!(hit.is_some(), "漏检：{cmd}");
            assert_eq!(hit.unwrap().1, expect, "{cmd}");
        }
    }

    #[test]
    fn tree_processing_maps_json_keys_to_channels() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let v = serde_json::json!({
            "choices": [{"message": {"tool_calls": [
                {"function": {"name": "run", "arguments": "rm -rf /"}}]}}]
        });
        let mut blocked = false;
        let out = e.process_tree(v, "t", &store, &mut blocked);
        let args = out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert_eq!(args, CMD_BLOCK_NOTICE);
        assert!(!args.contains("rm -rf /"));
        // JSON 仍合法
        assert!(serde_json::from_str::<Value>(&serde_json::to_string(&out).unwrap()).is_ok());
    }
}
