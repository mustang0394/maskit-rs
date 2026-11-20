//! 命令拦截：探测 / 改写 / 阻断三模式 + echo 抑制 + 有界前瞻缓冲（M7）。
//!
//! 对齐 Python `_cmd_process` / `_cmd_find` / `_cmd_rewrite_text` / `_cmd_flush_frames`:
//! - 内置 8 条规则（rm -rf /、rm -rf ~、del 盘符、format/mkfs、DROP DB、dd、fork 炸弹）
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
/// 完整扫描上限：≤1MiB 全量扫描，超过则只扫头尾（避免长响应退化）。
const CMD_SCAN_FULL_MAX: usize = 1 << 20;
/// 超限时头/尾各扫描的字节数。
const CMD_SCAN_EDGE: usize = 64 << 10;

/// 扫描窗口：≤1MiB 全量；超过时头尾各 64KiB。
///
/// 旧实现只看前 8KiB，危险命令写在长文本后半段即漏；而全量扫描
/// 大响应又会拖慢热路径，因此用「头+尾」折中。
fn scan_windows(text: &str) -> Vec<&str> {
    if text.len() <= CMD_SCAN_FULL_MAX {
        return vec![text];
    }
    let head = crate::util::truncate_utf8(text, CMD_SCAN_EDGE);
    let start = crate::util::floor_boundary(text, text.len().saturating_sub(CMD_SCAN_EDGE));
    vec![head, &text[start..]]
}

fn floor_byte_boundary(b: &[u8], idx: usize) -> usize {
    let mut i = idx.min(b.len());
    while i > 0 && i < b.len() && (b[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    i
}

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
            r#"(?i)\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+["']?(?:/|/\*)(?:\s|$|;|&|\||"|')"#,
        ),
        (
            // 现代 GNU rm 唯一真能删根的写法：--no-preserve-root 常放在
            // 目标 `/` 前、与被禁的 `-rf` 分开。旧规则要求 flags 后紧跟 `/`，
            // 因此 `rm -rf --no-preserve-root /` 完全绕过。
            "builtin-rm-root-nopreserve",
            "递归删除根目录(--no-preserve-root)",
            r#"(?i)\brm\s+[^\n]{0,80}--no-preserve-root[^\n]{0,40}["']?(?:/|/\*)(?:\s|$|;|&|\||"|')"#,
        ),
        (
            "builtin-rm-home",
            "递归删除家目录",
            r#"(?i)\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+~(?:/\*?)?(?=\s|$|;|&|\||"|')"#,
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

/// 内置危害命令规则（对齐 Python `BUILTIN_COMMAND_BLOCK_PATTERNS`）。
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
    /// 当前生效的密钥前缀：命中片段落库前的凭据清洗要用真实配置，
    /// 否则控制台里自定义的前缀（如 `ak-`）会在 `cmd_hits.snippet` 里漏明文。
    pub secret_prefixes: Vec<String>,
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
            secret_prefixes: cfg.mask.secret_prefixes.clone(),
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
            secret_prefixes: crate::mask::engine::default_secret_prefixes()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            disabled: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// 通道名 → 类型（对齐 `_cmd_channel_kind`）。
    pub fn channel_kind(channel: &str) -> &'static str {
        let ch = channel.to_ascii_lowercase();
        const REASON: &[&str] = &[".reason", ".reason2", ".think", "thinking", "reasoning"];
        // `.tool` 不在此列：槽位要按「点 + tool + 数字/结束」精确判断
        // （见 `has_tool_slot`），否则 `c0.tools_list` 这类正文字段会被误判。
        const TOOL: &[&str] = &[
            ".fcall",
            ".pj",
            ".args",
            "arguments",
            "partial_json",
            "tool_input",
            "tool_use",
            "input_json",
            "tool_call",
        ];
        // 通用增量通道带 `x` 前缀（`c0.xtool_input`），原字段名才是语义来源。
        // 不剥前缀时 `c0.xtool_input` 不含 `.tool`/`arguments`，会被当正文放过。
        let stripped = ch.replace(".x", ".");
        let candidates = [ch.as_str(), stripped.as_str()];
        // 协议元数据（调用 ID / 关联 ID / 名称 / 索引 / 签名）不是命令载荷：
        // `tool_use_id`、`tool_call_id` 含 `tool_use`/`tool_call` 子串，若按子串
        // 归类，rewrite 会把协议关联 ID 改写成占位说明，block 会误阻断工具结果。
        if candidates.iter().any(|c| is_protocol_meta_key(c)) {
            return "text";
        }
        // 工具**输出/结果**事件不是「即将执行的参数」：`response.tool_call_output.delta`、
        // `tool_result` 等含 `tool_call`/`tool_use` 子串，按子串归类会把工具
        // 执行结果改写/阻断，破坏结果回传。
        if candidates.iter().any(|c| is_tool_output_key(c)) {
            return "text";
        }
        if candidates
            .iter()
            .any(|c| REASON.iter().any(|m| c.contains(m)))
        {
            return "reason";
        }
        // `.tool` 必须后接数字或结束（`c0.tool0` / `c0.tool`）：
        // 单纯 `contains(".tool")` 会把 `c0.tools_list` 这类正文字段误判成工具通道。
        if candidates.iter().any(|c| has_tool_slot(c))
            || candidates
                .iter()
                .any(|c| TOOL.iter().any(|m| c.contains(m)))
        {
            return "tool";
        }
        "text"
    }

    /// 当前模式（供代理层决定流式是否可安全改写/阻断）。
    pub fn mode(&self) -> CmdBlockMode {
        self.mode
    }

    /// 是否配置了任何要扫描的通道。
    pub fn has_channels(&self) -> bool {
        !self.channels.is_empty()
    }

    /// rewrite/block 模式必须整包处理：不能在只看到半帧时下发。
    pub fn requires_whole_body(&self) -> bool {
        self.mode != CmdBlockMode::Observe && !self.channels.is_empty()
    }

    /// observe 模式的流式扫描：从已还原的 SSE/NDJSON 帧里提取文本槽位，
    /// 按真实 channel 记录命中（observe 零改写，无需 hold/pending）。
    ///
    /// 之前流式路径把整帧当 `text` 通道扫描，默认 `channels=["tool"]` 时
    /// 直接被通道闸门跳过 —— 流式工具参数里的危险命令完全不检查。
    pub fn scan_encoded_output(&self, bytes: &[u8], sid: &str, store: &SessionStore) {
        if self.mode != CmdBlockMode::Observe || self.channels.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(bytes);
        let mut unparsed_tool = false;
        for line in text.split('\n') {
            let line = line.trim_start();
            let payload = if let Some(rest) = line.strip_prefix("data:") {
                rest.trim_start()
            } else {
                line
            };
            if payload.is_empty() {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(payload) {
                Ok(v) => {
                    // 工具参数按通道跨帧累积后再判定（逐帧判定会漏掉被切开的
                    // 命令，也会把 `rm -rf /tmp` 的前半段误判成 `rm -rf /`）。
                    for (channel, text, _) in crate::stream::slots::text_slots(&v) {
                        if Self::channel_kind(&channel) == "tool" {
                            self.note_tool_fragment(&channel, &text, sid, store);
                        }
                    }
                    // 完成快照（`output_item.done` / `response.completed` /
                    // 整包 message）带的是完整参数，不走增量聚合，单独判一次。
                    for (_channel, text, _) in crate::stream::slots::snapshot_tool_slots(&v) {
                        let _ = self.process_aggregated_tool(&text, sid, store);
                    }
                    let took = self.event_takes_tool_strings(&v);
                    self.scan_encoded_value_ctx(&v, None, false, took, sid, store)
                }
                Err(_) => {
                    // SSE 单帧超限会被强制切分，切点处是半截 JSON；整帧解析
                    // 必然失败。按 tool 通道对原文兜底扫一遍，避免 observe
                    // 静默丢命中（解析成功时不会走这里，不会重复计数）。
                    if payload.contains("arguments") || payload.contains("partial_json") {
                        unparsed_tool = true;
                    }
                }
            }
        }
        if unparsed_tool && self.channels.contains("tool") {
            let _ = self.process(&text, "arguments", sid, store, false);
        }
    }

    /// 本事件里是否有字符串工具参数已被 `note_tool_fragment` 接管。
    fn event_takes_tool_strings(&self, v: &serde_json::Value) -> bool {
        crate::stream::slots::text_slots(v)
            .iter()
            .any(|(channel, _, _)| Self::channel_kind(channel) == "tool")
    }

    /// `in_tool_args`：是否已进入工具调用参数子树。
    ///
    /// 回归（审查发现 #3）：此前递归只传当前键名，`arguments` 一旦是**对象**，
    /// 内部叶子键变成 `cmd`/`path` 等业务字段，不再包含 `.tool`/`arguments`
    /// 标记 → 被判成 `text` 通道 → 默认 `channels=["tool"]` 直接放过，
    /// 危险命令既不记录也不处置。
    fn scan_encoded_value_ctx(
        &self,
        v: &serde_json::Value,
        key: Option<&str>,
        in_tool_args: bool,
        took_tool_string: bool,
        sid: &str,
        store: &SessionStore,
    ) {
        match v {
            serde_json::Value::String(s) => {
                // 已被聚合器接管的字符串片段：这里再扫会把 `rm -rf /tmp/keep`
                // 的前半段当成删根命令记一条误报（observe 不改写但会告警）。
                if took_tool_string && in_tool_args {
                    return;
                }
                if let Some(k) = key {
                    // 工具参数容器已由 `note_tool_fragment` 累积处理，这里跳过，
                    // 避免逐帧误报/重复记录。
                    if is_tool_args_key(k) {
                        return;
                    }
                    // `process()` 会按传入的通道名**再判一次**类型，所以不能把
                    // 业务键（`cmd`）传进去再期望它按 tool 处理；进入工具参数
                    // 子树后必须显式用工具通道名。
                    let channel = if in_tool_args { TOOL_ARGS_CHANNEL } else { k };
                    if self.channels.contains(Self::channel_kind(channel)) {
                        let _ = self.process(s, channel, sid, store, false);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for x in arr {
                    self.scan_encoded_value_ctx(x, key, in_tool_args, took_tool_string, sid, store);
                }
            }
            serde_json::Value::Object(map) => {
                let tool_use_block = is_anthropic_tool_block(map);
                for (k, v) in map {
                    let enters_tool = in_tool_args
                        || is_tool_args_key(k)
                        || (tool_use_block && is_tool_block_payload_key(k));
                    self.scan_encoded_value_ctx(
                        v,
                        Some(k),
                        enters_tool,
                        took_tool_string,
                        sid,
                        store,
                    );
                }
            }
            _ => {}
        }
    }

    /// 在文本里找第一条命中的启用规则（白名单优先）。
    pub fn find(&self, text: &str) -> Option<(String, String, String)> {
        if self.patterns.is_empty() || text.is_empty() {
            return None;
        }
        let windows = scan_windows(text);
        let disabled = self.disabled.lock().unwrap();
        for (id, label, rx) in &self.patterns {
            if disabled.contains(id) {
                continue;
            }
            for window in &windows {
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
            // 与 `find` 同一窗口策略：≤1MiB 全量；超限存头+尾（用换行隔开，
            // 避免头部与尾部拼接产生假的回声片段）。
            let window = if content.len() <= CMD_SCAN_FULL_MAX {
                content.to_vec()
            } else {
                let head = floor_byte_boundary(content, CMD_SCAN_EDGE);
                let start =
                    floor_byte_boundary(content, content.len().saturating_sub(CMD_SCAN_EDGE));
                let mut v = Vec::with_capacity(head + content.len() - start + 1);
                v.extend_from_slice(&content[..head]);
                v.push(b'\n');
                v.extend_from_slice(&content[start..]);
                v
            };
            s.cmd_req_window = Some(window);
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
        let clean: String =
            crate::server::response::redact_credentials(snippet, &self.secret_prefixes)
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
        walk_tree(&mut v, None, false, true, self, sid, store, blocked);
        v
    }

    /// 整包 SSE/NDJSON 的逐帧处理：**跳过**会被跨帧拼接的字符串片段
    /// （`arguments` / `partial_json`），它们由 `process_aggregated_tool`
    /// 在拼接完整后统一判定。
    ///
    /// 为什么要跳过：逐帧各自按 `final=true` 判定，既漏拦拆开的命令，
    /// 又会对「恰好以 `/` 结尾」的安全前缀误报（如 `rm -rf /tmp` 拆成
    /// `rm -rf /` + `tmp`）。
    pub fn process_tree_defer_streamed(
        &self,
        mut v: Value,
        sid: &str,
        store: &SessionStore,
        blocked: &mut bool,
    ) -> Value {
        if self.patterns.is_empty() {
            return v;
        }
        walk_tree(&mut v, None, false, false, self, sid, store, blocked);
        v
    }

    /// 对**已拼接完整**的工具参数做判定（F-01/F-02 共用入口）。
    ///
    /// - 字符串形式且能解析成 JSON → 解析后按工具上下文扫描/改写，再序列化回
    ///   字符串（外层仍是字符串，内层保持 JSON 合法）；
    /// - 纯文本工具输入 → 直接按文本扫描（不强制 JSON 解析）；
    /// - 解析失败但形似 JSON（以 `{`/`[` 开头）→ 记录诊断并按文本兜底扫描，
    ///   不静默当作安全参数（客户端同样解析失败，不会执行）。
    ///
    /// 返回 `(处理后的参数文本, 是否阻断)`。
    pub fn process_aggregated_tool(
        &self,
        text: &str,
        sid: &str,
        store: &SessionStore,
    ) -> (String, bool) {
        if self.patterns.is_empty() || !self.channels.contains("tool") || text.is_empty() {
            return (text.to_string(), false);
        }
        if let Some(inner) = parse_json_payload(text) {
            let mut v = inner;
            let mut blocked = false;
            walk_tree(&mut v, None, true, true, self, sid, store, &mut blocked);
            if blocked {
                return (text.to_string(), true);
            }
            return (
                serde_json::to_string(&v).unwrap_or_else(|_| text.to_string()),
                false,
            );
        }
        if is_json_like(text) {
            tracing::debug!(
                len = text.len(),
                "工具参数形似 JSON 但解析失败，按文本兜底扫描"
            );
        }
        // 解析失败但形似 JSON：文本里还带 `\"` 转义，直接扫原文会让
        // `rm -rf /\"` 这类边界匹配不到。补一份反转义视图再扫一次。
        if let Some(hit) = self.find(text).filter(|h| !self.is_echo(sid, &h.0, store)) {
            return self.apply_aggregated_hit(text, hit, sid, store);
        }
        if is_json_like(text) {
            let unescaped = unescape_json_like(text);
            if let Some(hit) = self
                .find(&unescaped)
                .filter(|h| !self.is_echo(sid, &h.0, store))
            {
                return self.apply_aggregated_hit(text, hit, sid, store);
            }
        }
        (text.to_string(), false)
    }

    /// 命中后的处置（observe 记录 / rewrite 改写 / block 置位）。
    fn apply_aggregated_hit(
        &self,
        text: &str,
        hit: (String, String, String),
        sid: &str,
        store: &SessionStore,
    ) -> (String, bool) {
        if self.mode == CmdBlockMode::Observe {
            self.record(sid, &hit, "tool", false, store);
            return (text.to_string(), false);
        }
        let blocked = self.mode == CmdBlockMode::Block;
        self.record(sid, &hit, "tool", blocked, store);
        if blocked {
            if let Some(mut s) = store.get_mut(sid) {
                s.cmd_blocked = true;
            }
            (text.to_string(), true)
        } else {
            (self.rewrite(text), false)
        }
    }
    /// observe 流式路径：把跨 chunk 的工具参数片段累积到会话。
    ///
    /// 只有「看起来已经完整」的缓冲才即时判定：
    /// - JSON 参数：能成功解析才判（半截 JSON 解析失败，判了就是误报）；
    /// - JSON 解析失败/纯文本：留到流末 `flush_tool_fragments` 统一判。
    ///
    /// 为什么不能每帧都判：`rm -rf /tmp` 被切在 `/` 上时，前半段 `rm -rf /`
    /// 单独看就是「删根目录」，逐帧判定必然误报。
    pub fn note_tool_fragment(&self, channel: &str, text: &str, sid: &str, store: &SessionStore) {
        const MAX_CHANNELS: usize = 32;
        const MAX_BYTES: usize = 128 * 1024;
        let mut full = {
            let Some(s) = store.get(sid) else {
                return;
            };
            let cur = s.cmd_tool_buf.get(channel).cloned().unwrap_or_default();
            format!("{cur}{text}")
        };
        if full.len() > MAX_BYTES {
            // 超限：丢弃最早的部分（无界缓冲比漏检更危险）。
            let cut = full.len() - MAX_BYTES;
            let mut sp = cut;
            while sp < full.len() && !full.is_char_boundary(sp) {
                sp += 1;
            }
            full = full[sp..].to_string();
        }
        if let Some(mut s) = store.get_mut(sid) {
            if s.cmd_tool_buf.len() < MAX_CHANNELS || s.cmd_tool_buf.contains_key(channel) {
                s.cmd_tool_buf.insert(channel.to_string(), full.clone());
            }
        }
        if parse_json_payload(&full).is_some() {
            let _ = self.process_aggregated_tool(&full, sid, store);
        }
    }

    /// 流末（或异常结束）统一判定尚未判定的工具参数缓冲，并释放状态。
    ///
    /// 客户端提前断开时流末代码可能不执行，`sweep` 会回收会话，
    /// 缓冲随会话一起释放，不会跨请求残留。
    pub fn flush_tool_fragments(&self, sid: &str, store: &SessionStore) {
        let bufs: Vec<(String, String)> = match store.get(sid) {
            Some(s) => s
                .cmd_tool_buf
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            None => return,
        };
        if let Some(mut s) = store.get_mut(sid) {
            s.cmd_tool_buf.clear();
        }
        for (_channel, full) in bufs {
            if full.is_empty() {
                continue;
            }
            let _ = self.process_aggregated_tool(&full, sid, store);
        }
    }

    /// 流式字节处理（逐帧还原后的明文；按帧内 JSON 槽位无法拆分时走整体判定）。
    ///
    /// ⚠️ 仅在**整段报文**（JSON 解析失败回退）路径使用：它把整块文本当成
    /// `c0.content`（text 通道）扫描。默认 `channels=["tool"]` 时该通道被跳过，
    /// 因此不能用来处理工具参数增量 —— 那走 `scan_encoded_output`。
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

#[allow(clippy::too_many_arguments)]
fn walk_tree(
    v: &mut Value,
    key: Option<&str>,
    in_tool_args: bool,
    final_frame: bool,
    engine: &CmdBlockEngine,
    sid: &str,
    store: &SessionStore,
    blocked: &mut bool,
) {
    match v {
        Value::String(s) => {
            let channel = key.unwrap_or("");
            // 增量帧（`final_frame=false`）且已在工具参数内：这段载荷由聚合器
            // 按通道拼接后统一判定。这里**绝不能**按片段扫描 ——
            // `rm -rf /` + `tmp/keep` 的完整值是安全路径，逐片看却是删根命令。
            if !final_frame && in_tool_args {
                return;
            }
            let (out, b) = if in_tool_args {
                engine.process(s, TOOL_ARGS_CHANNEL, sid, store, true)
            } else {
                engine.process(s, channel, sid, store, true)
            };
            if b {
                *blocked = true;
            }
            *s = out;
        }
        Value::Array(arr) => {
            for item in arr {
                walk_tree(
                    item,
                    key,
                    in_tool_args,
                    final_frame,
                    engine,
                    sid,
                    store,
                    blocked,
                );
            }
        }
        Value::Object(map) => {
            let tool_use_block = is_anthropic_tool_block(map);
            for (k, val) in map.iter_mut() {
                // ── 参数容器边界：只在这里判定一次 ──
                //
                // 不能在「字符串叶子」里按字段名再判：进入业务参数后同名键
                // （`input`、`arguments`）是**实际值**，再解析/序列化会改坏
                // 工具入参（例如 `"input": "{ \"x\": 1 }"` → `{"x":1}`）。
                if !in_tool_args && is_tool_args_key(k) {
                    match val {
                        Value::String(inner) => {
                            // 增量帧：片段交给聚合器；快照帧：完整值就地判定
                            if final_frame {
                                let (out, b) = engine.process_aggregated_tool(inner, sid, store);
                                if b {
                                    *blocked = true;
                                }
                                *inner = out;
                            }
                            continue;
                        }
                        Value::Object(_) | Value::Array(_) => {
                            // 结构化参数（对象/数组）本身就是完整值：它不可能被
                            // 「跨帧拼接」（半截 JSON 不合法），必须整棵扫描。
                            // 之前沿用 `final_frame=false` 直接跳字符串叶子，
                            // 对象形式的流式工具参数因此完全漏拦。
                            walk_tree(val, Some(k), true, true, engine, sid, store, blocked);
                            continue;
                        }
                        _ => {}
                    }
                }
                let enters = in_tool_args || (tool_use_block && is_tool_block_payload_key(k));
                // 工具块里的结构化载荷（Anthropic `tool_use.input` 等）同理：
                // 完整结构，不能按增量片段跳过。
                let child_final = final_frame
                    || (tool_use_block
                        && is_tool_block_payload_key(k)
                        && matches!(val, Value::Object(_) | Value::Array(_)));
                walk_tree(
                    val,
                    Some(k),
                    enters,
                    child_final,
                    engine,
                    sid,
                    store,
                    blocked,
                );
            }
        }
        _ => {}
    }
}

/// 解析工具参数字符串里的「内层 JSON」。
///
/// 客户端最终使用的往往是 `arguments` 字符串里再套一份 JSON（Chat Completions
/// 规范如此）。直接拿带转义的整串去跑命令正则，`/` 后面紧跟 `\"`，内置
/// 根目录删除规则永远匹配不到 —— F-01 的根因。
fn parse_json_payload(text: &str) -> Option<Value> {
    let t = text.trim_start();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return None;
    }
    serde_json::from_str::<Value>(t).ok()
}

/// 是否形似 JSON（解析失败时用于选择兜底策略与诊断）。
fn is_json_like(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// 尽力反转义（只处理 JSON 字符串里常见的 `\"`、`\\`、`\n`、`\t`），
/// 用于「形似 JSON 但整体解析失败」的兜底扫描。仅影响检测视图，不改写原文。
fn unescape_json_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut it = text.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.peek() {
            Some('"') => {
                out.push('"');
                it.next();
            }
            Some('\\') => {
                out.push('\\');
                it.next();
            }
            Some('n') => {
                out.push('\n');
                it.next();
            }
            Some('t') => {
                out.push('\t');
                it.next();
            }
            _ => out.push('\\'),
        }
    }
    out
}

/// 进入工具参数子树后使用的统一通道名（`channel_kind` 判为 `tool`）。
const TOOL_ARGS_CHANNEL: &str = "arguments";

/// 工具输出 / 结果事件（不是输入参数）。
fn is_tool_output_key(ch: &str) -> bool {
    const OUT: &[&str] = &[
        "tool_output",
        "tool_result",
        "tool_response",
        "tool_call_output",
        "tool_use_result",
        "tool_call_result",
    ];
    OUT.iter().any(|m| ch.contains(m))
}

/// 协议元数据字段（调用 ID / 关联 ID / 名称 / 索引 / 签名等）。
///
/// 这些字段只用于客户端定位与关联工具调用，不是命令载荷；一旦被归入 tool
/// 通道，rewrite 会改坏协议关联 ID，block 会误阻断整个工具结果。
fn is_protocol_meta_key(ch: &str) -> bool {
    const META: &[&str] = &[
        "tool_use_id",
        "tool_call_id",
        "tool_id",
        "call_id",
        "item_id",
        "call_index",
        "index",
        "name",
        "signature",
    ];
    // 只比对最后一个 `.` 之后的段（通道形如 `c0.tool_use_id` / `tool_use_id`），
    // 避免把 `arguments.name`（参数里的业务字段）误判成协议元数据。
    let seg = ch.rsplit('.').next().unwrap_or(ch);
    META.contains(&seg)
}

/// `.tool` 槽位：必须以数字开头（`c0.tool0`、`c0.tool0@1`）或正好结束。
fn has_tool_slot(ch: &str) -> bool {
    let mut rest = ch;
    while let Some(i) = rest.find(".tool") {
        let after = &rest[i + ".tool".len()..];
        if after.is_empty() || after.as_bytes()[0].is_ascii_digit() {
            return true;
        }
        rest = &after[0..];
    }
    false
}

/// 该键是否开启「工具调用参数」子树。
///
/// 只认协议里明确的参数容器，避免任意字段名含 `tool` 就被误判成工具通道
/// （例如正文里出现 `tool_settings` 之类的普通字段）。
fn is_tool_args_key(k: &str) -> bool {
    matches!(
        k.to_ascii_lowercase().as_str(),
        "arguments" | "partial_json" | "tool_input" | "tool_args" | "input_json"
    )
}

/// 工具块/工具事件：`type` 标识了「这块内容是工具调用」。
///
/// 覆盖 Anthropic `tool_use` / `server_tool_use`，以及 Responses 风格
/// `custom_tool_call_input.delta` / `response.tool_input.delta`。
/// 不能把任意 `input`/`delta` 字段都当工具参数 —— Responses API 的顶层
/// `input`、普通业务 JSON 都可能用它，误判会让正文被 rewrite/block。
fn is_anthropic_tool_block(map: &serde_json::Map<String, Value>) -> bool {
    map.get("type").and_then(Value::as_str).is_some_and(|t| {
        let t = t.to_ascii_lowercase();
        // 不能用 `contains("tool_call")` 泛匹配：`response.tool_call_output.delta`
        // 是工具**输出**，会被误当成输入参数改写/阻断。
        if is_tool_output_key(&t) {
            return false;
        }
        t == "tool_use"
            || t == "server_tool_use"
            || (t.ends_with(".delta")
                && (t.contains("custom_tool_call_input")
                    || t.contains("tool_input")
                    || t.contains("tool_call_input")))
    })
}

/// 工具块内承载参数的键。
fn is_tool_block_payload_key(k: &str) -> bool {
    matches!(
        k.to_ascii_lowercase().as_str(),
        "input" | "delta" | "arguments" | "input_json"
    )
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
            secret_prefixes: crate::mask::engine::default_secret_prefixes()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            disabled: std::sync::Mutex::new(HashSet::new()),
        };
        let _ = &mut cfg;
        e
    }

    /// B1 回归：>8KB 中文文本的第 8192 字节落在汉字中间时，`find` 不能 panic。
    #[test]
    fn find_large_cjk_does_not_panic() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        // 9000 字节；8192 % 3 = 2，正好切在字符内部。
        let text = "密".repeat(3000);
        assert!(e.find(&text).is_none());
        // 危险命令在 8KB 之后（当前窗口只扫头部，至少不能因切片崩溃）
        let mut tail = text.clone();
        tail.push_str(" rm -rf /");
        assert!(e.find(&tail).is_some(), "危险命令在 8KB 之后也必须命中");
    }

    /// 回归：默认配置必须**开箱即用**地装载 8 条内置规则。
    /// 曾因 `CommandBlockConfig::default()` 用 `patterns: []`，
    /// 新装实例一条规则都不跑，`rm -rf /` 完全不拦（Python 版是拦的）。
    #[test]
    fn default_config_seeds_builtin_patterns() {
        let cfg = crate::config::Config::default();
        assert_eq!(
            cfg.command_block.patterns.len(),
            8,
            "默认配置必须播种 8 条内置命令规则"
        );
        let e = CmdBlockEngine::new(&cfg);
        assert_eq!(e.patterns.len(), 8, "引擎必须实际装载全部内置规则");
        // 每条都能检出对应危害形态
        for (hazard, expect_id) in [
            ("rm -rf /", "builtin-rm-root"),
            ("rm -rf --no-preserve-root /", "builtin-rm-root-nopreserve"),
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
        assert_eq!(seeded.len(), 8);
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

    /// D2 回归：流式 tool arguments 的 observe 命中必须被记录。
    /// 旧实现把整帧当 text 通道，默认 channels=["tool"] 时直接跳过。
    #[test]
    fn scan_encoded_output_records_tool_hits() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let frame = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"rm -rf /\"}}]}}]}\n\n";
        e.scan_encoded_output(frame.as_bytes(), "s", &store);
        // 纯文本参数要等流末统一判定（逐帧判会把 `rm -rf /tmp` 的前半段误报）
        e.flush_tool_fragments("s", &store);
        assert!(
            !store
                .get("s")
                .map(|s| s.cmd_hits.is_empty())
                .unwrap_or(true),
            "流式 arguments 应记录命令命中"
        );
    }

    /// 回归（审查发现 #3 流式侧）：`delta.tool_input` 走通用桶 → 通道名带
    /// `c0.x` 前缀。旧分类不含 `.tool`，被当正文放过，observe 永不记录。
    #[test]
    fn scan_encoded_output_recognizes_generic_tool_input() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let frame = "data: {\"choices\":[{\"delta\":{\"tool_input\":\"rm -rf /\"}}]}\n\n";
        e.scan_encoded_output(frame.as_bytes(), "s", &store);
        e.flush_tool_fragments("s", &store);
        assert!(
            !store
                .get("s")
                .map(|s| s.cmd_hits.is_empty())
                .unwrap_or(true),
            "通用增量通道里的工具参数必须被记录"
        );
    }

    /// 对象形式的流式工具参数：内部叶子键是 `cmd` 等业务字段，
    /// 必须靠「进入工具参数子树」的上下文判定，而不是键名。
    #[test]
    fn scan_encoded_output_handles_object_arguments() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let frame =
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":{\"cmd\":\"rm -rf /\"}}}]}}]}\n\n";
        e.scan_encoded_output(frame.as_bytes(), "s", &store);
        assert!(
            !store
                .get("s")
                .map(|s| s.cmd_hits.is_empty())
                .unwrap_or(true),
            "对象形式 arguments 的工具参数必须被记录"
        );
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
            ("rm -rf --no-preserve-root /", "builtin-rm-root-nopreserve"),
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

    /// 回归（审查发现 #3）：`arguments` 是**对象**时，内部叶子键是业务字段
    /// （`cmd`/`path`），不含任何 tool 标记。只传当前键名的旧实现会把它判成
    /// `text` 通道，默认 `channels=["tool"]` 直接放过。
    #[test]
    fn tree_processing_handles_object_arguments() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let v = serde_json::json!({
            "choices": [{"message": {"tool_calls": [
                {"function": {"name": "run", "arguments": {"cmd": "rm -rf /"}}}]}}]
        });
        let mut blocked = false;
        let out = e.process_tree(v, "t", &store, &mut blocked);
        let cmd = out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]["cmd"]
            .as_str()
            .unwrap();
        assert_eq!(cmd, CMD_BLOCK_NOTICE, "对象形式 arguments 必须被处置");
        assert!(!cmd.contains("rm -rf /"));
    }

    /// Anthropic 风格工具块：对象 `input` 内的危险命令也按 tool 通道处置。
    #[test]
    fn anthropic_object_input_is_tool_channel() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let v = serde_json::json!({
            "content": [
                {"type": "tool_use", "name": "sh", "input": {"command": "mkfs.ext4 /dev/sda1"}}
            ]
        });
        let mut blocked = false;
        let out = e.process_tree(v, "t", &store, &mut blocked);
        let cmd = out["content"][0]["input"]["command"].as_str().unwrap();
        // rewrite 只替换命中片段，尾巴可能保留（`/dev/sda1` → 匹配到 `/dev/sd`）。
        assert!(cmd.contains(CMD_BLOCK_NOTICE), "未处置: {cmd}");
        assert!(!cmd.contains("mkfs.ext4"), "危险命令仍在: {cmd}");
    }

    /// 通用增量通道 `c0.xtool_input` 带 `x` 前缀，旧分类不含 `.tool`
    /// → 被判成 text 通道，流式 observe 永远不记录工具参数。
    #[test]
    fn generic_x_prefixed_tool_channel_is_tool() {
        assert_eq!(CmdBlockEngine::channel_kind("c0.xtool_input"), "tool");
        assert_eq!(CmdBlockEngine::channel_kind("c0.xarguments"), "tool");
        assert_eq!(CmdBlockEngine::channel_kind("c0.content"), "text");
        assert_eq!(CmdBlockEngine::channel_kind("c0.xtext"), "text");
    }

    /// 普通正文不得因为字段名带 `tool` 就被误判成工具通道。
    #[test]
    fn non_tool_fields_stay_text() {
        assert_eq!(CmdBlockEngine::channel_kind("tool_settings"), "text");
        assert_eq!(CmdBlockEngine::channel_kind("c0.tools_list"), "text");
    }

    /// F-01 回归：`arguments` 是 **JSON 字符串**时，必须先解析内层 JSON 再判定。
    /// 直接用带转义的整串跑正则，`/` 后面紧跟 `\"`，根目录规则永远不命中。
    #[test]
    fn json_string_arguments_are_parsed_before_scanning() {
        for mode in [
            CmdBlockMode::Observe,
            CmdBlockMode::Rewrite,
            CmdBlockMode::Block,
        ] {
            let e = engine(mode, &["tool"]);
            let store = SessionStore::new();
            store.new_session("s");
            let mut blocked = false;
            let v: serde_json::Value = serde_json::from_str(
                r#"{"tool_calls":[{"function":{"name":"sh","arguments":"{\"command\":\"rm -rf /\"}"}}]}"#,
            )
            .unwrap();
            let out = e.process_tree(v, "s", &store, &mut blocked);
            let hits = store.get("s").map(|s| s.cmd_hits.len()).unwrap_or(0);
            match mode {
                CmdBlockMode::Observe => {
                    assert_eq!(hits, 1, "observe 必须记录 JSON 字符串参数里的命令");
                    assert!(!blocked);
                }
                CmdBlockMode::Rewrite => {
                    assert_eq!(hits, 1);
                    let args = out["tool_calls"][0]["function"]["arguments"]
                        .as_str()
                        .unwrap();
                    assert!(!args.contains("rm -rf /"), "rewrite 未生效: {args}");
                    // 外层仍是字符串，且内层仍是合法 JSON
                    let inner: serde_json::Value = serde_json::from_str(args).unwrap();
                    assert!(inner["command"].as_str().is_some());
                }
                CmdBlockMode::Block => {
                    assert!(blocked, "block 必须阻断");
                    assert_eq!(hits, 1);
                }
            }
        }
    }

    /// 同一内容以「字符串」和「对象」两种形式表达时，安全判定必须一致。
    #[test]
    fn string_and_object_arguments_agree() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let mut blocked = false;
        let as_str: serde_json::Value = serde_json::from_str(
            r#"{"tool_calls":[{"function":{"arguments":"{\"cmd\":\"rm -rf /\"}"}}]}"#,
        )
        .unwrap();
        let as_obj: serde_json::Value = serde_json::json!({
            "tool_calls": [{"function": {"arguments": {"cmd": "rm -rf /"}}}]
        });
        let o1 = e.process_tree(as_str, "s", &store, &mut blocked);
        let o2 = e.process_tree(as_obj, "s", &store, &mut blocked);
        assert_eq!(
            o1["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap()
                .contains("rm -rf /"),
            o2["tool_calls"][0]["function"]["arguments"]
                .to_string()
                .contains("rm -rf /"),
            "字符串与对象形式的判定必须一致"
        );
        assert!(!blocked);
    }

    /// 安全参数（不含危险命令）改写后保持语义与类型不变。
    #[test]
    fn safe_json_string_arguments_keep_type_and_semantics() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let mut blocked = false;
        let v: serde_json::Value = serde_json::from_str(
            r#"{"tool_calls":[{"function":{"arguments":"{\"path\":\"a/b\",\"n\":3}"}}]}"#,
        )
        .unwrap();
        let out = e.process_tree(v, "s", &store, &mut blocked);
        let args = out["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let inner: serde_json::Value = serde_json::from_str(args).unwrap();
        assert_eq!(inner["path"], "a/b");
        assert_eq!(inner["n"], 3);
        assert!(!blocked);
    }

    /// F-03 回归：协议关联 ID 不是命令载荷，不得被改写/阻断。
    #[test]
    fn protocol_metadata_ids_are_not_tool_payload() {
        assert_eq!(CmdBlockEngine::channel_kind("tool_use_id"), "text");
        assert_eq!(CmdBlockEngine::channel_kind("c0.tool_call_id"), "text");
        assert_eq!(CmdBlockEngine::channel_kind("arguments"), "tool");

        let mut cfg = crate::config::Config::default();
        cfg.command_block.mode = CmdBlockMode::Rewrite;
        cfg.command_block.channels = vec!["tool".into()];
        cfg.command_block.patterns.push(crate::config::CmdPattern {
            id: "probe-id".into(),
            label: "probe".into(),
            regex: "^srvtoolu_demo$".into(),
            enabled: true,
            builtin: false,
        });
        let e = CmdBlockEngine::new(&cfg);
        let store = SessionStore::new();
        store.new_session("s");
        let mut blocked = false;
        let v = serde_json::json!({
            "content": [{"type": "web_search_tool_result",
                         "tool_use_id": "srvtoolu_demo", "content": []}]
        });
        let out = e.process_tree(v, "s", &store, &mut blocked);
        assert_eq!(out["content"][0]["tool_use_id"], "srvtoolu_demo");
        assert!(!blocked);
    }

    /// 中转发明的 `input_json`（Responses/Anthropic 变体）也是工具参数。
    #[test]
    fn input_json_variants_are_tool_channel() {
        assert_eq!(CmdBlockEngine::channel_kind("a0.xinput_json"), "tool");
        assert_eq!(CmdBlockEngine::channel_kind("a0.input_json"), "tool");
        assert_eq!(CmdBlockEngine::channel_kind("input_json"), "tool");
    }

    /// Responses 自定义工具事件：`type` 里带 `tool_call`，顶层 `delta` 是参数。
    #[test]
    fn custom_tool_call_delta_is_tool_channel() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let frame =
            "data: {\"type\":\"response.custom_tool_call_input.delta\",\"delta\":\"rm -rf /\"}\n\n";
        e.scan_encoded_output(frame.as_bytes(), "s", &store);
        // 纯文本参数要等流末统一判定（逐帧判会把安全路径的前半段误报）
        e.flush_tool_fragments("s", &store);
        assert!(
            !store
                .get("s")
                .map(|s| s.cmd_hits.is_empty())
                .unwrap_or(true),
            "custom_tool_call_input.delta 必须被记录"
        );
    }

    /// 结构化（对象）工具参数：整包流式路径必须整棵扫描，不能因为
    /// 「增量帧跳过字符串叶子」而漏拦。Chat 与 Anthropic 两种形态都覆盖。
    #[test]
    fn object_form_streamed_tool_args_are_scanned() {
        for body in [
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":{\"cmd\":\"rm -rf /\"}}}]}}]}\n\n",
            "data: {\"type\":\"tool_use\",\"input\":{\"command\":\"rm -rf /\"}}\n\n",
        ] {
            for mode in [CmdBlockMode::Rewrite, CmdBlockMode::Block] {
                let mut cfg = crate::config::Config::default();
                cfg.command_block.mode = mode;
                let e = CmdBlockEngine::new(&cfg);
                let store = SessionStore::new();
                store.new_session("s");
                let out = crate::server::response::process_whole(
                    body.as_bytes(),
                    "text/event-stream",
                    "s",
                    &store,
                    &e,
                );
                let text = String::from_utf8_lossy(&out.body).to_string();
                match mode {
                    CmdBlockMode::Rewrite => {
                        assert!(
                            !text.contains("rm -rf /"),
                            "对象参数未被改写: {text}"
                        );
                    }
                    _ => assert!(out.blocked, "对象参数未被阻断: {body}"),
                }
            }
        }
    }

    /// 工具**输出/结果**事件不是输入参数：`response.tool_call_output.delta`、
    /// `tool_result` 等即使含 `tool_call`/`tool_use` 子串也不得进入 tool 通道。
    #[test]
    fn tool_output_events_are_not_tool_input() {
        for ch in [
            "response.tool_call_output.delta",
            "r0.xresponse.tool_call_output.delta",
            "tool_result",
            "tool_call_result",
            "tool_response",
        ] {
            assert_eq!(
                CmdBlockEngine::channel_kind(ch),
                "text",
                "{ch} 不能归为工具参数"
            );
        }
        // 输入事件仍然要识别
        assert_eq!(CmdBlockEngine::channel_kind("arguments"), "tool");
        assert_eq!(
            CmdBlockEngine::channel_kind("r0.xresponse.custom_tool_call_input.delta"),
            "tool"
        );

        // 行为验证：自定义规则命中工具输出时，rewrite 不得改写
        let mut cfg = crate::config::Config::default();
        cfg.command_block.mode = CmdBlockMode::Rewrite;
        cfg.command_block.patterns.push(crate::config::CmdPattern {
            id: "audit".into(),
            label: "audit".into(),
            regex: "^AUDIT$".into(),
            enabled: true,
            builtin: false,
        });
        let e = CmdBlockEngine::new(&cfg);
        let store = SessionStore::new();
        store.new_session("s");
        let body = "data: {\"type\":\"response.tool_call_output.delta\",\"delta\":\"AUDIT\"}\n\n";
        let out = crate::server::response::process_whole(
            body.as_bytes(),
            "text/event-stream",
            "s",
            &store,
            &e,
        );
        let text = String::from_utf8_lossy(&out.body).to_string();
        assert!(!out.blocked, "工具输出不得被阻断");
        assert!(text.contains("AUDIT"), "工具输出被改写: {text}");
    }

    /// observe 对「安全路径跨片段」不得产生误报：`rm -rf /` + `tmp/keep`
    /// 拼接后是安全路径，`cmd_hits` 必须为空。
    #[test]
    fn observe_safe_path_split_records_nothing() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        for frag in ["rm -rf /", "tmp/keep"] {
            let frame = format!(
                "data: {{\"type\":\"response.custom_tool_call_input.delta\",\"delta\":\"{frag}\",\"item_id\":\"c1\"}}\n\n"
            );
            e.scan_encoded_output(frame.as_bytes(), "s", &store);
        }
        e.flush_tool_fragments("s", &store);
        assert!(
            store
                .get("s")
                .map(|s| s.cmd_hits.is_empty())
                .unwrap_or(false),
            "安全路径不应记录命中: {:?}",
            store.get("s").map(|s| s.cmd_hits.clone())
        );
    }

    /// Anthropic `server_tool_use` 的 `input` 对象同样属于工具参数。
    #[test]
    fn server_tool_use_input_is_tool_channel() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let v = serde_json::json!({
            "content": [{"type": "server_tool_use", "name": "sh",
                         "input": {"command": "rm -rf /"}}]
        });
        let mut blocked = false;
        let out = e.process_tree(v, "t", &store, &mut blocked);
        let cmd = out["content"][0]["input"]["command"].as_str().unwrap();
        assert!(
            !cmd.contains("rm -rf /"),
            "server_tool_use.input 未处置: {cmd}"
        );
    }

    /// 取舍说明：`arguments` 是协议专用容器名，任意层级出现都按工具参数处理。
    /// 这个测试把当前取舍固定下来，避免将来误以为是遗漏。
    #[test]
    fn arguments_key_is_treated_as_tool_container() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let v = serde_json::json!({"arguments": {"cmd": "rm -rf /"}});
        let mut blocked = false;
        let out = e.process_tree(v, "t", &store, &mut blocked);
        let cmd = out["arguments"]["cmd"].as_str().unwrap();
        assert!(
            !cmd.contains("rm -rf /"),
            "当前策略：arguments 子树一律按工具参数扫描（实际: {cmd}）"
        );
    }

    /// 完成快照（`output_item.done`）在 observe 流式路径也必须记录命中；
    /// 旧实现只在增量槽位上判定，快照被整段跳过。
    #[test]
    fn observe_records_snapshot_only_tool_arguments() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let frame = "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}\n\n";
        e.scan_encoded_output(frame.as_bytes(), "s", &store);
        e.flush_tool_fragments("s", &store);
        assert_eq!(
            store.get("s").map(|s| s.cmd_hits.len()).unwrap_or(0),
            1,
            "仅完成快照的响应也必须记录命中"
        );
    }

    /// 纯文本工具参数（非 JSON）不能被强制 JSON 解析拒绝，仍要按文本扫描。
    #[test]
    fn plain_text_tool_argument_is_scanned() {
        for mode in [CmdBlockMode::Observe, CmdBlockMode::Block] {
            let e = engine(mode, &["tool"]);
            let store = SessionStore::new();
            store.new_session("s");
            let (out, blocked) =
                e.process_aggregated_tool("rm -rf / --no-preserve-root", "s", &store);
            assert_eq!(
                store.get("s").map(|s| s.cmd_hits.len()).unwrap_or(0),
                1,
                "{mode:?}: 纯文本参数必须被扫描"
            );
            assert_eq!(out, "rm -rf / --no-preserve-root", "observe 不改写");
            assert_eq!(blocked, mode == CmdBlockMode::Block);
        }
    }

    /// 形似 JSON 但解析失败的参数：不能静默当安全（按文本兜底扫描）。
    #[test]
    fn json_like_unparsable_argument_is_still_scanned() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        // 缺右括号 → 解析失败；`/` 后紧跟 `\"`，raw 规则不命中，需先反转义兜底
        let _ = e.process_aggregated_tool("{\"command\":\"rm -rf /\"", "s", &store);
        assert_eq!(
            store.get("s").map(|s| s.cmd_hits.len()).unwrap_or(0),
            1,
            "形似 JSON 且解析失败时也要兜底扫描"
        );
    }

    /// observe 跨帧：两帧都不完整，只有流末 flush 才能判定（不逐帧误报）。
    #[test]
    fn observe_waits_for_stream_end_before_judging() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let f1 = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"command\\\":\\\"rm -r\"}}]}}]}\n\n";
        let f2 = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"f /\\\"}\"}}]}}]}\n\n";
        e.scan_encoded_output(f1.as_bytes(), "s", &store);
        e.scan_encoded_output(f2.as_bytes(), "s", &store);
        e.flush_tool_fragments("s", &store);
        assert_eq!(
            store.get("s").map(|s| s.cmd_hits.len()).unwrap_or(0),
            1,
            "跨帧拼接后的命令必须被记录"
        );
    }

    /// 安全命令被切在「看似危险的前缀」上时不得误报：
    /// `rm -rf /tmp` 的前半帧是 `rm -rf /`，逐帧判定会误改。
    #[test]
    fn safe_command_split_at_slash_is_not_false_positive() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let f1 = serde_json::json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"rm -rf /"}}]}}]});
        let f2 = serde_json::json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"tmp/keep"}}]}}]});
        let mut blocked = false;
        let o1 = e.process_tree_defer_streamed(f1, "s", &store, &mut blocked);
        assert_eq!(
            o1["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"], "rm -rf /",
            "逐帧不得改写（可能只是安全路径的前半段）"
        );
        let _ = e.process_tree_defer_streamed(f2, "s", &store, &mut blocked);
        assert!(!blocked);
    }

    /// 两个并行工具调用交错发送时，参数按通道隔离，不串数据。
    #[test]
    fn parallel_tool_calls_do_not_cross_contaminate() {
        let e = engine(CmdBlockMode::Observe, &["tool"]);
        let store = SessionStore::new();
        store.new_session("s");
        let frame = serde_json::json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"function":{"arguments":"rm -rf /"}},
            {"index":1,"function":{"arguments":"ls -la"}}]}}]});
        let line = format!("data: {}\n\n", serde_json::to_string(&frame).unwrap());
        e.scan_encoded_output(line.as_bytes(), "s", &store);
        e.flush_tool_fragments("s", &store);
        let hits = store.get("s").map(|s| s.cmd_hits.len()).unwrap_or(0);
        assert_eq!(hits, 1, "只应记录 index=0 的危险命令");
    }

    /// 普通业务 JSON 的 `input` 对象不能被当成工具参数（否则误拦正文）。
    #[test]
    fn plain_input_object_is_not_tool_args() {
        let e = engine(CmdBlockMode::Rewrite, &["tool"]);
        let store = SessionStore::new();
        store.new_session("t");
        let v = serde_json::json!({"input": {"text": "rm -rf /"}});
        let mut blocked = false;
        let out = e.process_tree(v, "t", &store, &mut blocked);
        assert_eq!(
            out["input"]["text"].as_str().unwrap(),
            "rm -rf /",
            "非 tool_use 块的 input 不得被改写"
        );
        assert!(!blocked);
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
