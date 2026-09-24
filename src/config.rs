//! Maskit-RS 配置模型：加载 / 保存 / schema 校验 / 热更新 / 默认值。
//!
//! 对齐 PLAN.md §6.2。数据目录由环境变量 `MASKIT_RS_DATA_DIR` 指定，
//! 默认为可执行文件旁的 `data/`。配置文件为 `<data_dir>/config.json`，
//! 不存在时生成默认配置。

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

/// 凭据类标签（对齐 Python `credential_labels.CREDENTIAL_LABELS`）。
/// 这些标签的原文**永不落库**，只记 preview + sha256 摘要 + 长度。
#[allow(dead_code)] // M3+ 使用
pub const CREDENTIAL_LABELS: &[&str] = &[
    "API_KEY",
    "TOKEN",
    "SECRET",
    "ACCESS_KEY",
    "JWT",
    "CONNSTR",
    "PRIVATE_KEY",
];

#[allow(dead_code)] // M3+ 使用
pub fn is_credential_label(label: &str) -> bool {
    CREDENTIAL_LABELS.contains(&label)
}

// ---------------------------------------------------------------------------
// 配置结构
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_bind")]
    pub bind: String,
}

fn default_port() -> u16 {
    18701
}
fn default_bind() -> String {
    "127.0.0.1".into()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            bind: default_bind(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamConfig {
    /// 上游地址，如 `https://api.your-relay.com` 或带路径前缀 `https://relay.example.com/v1`
    pub target: String,
    /// 注入的静态请求头（凭据头将被拒绝注入，对齐 Python `_CREDENTIAL_HEADER_NAMES`）
    #[serde(default)]
    pub extra_headers: std::collections::BTreeMap<String, String>,
    /// 上游连接超时（秒）
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// 上游整体读超时（秒；0 = 不限，SSE 长流必须为 0 或极大值）
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,
}

fn default_connect_timeout() -> u64 {
    15
}
fn default_read_timeout() -> u64 {
    0
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            extra_headers: Default::default(),
            connect_timeout_secs: default_connect_timeout(),
            read_timeout_secs: default_read_timeout(),
        }
    }
}

/// 21 类内置规则开关，对齐 Python `shield_defaults.DEFAULT_BUILTIN_RULES`。
/// 默认开启 7 类核心：API_KEY/CARD/CONNSTR/EMAIL/IDCARD/LANDLINE/PHONE。
pub fn default_builtin_rules() -> std::collections::BTreeMap<String, bool> {
    let on = [
        "API_KEY", "CARD", "CONNSTR", "EMAIL", "IDCARD", "LANDLINE", "PHONE",
    ];
    let off = [
        "ACCESS_KEY",
        "HKID",
        "IBAN",
        "IP_INTERNAL",
        "IP_PRIVATE",
        "IP_PUBLIC",
        "IPV6_PRIVATE",
        "JWT",
        "MAC",
        "PLATE",
        "PRIVATE_KEY",
        "SECRET",
        "TOKEN",
        "USCC",
    ];
    let mut m = std::collections::BTreeMap::new();
    for k in on {
        m.insert(k.to_string(), true);
    }
    for k in off {
        m.insert(k.to_string(), false);
    }
    m
}

/// 内置规则全集合（21 类）。用于校验 `builtin_rules` 的键。
pub const ALL_BUILTIN_RULES: &[&str] = &[
    "ACCESS_KEY",
    "API_KEY",
    "CARD",
    "CONNSTR",
    "EMAIL",
    "HKID",
    "IBAN",
    "IDCARD",
    "IP_INTERNAL",
    "IP_PRIVATE",
    "IP_PUBLIC",
    "IPV6_PRIVATE",
    "JWT",
    "LANDLINE",
    "MAC",
    "PHONE",
    "PLATE",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
    "USCC",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MaskConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_builtin_rules")]
    pub builtin_rules: std::collections::BTreeMap<String, bool>,
    /// 自定义敏感词 {词: 分类}
    #[serde(default)]
    pub custom_words: std::collections::BTreeMap<String, String>,
    /// 禁用的词分组（整个 label 关闭，对齐 Python `sensitive_disabled`）
    #[serde(default)]
    pub sensitive_disabled: Vec<String>,
    /// 词级禁用 {label: [词...]}（对齐 Python `sensitive_word_disabled`）
    #[serde(default)]
    pub sensitive_word_disabled: std::collections::BTreeMap<String, Vec<String>>,
    /// 整词匹配开关（词两侧加边界；仅对 ASCII 词有效，对齐 Python `sensitive_word_whole`）
    #[serde(default)]
    pub sensitive_word_whole: Vec<String>,
    /// 自定义正则（每条 {name, pattern}）
    #[serde(default)]
    pub custom_regexes: Vec<CustomRegex>,
    #[serde(default = "default_secret_prefixes")]
    pub secret_prefixes: Vec<String>,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_session_ttl")]
    pub session_ttl: u64,
    /// NER 预留位（PLAN §11：一期不实现，置 true 时告警）
    #[serde(default)]
    pub ner_enabled: bool,
    /// 凭据/自定义词命中记录原文（对齐 Python record_plaintext_words；
    /// 凭据类无论如何永不落库）
    #[serde(default = "default_true")]
    pub record_plaintext_words: bool,
}

fn default_true() -> bool {
    true
}
fn default_secret_prefixes() -> Vec<String> {
    vec!["sk-".into(), "ah-".into()]
}
fn default_max_body_bytes() -> usize {
    32 * 1024 * 1024
}
fn default_session_ttl() -> u64 {
    600
}

impl Default for MaskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            builtin_rules: default_builtin_rules(),
            custom_words: Default::default(),
            sensitive_disabled: Default::default(),
            sensitive_word_disabled: Default::default(),
            sensitive_word_whole: Default::default(),
            custom_regexes: Default::default(),
            secret_prefixes: default_secret_prefixes(),
            max_body_bytes: default_max_body_bytes(),
            session_ttl: default_session_ttl(),
            ner_enabled: false,
            record_plaintext_words: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustomRegex {
    pub name: String,
    pub pattern: String,
}

/// 命令拦截三模式
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CmdBlockMode {
    Observe,
    Rewrite,
    Block,
}

impl Default for CmdBlockMode {
    #[allow(clippy::derivable_impls)] // serde default 需要显式 fn
    fn default() -> Self {
        CmdBlockMode::Observe
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CmdPattern {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub regex: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// builtin 规则删除不复活（对齐 Python command_block.builtin 语义）
    #[serde(default)]
    pub builtin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommandBlockConfig {
    #[serde(default)]
    pub mode: CmdBlockMode,
    #[serde(default = "default_cmd_channels")]
    pub channels: Vec<String>,
    #[serde(default)]
    pub allow_patterns: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<CmdPattern>,
}

fn default_cmd_channels() -> Vec<String> {
    vec!["tool".into()]
}

impl Default for CommandBlockConfig {
    fn default() -> Self {
        // **开箱即用**：首次启动即播种 7 条内置危害命令规则
        // （对齐 Python `panel._normalize_command_block`：`patterns` 键缺失时灌种子，
        //  键存在（哪怕是 `[]`）才尊重用户显式清空）。
        //
        // 回归：这里曾默认 `patterns: []`，而 `CmdBlockEngine` 只从 cfg 读规则，
        // 导致新装实例一条规则都不装载，`rm -rf /` 完全不拦（Python 版是拦的）。
        Self {
            mode: CmdBlockMode::Observe,
            channels: default_cmd_channels(),
            allow_patterns: Default::default(),
            patterns: crate::cmdblock::default_builtin_patterns(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub passive: bool,
    #[serde(default = "default_severity_floor")]
    pub severity_floor: String,
    #[serde(default)]
    pub signals: std::collections::BTreeMap<String, bool>,
}

fn default_severity_floor() -> String {
    "MEDIUM".into()
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            passive: true,
            severity_floor: default_severity_floor(),
            signals: Default::default(),
        }
    }
}

/// 全量配置（PLAN §6.2）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub mask: MaskConfig,
    #[serde(default)]
    pub command_block: CommandBlockConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    /// D6：已路由流量绝不放行原文（非 JSON→503 / 解析失败→400 / 超限→413 / 未知形态→整棵脱敏）
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    /// 响应侧 PII 扫描（幻觉泄漏告警，只记录不改写）
    #[serde(default = "default_true")]
    pub response_scan: bool,
    /// SSE/NDJSON 流式逐事件还原
    #[serde(default = "default_true")]
    pub stream_response: bool,
    #[serde(default = "default_retention")]
    pub log_retention_days: u32,
    /// Web 控制台令牌（≥16 位 ASCII；空则启动时生成随机并写入日志）
    #[serde(default)]
    pub panel_token: String,
    /// 脱敏暂停（运行时开关，等价 filter_enabled=false：纯透传 + BYPASS 事件）
    #[serde(default)]
    pub paused: bool,
}

fn default_retention() -> u32 {
    7
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: Default::default(),
            upstream: Default::default(),
            mask: Default::default(),
            command_block: Default::default(),
            audit: Default::default(),
            fail_closed: true,
            response_scan: true,
            stream_response: true,
            log_retention_days: default_retention(),
            panel_token: String::new(),
            paused: false,
        }
    }
}

// ---------------------------------------------------------------------------
// 校验
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ConfigWarning(pub String);

impl Config {
    /// schema 校验 + 未知形态规整。返回告警列表（不阻断，落日志）。
    pub fn validate(&self) -> Vec<ConfigWarning> {
        let mut warnings: Vec<ConfigWarning> = Vec::new();

        if self.server.port == 0 {
            warnings.push(ConfigWarning("server.port 为 0，已回退 18701".into()));
        }
        // 内置规则：未知键告警 + 缺失键补默认
        for k in self.mask.builtin_rules.keys() {
            if !ALL_BUILTIN_RULES.contains(&k.as_str()) {
                warnings.push(ConfigWarning(format!("未知内置规则键: {k}（已忽略）")));
            }
        }
        for k in ALL_BUILTIN_RULES {
            if !self.mask.builtin_rules.contains_key(*k) {
                warnings.push(ConfigWarning(format!("内置规则缺失键 {k}，已补默认值")));
            }
        }
        if self.mask.ner_enabled {
            warnings.push(ConfigWarning(
                "mask.ner_enabled=true 但 NER 一期未实现（PLAN §11），配置被忽略".into(),
            ));
        }
        if !self.upstream.target.is_empty() && !self.upstream.target.contains("://") {
            warnings.push(ConfigWarning(
                "upstream.target 缺少 scheme（http:// 或 https://）".into(),
            ));
        }
        if !self.panel_token.is_empty() && self.panel_token.len() < 16 {
            warnings.push(ConfigWarning(
                "panel_token 少于 16 位，已忽略并回退随机令牌".into(),
            ));
        }
        if self.mask.max_body_bytes > 128 * 1024 * 1024 {
            warnings.push(ConfigWarning(
                "mask.max_body_bytes 超过 128MiB 上限，已截断到 128MiB".into(),
            ));
        }
        warnings
    }

    /// 规整后的克隆（补齐缺失键 / 截断越界值）。
    pub fn normalized(&self) -> Config {
        let mut c = self.clone();
        if c.server.port == 0 {
            c.server.port = 18701;
        }
        // 补齐缺失内置规则键
        let defaults = default_builtin_rules();
        for (k, v) in defaults {
            c.mask.builtin_rules.entry(k).or_insert(v);
        }
        c.mask
            .builtin_rules
            .retain(|k, _| ALL_BUILTIN_RULES.contains(&k.as_str()));
        if c.mask.max_body_bytes > 128 * 1024 * 1024 {
            c.mask.max_body_bytes = 128 * 1024 * 1024;
        }
        if c.mask.session_ttl == 0 {
            c.mask.session_ttl = 600;
        }
        if c.panel_token.len() < 16 {
            // 交给启动逻辑生成随机令牌
            c.panel_token.clear();
        }
        // 审计 signals：补默认（全部开启）
        let default_signals = [
            "error_leak",
            "identity_swap",
            "tool_call_rewrite",
            "sse_anomaly",
            "response_poison",
            "cross_request_pollution",
            "credential_echo",
            "dangerous_action",
        ];
        for s in default_signals {
            c.audit.signals.entry(s.to_string()).or_insert(true);
        }
        c
    }
}

// ---------------------------------------------------------------------------
// 运行时配置中心（Arc<RwLock> + 热更新通知）
// ---------------------------------------------------------------------------

pub struct ConfigCenter {
    inner: RwLock<Config>,
    /// 原子镜像：热路径免锁读取的少量字段
    fail_closed: AtomicBool,
    paused: AtomicBool,
    max_body_bytes: AtomicU64,
    version: AtomicU64,
    data_dir: PathBuf,
}

impl ConfigCenter {
    pub fn load_or_init(
        data_dir: &Path,
    ) -> std::io::Result<(std::sync::Arc<Self>, Vec<ConfigWarning>)> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join("config.json");
        let (mut cfg, mut warnings) = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            match serde_json::from_str::<Config>(&raw) {
                Ok(c) => (c, Vec::new()),
                Err(e) => (
                    Config::default(),
                    vec![ConfigWarning(format!(
                        "config.json 解析失败（{}），已回退默认配置",
                        e
                    ))],
                ),
            }
        } else {
            let c = Config::default();
            // 生成默认配置文件
            let body = serde_json::to_string_pretty(&c).unwrap_or_else(|_| "{}".into());
            fs::write(&path, body)?;
            (c, Vec::new())
        };
        warnings.extend(cfg.validate());
        cfg = cfg.normalized();
        if cfg.panel_token.is_empty() {
            let tok = generate_token();
            tracing::warn!(token = %tok, "panel_token 未设置，已生成随机令牌（重启会变，请在控制台设置固定值）");
            cfg.panel_token = tok;
            // 回写，保证重启后令牌稳定
            let body = serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| "{}".into());
            let _ = fs::write(&path, body);
        }
        let center = std::sync::Arc::new(Self {
            fail_closed: AtomicBool::new(cfg.fail_closed),
            paused: AtomicBool::new(cfg.paused),
            max_body_bytes: AtomicU64::new(cfg.mask.max_body_bytes as u64),
            version: AtomicU64::new(1),
            inner: RwLock::new(cfg),
            data_dir: data_dir.to_path_buf(),
        });
        Ok((center, warnings))
    }

    pub fn get(&self) -> Config {
        self.inner.read().unwrap().clone()
    }

    #[allow(dead_code)] // M9+ 使用
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// 整体替换配置（POST /config）。校验失败的字段回退默认并返回告警。
    pub fn update(&self, new_cfg: Config) -> Vec<ConfigWarning> {
        let mut warnings = new_cfg.validate();
        let cfg = new_cfg.normalized();
        {
            let mut w = self.inner.write().unwrap();
            *w = cfg;
        }
        self.sync_atomics();
        self.persist();
        warnings.extend(self.hot_apply_warnings());
        self.version.fetch_add(1, Ordering::Release);
        warnings
    }

    /// 局部补丁：对 JSON 值做路径级 set（对齐 Python /api/config/patch 的核心语义）。
    ///
    /// 用 serde_json 的 JSON Pointer 原语（`/mask/custom_words/张三`）——
    /// 手写逐层重建会丢掉同级字段（曾把 `mask` 下除 custom_words 外的全部字段抹掉）。
    pub fn patch(
        &self,
        path: &str,
        value: serde_json::Value,
    ) -> Result<Vec<ConfigWarning>, String> {
        let mut cfg_json = serde_json::to_value(self.get()).map_err(|e| e.to_string())?;
        let segs: Vec<String> = path
            .split('.')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if segs.is_empty() {
            return Err("patch path 不能为空".into());
        }
        // 构造 JSON Pointer（`~` → `~0`，`/` → `~1` 转义）
        let pointer = format!(
            "/{}",
            segs.iter()
                .map(|s| s.replace('~', "~0").replace('/', "~1"))
                .collect::<Vec<_>>()
                .join("/")
        );
        // 顶层键允许不存在（新建）；中间键必须存在，否则报错（避免静默建错层级）
        if segs.len() == 1 {
            let obj = cfg_json
                .as_object_mut()
                .ok_or_else(|| "配置根不是对象".to_string())?;
            obj.insert(segs[0].clone(), value);
        } else {
            let parent_ptr = format!(
                "/{}",
                segs[..segs.len() - 1]
                    .iter()
                    .map(|s| s.replace('~', "~0").replace('/', "~1"))
                    .collect::<Vec<_>>()
                    .join("/")
            );
            let parent = cfg_json
                .pointer_mut(&parent_ptr)
                .ok_or_else(|| format!("路径 {path} 的父级不存在"))?;
            let obj = parent
                .as_object_mut()
                .ok_or_else(|| format!("路径 {path} 的父级不是对象"))?;
            obj.insert(segs[segs.len() - 1].clone(), value);
        }
        let _ = pointer;
        let new_cfg: Config =
            serde_json::from_value(cfg_json).map_err(|e| format!("补丁后配置非法: {e}"))?;
        Ok(self.update(new_cfg))
    }

    /// 持久化当前配置到磁盘（原子写：tmp + rename，避免同路径覆盖写坏文件）。
    pub fn persist(&self) {
        let cfg = self.get();
        let body = match serde_json::to_string_pretty(&cfg) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("配置序列化失败: {e}");
                return;
            }
        };
        let path = self.data_dir.join("config.json");
        let tmp = self.data_dir.join(".config.json.tmp");
        if let Err(e) = fs::write(&tmp, body).and_then(|_| fs::rename(&tmp, &path)) {
            tracing::error!("配置写盘失败: {e}");
        }
    }

    fn sync_atomics(&self) {
        let cfg = self.get();
        self.fail_closed.store(cfg.fail_closed, Ordering::Release);
        self.paused.store(cfg.paused, Ordering::Release);
        self.max_body_bytes
            .store(cfg.mask.max_body_bytes as u64, Ordering::Release);
    }

    /// 热更新后需要重建的组件由订阅方通过 version 变化感知。
    fn hot_apply_warnings(&self) -> Vec<ConfigWarning> {
        Vec::new()
    }

    // ---- 热路径免锁读取 ----

    #[allow(dead_code)] // M6 使用
    pub fn fail_closed(&self) -> bool {
        self.fail_closed.load(Ordering::Acquire)
    }
    #[allow(dead_code)] // M6 使用
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes.load(Ordering::Acquire) as usize
    }
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
    pub fn panel_token(&self) -> String {
        self.get().panel_token
    }
}

fn generate_token() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// 按 '.' 分段路径从 JSON 值中取子值（保留给测试与诊断用）。
#[allow(dead_code)]
fn get_at_path<'a>(v: &'a serde_json::Value, segs: &[String]) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for s in segs {
        cur = cur.as_object()?.get(s)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrip() {
        let c = Config::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        assert_eq!(c.server.port, 18701);
        assert!(c.fail_closed);
        // 默认开启 7 类
        assert!(c.mask.builtin_rules["PHONE"]);
        assert!(!c.mask.builtin_rules["JWT"]);
    }

    #[test]
    fn validate_fills_missing_rules() {
        let mut c = Config::default();
        c.mask.builtin_rules.remove("EMAIL");
        c.mask.builtin_rules.insert("BOGUS".into(), true);
        let w = c.validate();
        assert!(w.iter().any(|w| w.0.contains("BOGUS")));
        let n = c.normalized();
        assert!(n.mask.builtin_rules.contains_key("EMAIL"));
        assert!(!n.mask.builtin_rules.contains_key("BOGUS"));
    }

    #[test]
    fn patch_updates_nested_value() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        center
            .patch("mask.custom_words.李四", serde_json::json!("人名"))
            .unwrap();
        let cfg = center.get();
        assert_eq!(
            cfg.mask.custom_words.get("李四").map(String::as_str),
            Some("人名")
        );
        // 持久化验证
        let raw = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(raw.contains("李四"));
    }

    #[test]
    fn patch_preserves_sibling_fields() {
        // 回归：早期实现在嵌套路径上会丢掉同级字段
        // （patch 「mask.custom_words.X」曾把 mask 下除 custom_words 外的全部字段抹掉）
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let before = center.get();
        center
            .patch("mask.custom_words.王五", serde_json::json!("人名"))
            .unwrap();
        let after = center.get();
        assert_eq!(
            after.mask.custom_words.get("王五").map(String::as_str),
            Some("人名")
        );
        // 同级字段必须原样保留
        assert_eq!(
            after.mask.builtin_rules, before.mask.builtin_rules,
            "builtin_rules 被抹掉"
        );
        assert_eq!(after.mask.secret_prefixes, before.mask.secret_prefixes);
        assert_eq!(after.mask.max_body_bytes, before.mask.max_body_bytes);
        assert_eq!(after.server.port, before.server.port);
        assert_eq!(after.upstream.target, before.upstream.target);
        // 深层路径
        center
            .patch("mask.builtin_rules.JWT", serde_json::json!(true))
            .unwrap();
        let after2 = center.get();
        assert!(after2.mask.builtin_rules["JWT"]);
        assert_eq!(
            after2.mask.builtin_rules["PHONE"],
            before.mask.builtin_rules["PHONE"]
        );
        assert_eq!(
            after2.mask.custom_words.get("王五").map(String::as_str),
            Some("人名")
        );
        // 不存在的父级报错
        assert!(center
            .patch("nonexistent.deep.key", serde_json::json!(1))
            .is_err());
    }

    #[test]
    fn token_generated_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        assert!(center.get().panel_token.len() >= 16);
        // 回写稳定
        let (center2, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        assert_eq!(center.get().panel_token, center2.get().panel_token);
    }

    #[test]
    fn atomic_mirror_follows_update() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let mut cfg = center.get();
        cfg.fail_closed = false;
        cfg.paused = true;
        center.update(cfg);
        assert!(!center.fail_closed());
        assert!(center.paused());
    }
}
