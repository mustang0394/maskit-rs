//! Maskit-RS 配置模型：加载 / 保存 / schema 校验 / 热更新 / 默认值。
//!
//! 对齐 PLAN.md §6.2。数据目录由环境变量 `MASKIT_RS_DATA_DIR` 指定，
//! 默认为可执行文件旁的 `data/`。配置文件为 `<data_dir>/config.json`，
//! 不存在时生成默认配置。

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// 事件日志是否保留凭据类明文。默认 true（用户要求：不分类别，全部可看）。
///
/// 为 false 时恢复凭据红线：凭据类只留 sha256 摘要与打码预览。
/// 注意这**只影响日志展示层**，不影响占位符映射表（映射表始终全量落盘，
/// 否则缓存一致性无法保证）。
pub fn log_keeps_credential_plaintext(cfg: &Config) -> bool {
    cfg.mask.log_credential_plaintext
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
        "API_KEY",
        "CARD",
        "CONNSTR",
        "EMAIL",
        "IDCARD",
        "LANDLINE",
        "PHONE",
        // SSH 公钥默认开：形态上以 `AAAA` 开头的 base64 blob + 类型串，
        // 还会回解 blob 核对内部类型，几乎不可能误报（与 API_KEY 同一类）。
        "SSH_PUBKEY",
    ];
    let off = [
        "ACCESS_KEY",
        "HKID",
        "IBAN",
        "IP_INTERNAL",
        "IP_PRIVATE",
        "IP_PUBLIC",
        "IPV6_PRIVATE",
        // 公网 IPv6 默认关：与 IPv4 公网/IPv6 私网保持一致 ——
        // 网络类文档里地址很常见，默认开会把技术正文搅得很难读。
        "IPV6_PUBLIC",
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
    "IPV6_PUBLIC",
    "JWT",
    "LANDLINE",
    "MAC",
    "PHONE",
    "PLATE",
    "PRIVATE_KEY",
    "SECRET",
    "SSH_PUBKEY",
    "TOKEN",
    "USCC",
];

/// 多模态 / 编码载荷（base64）跳过策略。
///
/// 背景：大 base64 字段若落在未豁免位置，会被规则引擎线性扫描 ——
/// 1MB 随机 base64 实测 5~10 秒（本机容器配额下）。本策略按**值形态**
/// （data URI / 大块裸 base64）识别并跳过，与字段名解耦，因此自定义/中转
/// 字段也能覆盖。详见 `src/mask/blob.rs`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlobMode {
    /// 关闭（行为与改动前完全一致）
    Off,
    /// 只跳过 `data:...;base64,` 形态的 data URI
    DataUri,
    /// data URI + 大块裸 base64（默认）
    #[default]
    Auto,
}

/// 宽松反序列化：写错值（`"disabled"` / 大小写 / 带空格）时**退化为 auto**，
/// 而不是让整份 `Config` 反序列化失败 —— 后者会让 `ConfigCenter` 回退默认值，
/// 连 `upstream.target` / `panel_token` 一起丢掉。
impl<'de> Deserialize<'de> for BlobMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" | "false" => BlobMode::Off,
            "data_uri" | "datauri" | "data-uri" => BlobMode::DataUri,
            _ => BlobMode::Auto,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultimodalBlobConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: BlobMode,
    /// 裸 base64 的最小长度阈值（字节）。低于此长度的字符串照常扫描；
    /// data URI 不受此限。规整时夹在 [1KiB, 8MiB]。
    #[serde(default = "default_blob_min_base64_bytes")]
    pub min_base64_bytes: usize,
}

fn default_blob_min_base64_bytes() -> usize {
    8192
}

impl Default for MultimodalBlobConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: BlobMode::Auto,
            min_base64_bytes: default_blob_min_base64_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MaskConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_builtin_rules")]
    pub builtin_rules: std::collections::BTreeMap<String, bool>,
    /// 自定义敏感词 {词: 分类}
    #[serde(default)]
    pub custom_words: std::collections::BTreeMap<String, String>,
    /// 已声明的敏感词分组（**有序**，控制台按此顺序展示）。
    ///
    /// 为什么需要单独存一份：词表是 `{词: 分类}` 映射，分组只能由它反推 ——
    /// 于是「新建分组」这件事无法保存（没有词的组会当场消失），加词也必须
    /// 每次重新输入分组名。声明表让分组成为**独立实体**：先建组、再往里加词。
    ///
    /// 引擎不使用本字段（只认 `custom_words`）；分组的实际生效仍取决于
    /// 词表里有没有属于它的词。声明但无词的分组只是「空盒子」。
    #[serde(default)]
    pub custom_word_groups: Vec<String>,
    /// 禁用的词分组（整个 label 关闭，对齐 Python `sensitive_disabled`）
    #[serde(default)]
    pub sensitive_disabled: Vec<String>,
    /// 事件日志是否保留凭据类**明文原文**。
    ///
    /// true（默认）：所有类型的 `items[].original` 与 `dialog` 全文均保留明文，
    ///   控制台可直接看到「原文 → 占位符」的完整对照。
    /// false：恢复凭据红线 —— 凭据类只留 sha256 摘要与打码预览，原文不落库。
    ///
    /// ⚠️ true 会把 API Key / 私钥 / 连接串等**明文写入 SQLite**。数据库文件
    /// 权限为 0600，但**备份必须加密**；多人可读的主机上建议改回 false。
    #[serde(default = "default_true")]
    pub log_credential_plaintext: bool,
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
    /// 占位符映射表保留时长（秒，默认 24h，与内存表同口径）。
    /// 内存表是 DB 前面的一层 LRU 缓存（10000 条 + 24h TTL）；
    /// 被淘汰时回查本表，保证同一敏感值的占位符在有效期内保持稳定。
    #[serde(default = "default_mapping_ttl")]
    pub mapping_ttl: u64,
    /// NER 预留位（PLAN §11：一期不实现，置 true 时告警）
    #[serde(default)]
    pub ner_enabled: bool,
    /// 多模态 / 编码载荷（base64）跳过策略（C 方案：解析前外置 + 原字节拼回）
    #[serde(default)]
    pub multimodal_blob: MultimodalBlobConfig,
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
/// 映射表默认保留 24 小时（与内存表 RECENT_TTL 同口径）。
fn default_mapping_ttl() -> u64 {
    24 * 3600
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
            custom_word_groups: Default::default(),
            sensitive_disabled: Default::default(),
            log_credential_plaintext: true,
            sensitive_word_disabled: Default::default(),
            sensitive_word_whole: Default::default(),
            custom_regexes: Default::default(),
            secret_prefixes: default_secret_prefixes(),
            max_body_bytes: default_max_body_bytes(),
            session_ttl: default_session_ttl(),
            mapping_ttl: default_mapping_ttl(),
            ner_enabled: false,
            multimodal_blob: Default::default(),
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
    /// 内置规则播种版本：老配置缺省为 1，normalized 时补齐 v2 新增规则。
    #[serde(default = "default_builtin_seed_version")]
    pub builtin_seed_version: u32,
}

fn default_builtin_seed_version() -> u32 {
    1
}

fn default_cmd_channels() -> Vec<String> {
    vec!["tool".into()]
}

impl Default for CommandBlockConfig {
    fn default() -> Self {
        // **开箱即用**：首次启动即播种 8 条内置危害命令规则
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
            builtin_seed_version: 2,
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
    /// 完整报文诊断环：保留最近 N 条请求的**完整**请求体/响应体（0 = 关闭）。
    ///
    /// 与 `events` 表里的 `dialog`（抽取后的对话文本、8000 字符截断）不同，
    /// 这里存的是原始字节形态，用来排查「脱敏了没还原」这类问题 ——
    /// 必须能看到上游回来的占位符原样。只保留最近 N 条，超出即淘汰
    /// （`trace_blobs` 表按 sid 保留 N 组）。
    ///
    /// ⚠️ 仅当 `mask.log_credential_plaintext=true` 时生效：完整报文里含凭据明文，
    /// 关掉凭据明文开关时一并关闭，避免绕过红线。
    #[serde(default = "default_full_trace_count")]
    pub full_trace_count: usize,
    /// 完整报文**单侧**字节上限（原文 / 脱敏后 / 上游响应 / 还原后各算一侧）。
    ///
    /// 默认 32MiB，与 `mask.max_body_bytes` 对齐 —— 即**正常请求不截断**，
    /// 导出的就是完整报文。它只是防止 `max_body_bytes` 被调大后单条吞掉整个磁盘的
    /// 安全网（调小它会让导出文件出现「已截断」）。
    #[serde(default = "default_full_trace_max_bytes")]
    pub full_trace_max_bytes: usize,
    /// 完整报文**总字节预算**（所有保留组之和，默认 256MiB）。
    ///
    /// 条数上限（`full_trace_count`）管不住单条体积：20 组 × 4 侧 × 32MiB 理论上
    /// 能到 2.5GiB。超过本预算时写线程按「最旧 sid」整组淘汰，直到回到预算内。
    #[serde(default = "default_full_trace_total_bytes")]
    pub full_trace_total_bytes: usize,
    /// Web 控制台令牌（不限长度，原样生效；空则启动时生成 24 位随机值并写入日志）
    #[serde(default)]
    pub panel_token: String,
    /// 脱敏暂停（运行时开关，等价 filter_enabled=false：纯透传 + BYPASS 事件）
    #[serde(default)]
    pub paused: bool,
}

fn default_retention() -> u32 {
    7
}

fn default_full_trace_count() -> usize {
    20
}

fn default_full_trace_max_bytes() -> usize {
    32 * 1024 * 1024
}

fn default_full_trace_total_bytes() -> usize {
    256 * 1024 * 1024
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
            full_trace_count: default_full_trace_count(),
            full_trace_max_bytes: default_full_trace_max_bytes(),
            full_trace_total_bytes: default_full_trace_total_bytes(),
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
        if self.mask.max_body_bytes > 128 * 1024 * 1024 {
            warnings.push(ConfigWarning(
                "mask.max_body_bytes 超过 128MiB 上限，已截断到 128MiB".into(),
            ));
        }
        if self.full_trace_count > 200 {
            warnings.push(ConfigWarning(
                "full_trace_count 超过 200 上限，已截断到 200".into(),
            ));
        }
        if self.full_trace_max_bytes < 4096 {
            warnings.push(ConfigWarning(
                "full_trace_max_bytes 小于 4KiB，已抬到 4KiB（过小会截掉大部分报文）".into(),
            ));
        }
        // 多模态 blob 阈值：太小会把普通长文本误判成 base64，太大则失去跳过意义。
        // 与 `normalized()` 的 clamp 同口径（不因 mode=off 就跳过检查）。
        if self.mask.multimodal_blob.enabled {
            let m = self.mask.multimodal_blob.min_base64_bytes;
            if m < 1024 {
                warnings.push(ConfigWarning(
                    "mask.multimodal_blob.min_base64_bytes 小于 1KiB，已抬到 1KiB".into(),
                ));
            }
            if m > 8 * 1024 * 1024 {
                warnings.push(ConfigWarning(
                    "mask.multimodal_blob.min_base64_bytes 超过 8MiB 上限，已截断到 8MiB".into(),
                ));
            }
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
        // 分组声明：去空白、去重，保持用户顺序（空分组**必须保留** —— 那是它的意义）
        {
            let mut seen = std::collections::HashSet::new();
            let cleaned: Vec<String> = c
                .mask
                .custom_word_groups
                .iter()
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty() && seen.insert(g.clone()))
                .collect();
            c.mask.custom_word_groups = cleaned;
        }
        if c.mask.max_body_bytes > 128 * 1024 * 1024 {
            c.mask.max_body_bytes = 128 * 1024 * 1024;
        }
        if c.mask.session_ttl == 0 {
            c.mask.session_ttl = 600;
        }
        if c.mask.mapping_ttl == 0 {
            c.mask.mapping_ttl = 24 * 3600;
        }
        // 多模态 blob 阈值夹在 [1KiB, 8MiB]（与 `BlobPolicy::from_config` 同口径）。
        c.mask.multimodal_blob.min_base64_bytes = c
            .mask
            .multimodal_blob
            .min_base64_bytes
            .clamp(1024, 8 * 1024 * 1024);
        // 完整报文诊断环：条数封顶 200，单侧上限夹在 [4KiB, 32MiB]。
        // 0 是合法的「关闭」，不参与抬升。
        c.full_trace_count = c.full_trace_count.min(200);
        if c.full_trace_count > 0 {
            c.full_trace_max_bytes = c.full_trace_max_bytes.clamp(4096, 32 * 1024 * 1024);
            // 总预算夹在 [16MiB, 4GiB]：太小会把诊断环挤成 1~2 组，太大失去兜底意义
            c.full_trace_total_bytes = c
                .full_trace_total_bytes
                .clamp(16 * 1024 * 1024, 4 * 1024 * 1024 * 1024);
        }
        // panel_token 不做长度限制：用户设什么就是什么（仅空值才交给启动逻辑生成）。
        c.panel_token = c.panel_token.trim().to_string();
        // 审计 signals：补默认（全部开启）
        let default_signals = [
            "error_leak",
            "identity_swap",
            "sse_anomaly",
            "response_poison",
            "dangerous_action",
        ];
        for s in default_signals {
            c.audit.signals.entry(s.to_string()).or_insert(true);
        }
        c
    }
}

/// 老配置迁移（仅在启动加载时执行一次，不能在 `normalized()` 里做）：
/// v2 新增 `--no-preserve-root` 规则。
///
/// 放进 `normalized()` 会让任何不回写 `builtin_seed_version` 的 PUT/PATCH
/// 把用户删掉的规则重新塞回去；显式 `patterns: []` 也必须尊重，不能借迁移
/// 复活内置规则。
fn migrate_builtin_rules(c: &mut Config) -> bool {
    if c.command_block.builtin_seed_version >= 2 {
        return false;
    }
    if !c.command_block.patterns.is_empty()
        && !c
            .command_block
            .patterns
            .iter()
            .any(|p| p.id == "builtin-rm-root-nopreserve")
    {
        if let Some(p) = crate::cmdblock::default_builtin_patterns()
            .into_iter()
            .find(|p| p.id == "builtin-rm-root-nopreserve")
        {
            c.command_block.patterns.push(p);
        }
    }
    c.command_block.builtin_seed_version = 2;
    true
}

// ---------------------------------------------------------------------------
// 运行时配置中心（Arc<RwLock> + 热更新通知）
// ---------------------------------------------------------------------------

pub struct ConfigCenter {
    inner: RwLock<Config>,
    /// 配置写入串行化锁：`update`/`update_with`/`patch` 全部经此排队，
    /// 避免 get→改→整体 update 的读-改-写丢更新；写盘也在锁内完成。
    mutate: Mutex<()>,
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
        let created = !data_dir.exists();
        fs::create_dir_all(data_dir)?;
        if created {
            restrict_dir(data_dir);
        }
        let path = data_dir.join("config.json");
        // 是否允许把内存中的默认配置写回磁盘。
        // 解析失败且无法备份原文件时**绝不覆盖**，避免把用户的配置冲掉。
        let mut may_write = true;
        let (mut cfg, mut warnings) = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            match serde_json::from_str::<Config>(&raw) {
                Ok(c) => (c, Vec::new()),
                Err(e) => {
                    // B4：坏配置先改名保留，rename 成功才允许写回默认配置。
                    let bad = data_dir.join(format!("config.json.bad.{}", now_unix()));
                    match fs::rename(&path, &bad) {
                        Ok(()) => (
                            Config::default(),
                            vec![ConfigWarning(format!(
                                "config.json 解析失败（{}），原文件已备份为 {}，已使用默认配置",
                                e,
                                bad.display()
                            ))],
                        ),
                        Err(re) => {
                            may_write = false;
                            (
                                Config::default(),
                                vec![ConfigWarning(format!(
                                    "config.json 解析失败（{}），且备份失败（{}），已使用内存默认配置且未覆盖原文件",
                                    e, re
                                ))],
                            )
                        }
                    }
                }
            }
        } else {
            (Config::default(), Vec::new())
        };
        warnings.extend(cfg.validate());
        let migrated = migrate_builtin_rules(&mut cfg);
        cfg = cfg.normalized();
        // 解析失败且无法备份原文件：继续启动只会生成一个无法落盘、也无法从磁盘
        // 读取的令牌（所有管理 API 401 且每次重启都变）。直接报错退出，让用户先
        // 修复数据目录权限；绝不覆盖原文件。
        if !may_write {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} 解析失败且无法改名备份，拒绝覆盖；请修复数据目录权限后重启",
                    path.display()
                ),
            ));
        }
        // 空值/非法值一律重新生成；不把令牌打印到日志（避免令牌进入日志/截图）。
        if !is_valid_panel_token(&cfg.panel_token) {
            let why = if cfg.panel_token.is_empty() {
                "panel_token 未设置"
            } else {
                "panel_token 含非 ASCII 或空白字符"
            };
            let tok = generate_token();
            tracing::warn!(
                "{}，已生成随机令牌并写入 config.json（请从数据目录读取）",
                why
            );
            cfg.panel_token = tok;
            if let Err(e) = write_config_private(&path, &cfg) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "panel_token 已生成但无法写入 {}（{}）；继续启动会导致控制台令牌不可见且每次重启变化，已中止",
                        path.display(),
                        e
                    ),
                ));
            }
        }
        if migrated {
            if let Err(e) = write_config_private(&path, &cfg) {
                warnings.push(ConfigWarning(format!(
                    "内置命令规则迁移已生效，但写入 config.json 失败：{e}"
                )));
            }
        }
        let center = std::sync::Arc::new(Self {
            fail_closed: AtomicBool::new(cfg.fail_closed),
            paused: AtomicBool::new(cfg.paused),
            max_body_bytes: AtomicU64::new(cfg.mask.max_body_bytes as u64),
            version: AtomicU64::new(1),
            inner: RwLock::new(cfg.clone()),
            mutate: Mutex::new(()),
            data_dir: data_dir.to_path_buf(),
        });
        // 启动时同步一次 blob 策略镜像（响应侧还原链路使用）。
        crate::mask::engine::set_blob_policy(&cfg.mask.multimodal_blob);
        Ok((center, warnings))
    }

    pub fn get(&self) -> Config {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    #[allow(dead_code)] // M9+ 使用
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// 整体替换配置（PUT /config）。串行化写入，避免并发覆盖。
    pub fn update(&self, new_cfg: Config) -> Vec<ConfigWarning> {
        let _guard = self.lock_mutate();
        self.apply_locked(new_cfg)
    }

    /// 在**当前配置**上做局部修改（pause/resume/rotate/patch 等）。
    ///
    /// 锁内完成“读→改→写→持久化”，避免 get→改→整体 update 的丢更新。
    pub fn update_with<F>(&self, f: F) -> Vec<ConfigWarning>
    where
        F: FnOnce(&mut Config),
    {
        let _guard = self.lock_mutate();
        let mut cfg = self.get();
        f(&mut cfg);
        self.apply_locked(cfg)
    }

    fn update_with_try<F>(&self, f: F) -> Result<Vec<ConfigWarning>, String>
    where
        F: FnOnce(&mut Config) -> Result<(), String>,
    {
        let _guard = self.lock_mutate();
        let mut cfg = self.get();
        f(&mut cfg)?;
        Ok(self.apply_locked(cfg))
    }

    fn lock_mutate(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mutate.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 调用方必须已持有 `mutate` 锁。
    fn apply_locked(&self, mut new_cfg: Config) -> Vec<ConfigWarning> {
        let mut warnings = new_cfg.validate();
        let current = self.get();
        // 端口/bind 只在启动时绑定监听器；热更新无法 rebind，必须明确告警。
        if current.server.port != new_cfg.server.port || current.server.bind != new_cfg.server.bind
        {
            warnings.push(ConfigWarning(
                "server.port/bind 变更需重启进程后生效（当前监听地址不变）".into(),
            ));
        }
        // panel_token 为空/非法时保留旧值：否则 auth 中间件会拒绝全部请求，
        // 控制台被锁死且无法通过 API 恢复。
        let token = new_cfg.panel_token.trim().to_string();
        if token.is_empty() {
            new_cfg.panel_token = current.panel_token.clone();
            warnings.push(ConfigWarning("panel_token 不能为空，已保留原令牌".into()));
        } else if !is_valid_panel_token(&token) {
            new_cfg.panel_token = current.panel_token.clone();
            warnings.push(ConfigWarning(
                "panel_token 只能包含可打印 ASCII 且不含空白，已保留原令牌".into(),
            ));
        } else {
            new_cfg.panel_token = token;
        }
        let mut cfg = new_cfg.normalized();
        // 单调版本：旧客户端/PUT 不回写该字段时 serde 缺省为 1，若直接落盘，
        // 下次启动会再次执行 v2 迁移，把用户删掉的内置规则复活。
        cfg.command_block.builtin_seed_version = cfg
            .command_block
            .builtin_seed_version
            .max(current.command_block.builtin_seed_version);
        {
            let mut w = self.inner.write().unwrap_or_else(|e| e.into_inner());
            *w = cfg.clone();
        }
        // 一律消费快照：sync_atomics/persist 不再回读 inner。
        // 这既避免未来的 RwLock 重入死锁，也让写盘内容与原子镜像严格同源。
        self.sync_atomics(&cfg);
        if !self.persist_snapshot(&cfg) {
            warnings.push(ConfigWarning(
                "配置已在内存生效，但写入 config.json 失败；重启后会回退到磁盘旧配置".into(),
            ));
        }
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
        let segs: Vec<String> = path
            .split('.')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        self.patch_segs(&segs, value)
    }

    /// 按**路径段数组**打补丁（推荐入口）。
    ///
    /// 字符串 \`path\` 以 \`.\` 分隔，无法表达「键本身含 \`.\`」的路径 —— 例如
    /// 敏感词 \`example.com\` 走 \`mask.custom_words.example.com\` 会被切成 4 段，
    /// 写成 \`custom_words → example → com\` 的嵌套结构（值从一个字符串变成对象，
    /// 匹配逻辑随之错乱）。本方法不经过任何分隔符，键原样写入。
    ///
    /// \`value\` 为 \`null\` 时表示**删除该键**（而非写入 null）—— 让删除也能
    /// 一次原子 patch 完成，不必先读整表再回写（避免读-改-写竞态）。
    pub fn patch_segs(
        &self,
        segs: &[String],
        value: serde_json::Value,
    ) -> Result<Vec<ConfigWarning>, String> {
        if segs.is_empty() {
            return Err("patch path 不能为空".into());
        }
        let segs_owned: Vec<String> = segs.to_vec();
        self.update_with_try(move |cfg| {
            let segs: Vec<&str> = segs_owned.iter().map(String::as_str).collect();
            let shown = segs.join(".");
            let mut cfg_json = serde_json::to_value(&*cfg).map_err(|e| e.to_string())?;
            // 顶层键允许不存在（新建）；中间键必须存在，否则报错（避免静默建错层级）
            if segs.len() == 1 {
                let obj = cfg_json
                    .as_object_mut()
                    .ok_or_else(|| "配置根不是对象".to_string())?;
                if value.is_null() {
                    obj.remove(segs[0]);
                } else {
                    obj.insert(segs[0].to_string(), value);
                }
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
                    .ok_or_else(|| format!("路径 {shown} 的父级不存在"))?;
                let obj = parent
                    .as_object_mut()
                    .ok_or_else(|| format!("路径 {shown} 的父级不是对象"))?;
                if value.is_null() {
                    obj.remove(segs[segs.len() - 1]);
                } else {
                    obj.insert(segs[segs.len() - 1].to_string(), value);
                }
            }
            *cfg = serde_json::from_value(cfg_json).map_err(|e| format!("补丁后配置非法: {e}"))?;
            Ok(())
        })
    }

    /// 持久化当前配置（外部入口；内部写盘走 `persist_snapshot`）。
    pub fn persist(&self) {
        let _guard = self.lock_mutate();
        let cfg = self.get();
        let _ = self.persist_snapshot(&cfg);
    }

    /// 原子写：唯一 tmp → 0600 → fsync → rename。
    ///
    /// 并发写不会共用同一个 tmp 文件；即使 rename 失败，也不会覆盖原文件。
    fn persist_snapshot(&self, cfg: &Config) -> bool {
        let path = self.data_dir.join("config.json");
        match write_config_private(&path, cfg) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!("配置写盘失败: {e}");
                false
            }
        }
    }

    fn sync_atomics(&self, cfg: &Config) {
        self.fail_closed.store(cfg.fail_closed, Ordering::Release);
        self.paused.store(cfg.paused, Ordering::Release);
        self.max_body_bytes
            .store(cfg.mask.max_body_bytes as u64, Ordering::Release);
        // 响应侧还原链路没有 Config，靠这个原子镜像跟随热更新。
        crate::mask::engine::set_blob_policy(&cfg.mask.multimodal_blob);
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

/// 面板令牌必须能安全放进 `Authorization: Bearer` / `x-panel-token` 头。
///
/// 只接受可打印 ASCII（拒绝空白、控制字符、中文等）——否则
/// `HeaderValue::to_str()` 失败会让所有管理 API 返回 401，把控制台锁死。
fn is_valid_panel_token(t: &str) -> bool {
    !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 原子写配置文件：唯一临时名 + 0600 + fsync + rename。
fn write_config_private(path: &Path, cfg: &Config) -> std::io::Result<()> {
    use std::io::Write;
    let body = serde_json::to_string_pretty(cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = dir.join(format!(
        ".config.json.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn restrict_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
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

    /// 回归：panel_token 曾被强制要求 ≥16 位，短令牌会被 `normalized()` **静默丢弃**
    /// 并替换为随机 24 位值 —— 用户设了固定短令牌，却发现每次重启/保存都失效。
    #[test]
    fn short_panel_token_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();

        for short in ["a", "123", "abc", "16chars-long-token"] {
            let mut cfg = center.get();
            cfg.panel_token = short.to_string();
            center.update(cfg);
            assert_eq!(
                center.get().panel_token,
                short,
                "短令牌 {short:?} 必须原样保留，不该被替换成随机值"
            );
        }

        // 极端长度：1 位、以及超长（512 位）都应原样保留
        let mut cfg = center.get();
        cfg.panel_token = "x".repeat(512);
        center.update(cfg);
        assert_eq!(center.get().panel_token.len(), 512);

        // 重启后仍是同一个值（能持久化，不被重新生成）
        let (center2, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        assert_eq!(center2.get().panel_token.len(), 512);

        // 留空：保留旧令牌并告警（不能把 auth 锁死）
        let before = center2.get().panel_token;
        let mut cfg = center2.get();
        cfg.panel_token = String::new();
        let w = center2.update(cfg);
        assert_eq!(
            center2.get().panel_token,
            before,
            "空令牌必须保留原令牌，不能把自己锁在控制台外"
        );
        assert!(
            w.iter().any(|x| x.0.contains("panel_token")),
            "空令牌应产生显式告警"
        );
    }

    #[test]
    fn non_ascii_panel_token_rejected_and_old_kept() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let before = center.get().panel_token;
        let mut cfg = center.get();
        cfg.panel_token = "中文令牌".to_string();
        let w = center.update(cfg);
        assert_eq!(center.get().panel_token, before);
        assert!(w.iter().any(|x| x.0.contains("panel_token")));
        // 重启也不能把非 ASCII 令牌写进配置
        let (center2, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        assert!(center2
            .get()
            .panel_token
            .bytes()
            .all(|b| b.is_ascii_graphic()));
    }

    #[test]
    fn corrupt_config_is_backed_up_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "{ this is not json").unwrap();
        let (center, warnings) = ConfigCenter::load_or_init(dir.path()).unwrap();
        assert!(!center.get().panel_token.is_empty());
        assert!(warnings.iter().any(|w| w.0.contains("备份")));
        let bads: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("config.json.bad.")
            })
            .collect();
        assert_eq!(bads.len(), 1, "坏配置应保留一份 .bad.<ts> 备份");
        // 新配置已落盘且可解析
        let raw = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        let cfg: Config = serde_json::from_str(&raw).unwrap();
        assert!(!cfg.panel_token.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn config_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _ = ConfigCenter::load_or_init(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join("config.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "config.json 含 panel_token，必须是 0600");
    }

    #[test]
    fn concurrent_update_with_keeps_all_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let mut handles = Vec::new();
        for i in 0..8 {
            let c = center.clone();
            handles.push(std::thread::spawn(move || {
                c.update_with(|cfg| {
                    cfg.mask
                        .custom_words
                        .insert(format!("并发词{i}"), "ORG".to_string());
                });
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let cfg = center.get();
        for i in 0..8 {
            assert!(
                cfg.mask.custom_words.contains_key(&format!("并发词{i}")),
                "并发 update_with 不应丢字段: 并发词{i}"
            );
        }
        // 文件仍是完整 JSON
        let raw = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        let _: Config = serde_json::from_str(&raw).unwrap();
    }

    #[test]
    fn builtin_migration_adds_rule_once_and_respects_explicit_empty() {
        let mut c = Config::default();
        c.command_block.patterns.clear();
        c.command_block.builtin_seed_version = 1;
        assert!(super::migrate_builtin_rules(&mut c));
        assert_eq!(c.command_block.builtin_seed_version, 2);
        assert!(
            c.command_block.patterns.is_empty(),
            "显式清空不得被迁移复活"
        );
        assert!(!super::migrate_builtin_rules(&mut c), "已迁移不得重复执行");

        let mut c2 = Config::default();
        c2.command_block
            .patterns
            .retain(|p| p.id != "builtin-rm-root-nopreserve");
        c2.command_block.builtin_seed_version = 1;
        assert!(super::migrate_builtin_rules(&mut c2));
        assert!(c2
            .command_block
            .patterns
            .iter()
            .any(|p| p.id == "builtin-rm-root-nopreserve"));
    }

    #[test]
    fn update_cannot_downgrade_builtin_seed_version() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let mut cfg = center.get();
        cfg.command_block.builtin_seed_version = 1;
        center.update(cfg);
        assert_eq!(center.get().command_block.builtin_seed_version, 2);
    }

    /// 纯空白令牌等同未设置（trim 后触发自动生成），不留「看不见的弱口令」。
    #[test]
    fn blank_panel_token_treated_as_unset() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        let mut cfg = center.get();
        cfg.panel_token = "   \t  ".to_string();
        assert!(
            cfg.normalized().panel_token.is_empty(),
            "全空白令牌应 trim 为空"
        );
    }

    /// 回归：敏感词含 `.` 时，点分 `path` 会被切成多段并写成**嵌套结构**，
    /// 导致 custom_words 的值从「字符串」变成「对象」，匹配逻辑错乱。
    /// `segs` 入口不做任何分隔符切分，键原样写入。
    #[test]
    fn patch_segs_preserves_dots_in_key() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        for word in ["example.com", "Dr. Smith", "a.b.c.d", "normal"] {
            center
                .patch_segs(
                    &[
                        "mask".to_string(),
                        "custom_words".to_string(),
                        word.to_string(),
                    ],
                    serde_json::json!("域名"),
                )
                .unwrap();
            // 扁平键，值仍是字符串
            assert_eq!(
                center.get().mask.custom_words.get(word).map(String::as_str),
                Some("域名"),
                "词 {word:?} 应作为扁平键写入"
            );
            // 绝不能出现嵌套
            let v = serde_json::to_value(center.get()).unwrap();
            let entry = &v["mask"]["custom_words"][word];
            assert!(
                entry.is_string(),
                "词 {word:?} 的值必须是字符串，实际 {:?}",
                entry
            );
        }
        // 切勿把词拆成子键
        let v = serde_json::to_value(center.get()).unwrap();
        assert!(
            v["mask"]["custom_words"]["example"].is_null(),
            "不应产生子键 example"
        );
        assert!(
            v["mask"]["custom_words"]["com"].is_null(),
            "不应产生子键 com"
        );
    }

    /// JSON Pointer 特殊字符 `/` 与 `~` 同样必须原样保留。
    #[test]
    fn patch_segs_preserves_slash_and_tilde() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        for word in ["ACME/Inc", "a~b", "~1/x"] {
            center
                .patch_segs(
                    &[
                        "mask".to_string(),
                        "custom_words".to_string(),
                        word.to_string(),
                    ],
                    serde_json::json!("ORG"),
                )
                .unwrap();
            assert_eq!(
                center.get().mask.custom_words.get(word).map(String::as_str),
                Some("ORG"),
                "词 {word:?} 应原样写入"
            );
        }
    }

    /// `value: null` 表示删除键（而非写入 null 导致反序列化失败）。
    #[test]
    fn patch_segs_null_deletes_key() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        for w in ["example.com", "张三"] {
            center
                .patch_segs(
                    &["mask".into(), "custom_words".into(), w.into()],
                    serde_json::json!("ORG"),
                )
                .unwrap();
        }
        assert_eq!(center.get().mask.custom_words.len(), 2);
        // 删掉含 '.' 的那个
        center
            .patch_segs(
                &["mask".into(), "custom_words".into(), "example.com".into()],
                serde_json::Value::Null,
            )
            .unwrap();
        let m = &center.get().mask.custom_words;
        assert!(!m.contains_key("example.com"), "含 '.' 的键应被准确删除");
        assert_eq!(
            m.get("张三").map(String::as_str),
            Some("ORG"),
            "其他键不受影响"
        );
        // 删不存在的键不应报错（幂等）
        center
            .patch_segs(
                &["mask".into(), "custom_words".into(), "nope".into()],
                serde_json::Value::Null,
            )
            .unwrap();
    }

    /// 旧的点分 path 入口仍应工作（向后兼容）。
    #[test]
    fn patch_dotted_path_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let (center, _) = ConfigCenter::load_or_init(dir.path()).unwrap();
        center
            .patch("mask.custom_words.张三", serde_json::json!("人名"))
            .unwrap();
        assert_eq!(
            center
                .get()
                .mask
                .custom_words
                .get("张三")
                .map(String::as_str),
            Some("人名")
        );
        // segs 为空时回落
        assert!(center.patch("", serde_json::json!(1)).is_err());
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
