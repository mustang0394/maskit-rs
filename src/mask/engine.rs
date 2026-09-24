//! mask()/restore() 引擎编排：规则链 + 自定义词 + 前缀规则 + 会话登记。
//!
//! 对齐 Python transparent.py `mask()` 的完整语义：
//! 1. 前缀规则（sk-/ah-…）→ API_KEY
//! 2. 自定义词（aho-corasick 单趟，长词优先语义）
//! 3. 内置规则逐条（CONNSTR → EMAIL 豁免区间联动）
//! 4. 占位符防污染（跳过已有 {{…}} 片段）
//! 5. 唯一原文去重替换（dict.fromkeys 语义）
//!
//! restore()：三遍扫描（严格 → 转义 → 宽松）+ per-channel 扣留缓冲。

use once_cell::sync::Lazy;

use super::placeholder;
use super::rules::{self, RULES};
use super::session::{token_taken, SessionStore};
use crate::config::{is_credential_label, Config};
use aho_corasick::AhoCorasick;

// ---------------------------------------------------------------------------
// 前缀规则（sk-…）
// ---------------------------------------------------------------------------

/// 前缀正则缓存（前缀集 → 编译产物）。
///
/// 用 RwLock + 快速路径：命中时只读锁（并发无争用）；热路径不重新编译。
static PREFIX_CACHE: Lazy<std::sync::RwLock<(String, Option<regex::Regex>)>> =
    Lazy::new(|| std::sync::RwLock::new((String::new(), None)));

/// 构建前缀规则正则（对齐 `_prefix_secret_regex`：-/_ 等价展开 + 8 位阈值）。
pub fn prefix_regex(secret_prefixes: &[String]) -> Option<regex::Regex> {
    let key = secret_prefixes.join("\u{1}");
    {
        let cache = PREFIX_CACHE.read().unwrap();
        if cache.0 == key {
            return cache.1.clone();
        }
    }
    let mut parts = Vec::new();
    for p in secret_prefixes {
        if p.is_empty() {
            continue;
        }
        let mut pat = String::new();
        for ch in p.chars() {
            match ch {
                '-' | '_' => pat.push_str("[-_]"),
                c => {
                    // 逐字符安全转义
                    for esc in regex::escape(&c.to_string()).chars() {
                        pat.push(esc);
                    }
                }
            }
        }
        parts.push(pat);
    }
    let rx = if parts.is_empty() {
        None
    } else {
        regex::Regex::new(&format!(
            r"(?:{})[A-Za-z0-9][A-Za-z0-9_\-]{{7,}}",
            parts.join("|")
        ))
        .ok()
    };
    {
        let mut cache = PREFIX_CACHE.write().unwrap();
        *cache = (key, rx.clone());
    }
    rx
}

/// 默认前缀（供日志清洗等不持有 Config 的调用点使用）。
pub fn default_secret_prefixes() -> &'static [&'static str] {
    &["sk-", "ah-"]
}

// ---------------------------------------------------------------------------
// 自定义词
// ---------------------------------------------------------------------------

/// 自定义词引擎（词表 → AhoCorasick + label 映射）。
pub struct CustomWords {
    /// 词表（长词优先排序）
    pub words: Vec<(String, String)>, // (word, label)
    /// 小写词 → 词表下标（命中时 O(1) 取原始 key，避免每次线性扫描词表）
    lower_index: std::collections::HashMap<String, usize>,
    pub ac: Option<AhoCorasick>,
    /// 单字词/整词开关（两侧加边界）
    pub single_or_whole: std::collections::HashSet<String>,
    /// re: 前缀的正则词（regex → 失败回退 fancy-regex，D7 第 6 条）
    pub regex_words: Vec<(String, String, CompiledUserRegex)>,
    pub disabled_labels: std::collections::HashSet<String>,
    pub disabled_words: std::collections::HashMap<String, std::collections::HashSet<String>>,
}

/// 用户自定义正则的隔离通道（D7 第 6 条）。
pub enum CompiledUserRegex {
    Linear(regex::Regex),
    Fancy(fancy_regex::Regex),
}

impl CustomWords {
    pub fn build(cfg: &Config) -> Self {
        let mut words: Vec<(String, String)> = cfg
            .mask
            .custom_words
            .iter()
            .map(|(w, l)| (w.clone(), l.clone()))
            .filter(|(w, _)| !w.is_empty() && w.chars().count() <= 200)
            .collect();
        // 长词优先
        words.sort_by(|a, b| {
            b.0.chars()
                .count()
                .cmp(&a.0.chars().count())
                .then(a.0.cmp(&b.0))
        });
        let patterns: Vec<String> = words.iter().map(|(w, _)| w.clone()).collect();
        let ac = if patterns.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true) // IGNORECASE
                // 长词优先（对齐 Python `_custom_words_sorted` 的「同一位置长词先命中」）
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(&patterns)
                .ok()
        };
        let mut regex_words = Vec::new();
        for (w, l) in &words {
            if let Some(pat) = w.strip_prefix("re:") {
                let compiled = match regex::Regex::new(pat) {
                    Ok(r) => CompiledUserRegex::Linear(r),
                    Err(_) => match fancy_regex::Regex::new(pat) {
                        Ok(f) => CompiledUserRegex::Fancy(f),
                        Err(_) => continue, // 坏词跳过，不阻断其他词
                    },
                };
                regex_words.push((pat.to_string(), l.clone(), compiled));
            }
        }
        // 需要加边界的词：① 单字词（防「密」吃掉「密码」）
        //               ② 用户显式开启整词匹配的词（`sensitive_word_whole`）
        // 边界类分档对齐 Python：单字词含 CJK（「密」不应命中「密码」），
        // 整词开关不含 CJK（汉字之间本无词边界，含了等于永��命中）。
        let single_set: std::collections::HashSet<String> = words
            .iter()
            .filter(|(w, _)| w.chars().count() == 1)
            .map(|(w, _)| w.clone())
            .collect();
        let whole_set: std::collections::HashSet<String> = cfg
            .mask
            .sensitive_word_whole
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        let mut boundary_set = single_set;
        for (w, _) in &words {
            if whole_set.contains(&w.to_lowercase()) {
                boundary_set.insert(w.clone());
            }
        }
        let single_or_whole = boundary_set;
        let disabled_labels: std::collections::HashSet<String> =
            cfg.mask.sensitive_disabled.iter().cloned().collect();
        let disabled_words: std::collections::HashMap<String, std::collections::HashSet<String>> =
            cfg.mask
                .sensitive_word_disabled
                .iter()
                .map(|(label, words)| (label.clone(), words.iter().cloned().collect()))
                .collect();
        let mut lower_index = std::collections::HashMap::with_capacity(words.len());
        for (i, (w, _)) in words.iter().enumerate() {
            lower_index.entry(w.to_lowercase()).or_insert(i);
        }
        let this = Self {
            words,
            lower_index,
            ac,
            single_or_whole,
            regex_words,
            disabled_labels,
            disabled_words,
        };
        // 播种自定义词的确定性占位符（对齐 Python `_sync_custom_word_mappings`）：
        // 自定义词原文就在 config.json 里，不存在反推风险；需要跨重启稳定，
        // 否则长任务里历史消息的 {{TERM_xxx}} 还原不回来。
        // 由调用方（AppState）在拿到 store 后调用 register_custom_words，
        // 这里只负责提供 enabled 词表。
        this
    }

    /// 启用中的自定义词（供播种调用）。
    pub fn enabled_words(&self) -> Vec<(String, String)> {
        self.words
            .iter()
            .filter(|(w, l)| self.word_enabled(w, l))
            .cloned()
            .collect()
    }

    /// 在给定会话存储上播种确定性映射。
    pub fn register_words(&self, store: &SessionStore) {
        store.seed_custom_words(&self.enabled_words());
    }

    pub fn word_enabled(&self, word: &str, label: &str) -> bool {
        if self.disabled_labels.contains(label) {
            return false;
        }
        if let Some(set) = self.disabled_words.get(label) {
            if set.contains(word) {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// mask
// ---------------------------------------------------------------------------

/// 一次替换产生的 edit（占位符替换坐标，供响应侧 PII 扫描等使用）。
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub token: String,
}

/// mask 上下文：一次请求级管线共享。
pub struct MaskCtx<'a> {
    pub cfg: &'a Config,
    pub store: &'a SessionStore,
    pub sid: String,
    pub custom: &'a CustomWords,
    /// 前缀规则正则：**构造时预编译一次**。
    /// 早期在每个字符串叶子都重算（join 前缀数组 + 取锁 + clone），
    /// 实测 3000 条消息的请求里这一项就占 10ms。
    prefix_rx: Option<regex::Regex>,
}

impl<'a> MaskCtx<'a> {
    pub fn new(
        cfg: &'a Config,
        store: &'a SessionStore,
        sid: String,
        custom: &'a CustomWords,
    ) -> Self {
        let prefix_rx = prefix_regex(&cfg.mask.secret_prefixes);
        Self {
            cfg,
            store,
            sid,
            custom,
            prefix_rx,
        }
    }

    /// 已在构造期编译好的前缀正则（clone 成本 = Arc 原子加）。
    fn prefix_rx(&self) -> Option<&regex::Regex> {
        self.prefix_rx.as_ref()
    }
}

impl<'a> MaskCtx<'a> {
    /// 纯文本脱敏（对齐 Python mask()）。
    pub fn mask(&self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }
        let taken = token_taken();
        let mut out = text.to_string();
        // 本次 mask 调用命中的原文（用于 last_hits 登记，避免扫全量 fwd）
        let mut hit_acc: std::collections::HashSet<String> = std::collections::HashSet::new();

        // 1. 前缀规则
        if rules::rule_enabled("API_KEY", &self.cfg.mask.builtin_rules) {
            if let Some(rx) = self.prefix_rx().cloned() {
                let mut spans: Vec<(usize, usize, String)> = Vec::new();
                let mut token_of: std::collections::HashMap<&str, String> =
                    std::collections::HashMap::new();
                let ph_rx = placeholder::placeholder_rx();
                for m in rx.find_iter(&out) {
                    if ph_rx.is_match(m.as_str()) {
                        continue;
                    }
                    let orig = m.as_str();
                    if !token_of.contains_key(orig) {
                        let token = {
                            if self.store.get(&self.sid).is_none() {
                                self.store.new_session(&self.sid);
                            }
                            let mut session = self.store.get_mut(&self.sid).unwrap();
                            self.store.remember(&mut session, orig, "API_KEY", &taken);
                            session.fwd.get(orig).cloned().unwrap_or_default()
                        };
                        if token.is_empty() {
                            continue;
                        }
                        token_of.insert(orig, token);
                    }
                    if let Some(tok) = token_of.get(orig) {
                        spans.push((m.start(), m.end(), tok.clone()));
                    }
                }
                if !spans.is_empty() {
                    hit_acc.extend(token_of.into_keys().map(str::to_string));
                    out = splice_spans(&out, &spans);
                }
            }
        }

        // 2. 自定义词（单趟 aho-corasick + 正则词）
        {
            let (masked, custom_hits) = self.mask_custom_words(&out, &taken);
            out = masked;
            hit_acc.extend(custom_hits);
        }

        // 3. 内置规则（顺序敏感：CONNSTR 在 EMAIL 前）
        //
        // 性能：先用 RegexSet 单趟预筛出「有候选匹配的规则」，再逐条精细处理。
        // 逐条 captures_iter 在长会话（每轮上千条小消息）上开销显著。
        let mut exempt_conn: Vec<(usize, usize)> = Vec::new();
        let candidate: std::collections::HashSet<usize> =
            rules::candidate_rule_indices(&out).into_iter().collect();
        for (rule_idx, rule) in RULES.iter().enumerate() {
            if !candidate.contains(&rule_idx) {
                continue;
            }
            if !rules::rule_enabled(rule.label, &self.cfg.mask.builtin_rules) {
                continue;
            }
            if !rule.may_hit(&out) {
                continue;
            }
            // 单趟完成「校验 + 去重 + 定位」：一次 captures_iter 同时拿到
            // 原文集合与替换区间，避免早期实现的「先收集再 replace_unique」
            // 二次全文扫描（长会话下这是主要开销之一）。
            //
            // 去重必须 O(1)：早期用 `Vec::contains(&orig.to_string())` 是 O(n²)
            // 且每次匹配都分配 String（EMAIL 2000 匹配 → 200 万次分配，
            // 实测 297KB 单叶子从 ~5ms 劣化到 231ms）。
            let mut spans: Vec<(usize, usize, String)> = Vec::new();
            // orig → token：首次出现时取（或签发）占位符，**后续每处出现都要替换**
            // （早期版本用 HashSet 去重后 `continue`，导致同一原文的第二处起
            //  完全没被替换 —— 手机号泄漏的回归根因）。
            let mut token_of: std::collections::HashMap<&str, String> =
                std::collections::HashMap::new();
            let mut matched_any = false;
            for caps in rule.rx.captures_iter(&out) {
                let m0 = caps.get(0).unwrap();
                let m = caps.get(rule.value_group).unwrap_or(m0);
                let orig = m.as_str();
                // 边界 Check（D7 下沉的环视）
                if !rule.checks.iter().all(|chk| chk(&out, m0, &caps)) {
                    continue;
                }
                // 语义校验
                if !rules::semantic_check(rule.label, orig, &out, m0, &caps) {
                    // CONNSTR 被否决 → 压入豁免区间
                    if rule.exempt_on_reject && exempt_conn.len() < 512 {
                        exempt_conn.push((m0.start(), m0.end()));
                    }
                    continue;
                }
                // EMAIL 与豁免区间重叠 → 跳过
                if rule.avoid_exempt
                    && exempt_conn
                        .iter()
                        .any(|(s, e)| m0.start() < *e && m0.end() > *s)
                {
                    continue;
                }
                // 首次出现时取（或签发）占位符；复用已有映射
                if !token_of.contains_key(orig) {
                    let token = {
                        if self.store.get(&self.sid).is_none() {
                            self.store.new_session(&self.sid);
                        }
                        let mut session = self.store.get_mut(&self.sid).unwrap();
                        self.store.remember(&mut session, orig, rule.label, &taken);
                        session.fwd.get(orig).cloned().unwrap_or_default()
                    };
                    if token.is_empty() {
                        continue;
                    }
                    token_of.insert(orig, token);
                }
                let token = token_of.get(orig).cloned().unwrap_or_default();
                if token.is_empty() {
                    continue;
                }
                matched_any = true;
                // value_group=0 替换整段；>0 只替换捕获组区间
                let (gs, ge) = if rule.value_group == 0 {
                    (m0.start(), m0.end())
                } else {
                    (m.start(), m.end())
                };
                spans.push((gs, ge, token));
            }
            if matched_any {
                hit_acc.extend(token_of.into_keys().map(str::to_string));
                out = splice_spans(&out, &spans);
            }
        }

        // 4. 会话登记 last_hits（跨叶子累积）
        //
        // 只登记**本次 mask 调用新签发/命中的原文**，不能扫全量 fwd：
        // 早期实现每次 mask() 都克隆整个 fwd 键集（长会话 fwd 可达数千条），
        // 于是「一个请求几千条消息」变成 O(消息数 × fwd 数) 的平方级开销。
        // 命中集合已由 replace_unique / mask_custom_words 维护在 hit_acc 中。
        if !hit_acc.is_empty() {
            if let Some(mut s) = self.store.get_mut(&self.sid) {
                for orig in hit_acc {
                    let is_new = !s.fwd.contains_key(&orig);
                    s.last_hits.insert(orig.clone());
                    if is_new {
                        s.new_orig.insert(orig);
                    }
                }
            }
        }
        out
    }

    /// 对单条规则的唯一原文批量替换（对齐 `_mask_excluding_placeholders_ed` +
    /// `dict.fromkeys` 去重语义）。
    #[allow(clippy::too_many_arguments)]
    fn replace_unique(
        &self,
        text: &str,
        rx: &regex::Regex,
        value_group: usize,
        unique_origs: &[String],
        label: &str,
        taken: &dyn Fn(&str, &str) -> bool,
    ) -> String {
        use std::collections::HashMap;
        // 建立 orig → token 映射（复用表决定 token）
        let mut repl_map: HashMap<String, String> = HashMap::new();
        {
            if self.store.get(&self.sid).is_none() {
                self.store.new_session(&self.sid);
            }
            let mut session = self.store.get_mut(&self.sid).unwrap();
            for orig in unique_origs {
                if repl_map.contains_key(orig) {
                    continue;
                }
                let reused = self.store.remember(&mut session, orig, label, taken);
                let token = session.fwd.get(orig).cloned().unwrap_or_default();
                if reused {
                    // 记录到 session.suffix_reused 诊断
                }
                if !token.is_empty() {
                    repl_map.insert(orig.clone(), token);
                }
            }
        }
        if repl_map.is_empty() {
            return text.to_string();
        }
        // 单趟替换：跳过已有占位符片段（finditer 顺序，不重叠）
        let mut out = String::with_capacity(text.len() + 64);
        let mut last = 0usize;
        let placeholder_rx = placeholder::placeholder_rx();
        // 占位符区间已按 start 升序；用二分定位，避免 O(命中数 × 占位符数)
        let placeholders: Vec<(usize, usize)> = placeholder_rx
            .find_iter(text)
            .map(|m| (m.start(), m.end()))
            .collect();
        for caps in rx.captures_iter(text) {
            let m0 = caps.get(0).unwrap();
            let m = caps.get(value_group).unwrap_or(m0);
            let orig = m.as_str();
            let Some(token) = repl_map.get(orig) else {
                continue;
            };
            // 跳过落在已有占位符内的命中（二分：找到 start <= m0.start() 的最后一个区间）
            if overlaps_any(&placeholders, m0.start(), m0.end()) {
                continue;
            }
            if m0.start() < last {
                continue; // 重叠（不该发生，防御）
            }
            out.push_str(&text[last..m0.start()]);
            if value_group == 0 {
                out.push_str(token);
            } else {
                // value_group > 0：替换捕获组区间、保留匹配其余文本
                let gs = m0.start() + (m.start() - m0.start());
                let ge = m0.start() + (m.end() - m0.start());
                out.push_str(&text[m0.start()..gs]);
                out.push_str(token);
                out.push_str(&text[ge..m0.end()]);
            }
            last = m0.end();
        }
        out.push_str(&text[last..]);
        out
    }

    /// 自定义词替换。返回 (替换后文本, 本次命中的原文集合)。
    fn mask_custom_words(
        &self,
        text: &str,
        taken: &dyn Fn(&str, &str) -> bool,
    ) -> (String, std::collections::HashSet<String>) {
        let mut out = text.to_string();
        let mut hits: std::collections::HashSet<String> = std::collections::HashSet::new();
        // 2a. aho-corasick 单趟
        if let Some(ac) = &self.custom.ac {
            let placeholder_rx = placeholder::placeholder_rx();
            // 收集所有命中（同位置长词优先：AhoCorasick 最长匹配模式）
            let mut repl: std::collections::HashMap<usize, (usize, String, String)> =
                std::collections::HashMap::new(); // start -> (end, word_key, token)
            let placeholders: Vec<(usize, usize)> = placeholder_rx
                .find_iter(&out)
                .map(|m| (m.start(), m.end()))
                .collect();
            for mat in ac.find_iter(&out) {
                let word = &self.custom.words[mat.pattern().as_usize()].0;
                let label = self.custom.words[mat.pattern().as_usize()].1.clone();
                if !self.custom.word_enabled(word, &label) {
                    continue;
                }
                // 边界词：① 单字词（防「密」吃掉「密码」）
                //         ② 用户开启整词匹配的词（`sensitive_word_whole`，防 Acme 命中 AcmeCorp）
                // 边界类分档对齐 Python：单字词含 CJK；整词开关**不���** CJK
                // （汉字之间本无词边界，纳入就等于永不命中）。
                if self.custom.single_or_whole.contains(word) {
                    let is_single = word.chars().count() == 1;
                    let before = out[..mat.start()].chars().next_back();
                    let after = out[mat.end()..].chars().next();
                    let is_wordish = |c: Option<char>| {
                        c.map(|c| {
                            let ascii = c.is_ascii_alphanumeric() || c == '_';
                            let cjk = is_single && ('\u{4e00}'..='\u{9fff}').contains(&c);
                            ascii || cjk
                        })
                        .unwrap_or(false)
                    };
                    if is_wordish(before) || is_wordish(after) {
                        continue;
                    }
                }
                let (s, e) = (mat.start(), mat.end());
                if overlaps_any(&placeholders, s, e) {
                    continue;
                }
                if let Some((pe, _, _)) = repl.get(&s) {
                    if *pe >= e {
                        continue; // 已有更长命中
                    }
                }
                // 找原文 key（大小写归一 → O(1) 查预建索引）
                let matched = &out[s..e];
                let word_key = self
                    .custom
                    .lower_index
                    .get(&matched.to_lowercase())
                    .map(|&i| self.custom.words[i].0.clone())
                    .unwrap_or_else(|| matched.to_string());
                // 登记会话映射
                let token = {
                    if self.store.get(&self.sid).is_none() {
                        self.store.new_session(&self.sid);
                    }
                    let mut session = self.store.get_mut(&self.sid).unwrap();
                    self.store.remember(&mut session, &word_key, &label, taken);
                    session.fwd.get(&word_key).cloned().unwrap_or_default()
                };
                hits.insert(word_key.clone());
                repl.insert(s, (e, word_key, token));
            }
            if !repl.is_empty() {
                let mut new_out = String::with_capacity(out.len() + 32);
                let mut i = 0usize;
                while i < out.len() {
                    if let Some((e, _, token)) = repl.get(&i) {
                        new_out.push_str(token);
                        i = *e;
                    } else {
                        let ch = out[i..].chars().next().unwrap();
                        new_out.push(ch);
                        i += ch.len_utf8();
                    }
                }
                out = new_out;
            }
        }
        // 2b. 正则词（re: 前缀）
        for (_pat, label, compiled) in &self.custom.regex_words {
            match compiled {
                CompiledUserRegex::Linear(rx) => {
                    let origs: Vec<String> =
                        rx.find_iter(&out).map(|m| m.as_str().to_string()).collect();
                    if !origs.is_empty() {
                        out = self.replace_unique(&out, rx, 0, &origs, label, taken);
                        hits.extend(origs.iter().cloned());
                    }
                }
                CompiledUserRegex::Fancy(f) => {
                    // fancy 通道：仅收集原文再走统一替换（保持 100ms 预算语义由 M6 接线）
                    let origs: Vec<String> = f
                        .find_iter(&out)
                        .filter_map(|m| m.ok().map(|mm| mm.as_str().to_string()))
                        .collect();
                    if origs.is_empty() {
                        continue;
                    }
                    // fancy 命中用 aho 思路逐个替换（数量少，直接逐个）
                    for orig in &origs {
                        if self.store.get(&self.sid).is_none() {
                            self.store.new_session(&self.sid);
                        }
                        let token = {
                            let mut session = self.store.get_mut(&self.sid).unwrap();
                            self.store.remember(&mut session, orig, label, taken);
                            session.fwd.get(orig).cloned().unwrap_or_default()
                        };
                        if !token.is_empty() {
                            hits.insert(orig.clone());
                            out = out.replace(orig.as_str(), &token);
                        }
                    }
                }
            }
        }
        (out, hits)
    }

    /// 登记历史遗留占位符进本会话（对齐 `_seed_known`）。
    pub fn seed_known(&self, text: &str) {
        let rx = placeholder::placeholder_rx();
        let now = crate::store::events::now_secs();
        for m in rx.find_iter(text) {
            let token = m.as_str();
            if self.store.get(&self.sid).is_none() {
                self.store.new_session(&self.sid);
            }
            let mut session = self.store.get_mut(&self.sid).unwrap();
            if session.rev.contains_key(token) {
                continue;
            }
            if let Some(rec) = self.store.recent_rev.get(token) {
                if now - rec.ts <= self.store.recent_ttl() as f64 {
                    session.rev.insert(token.to_string(), rec.token.clone());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

/// restore 结果统计（供事件记录）。
#[derive(Default, Debug, Clone)]
pub struct RestoreStats {
    pub restored: u64,
    pub unresolved: u64,
    pub degraded: u64,
    pub samples: Vec<String>,
}

/// 还原文本（对齐 Python restore() final=True 形态；流式扣留在 M7 stream 模块）。
pub fn restore_final(
    text: &str,
    sid: &str,
    escape: bool,
    store: &SessionStore,
    stats: &mut RestoreStats,
) -> String {
    if !text.contains('_') && !text.contains('{') {
        return text.to_string();
    }
    let mut out = text.to_string();

    // 第一遍：容错双花括号（含内部空白/大小写改写）
    let braced = placeholder::braced_placeholder_rx();
    out = restore_pass(&out, braced, sid, escape, store, stats, true);

    // 第二遍：转义形态（只在含反斜杠时跑，降开销）
    if out.contains('\\') {
        let escaped = placeholder::escaped_placeholder_rx();
        out = restore_pass_escaped(&out, escaped, sid, escape, store, stats);
    }

    // 第三遍：宽松形态（剥掉花括号/半残）——只认查得到的 token
    if out.contains('_') {
        let loose = placeholder::loose_placeholder_rx();
        out = restore_pass_loose(&out, loose, sid, escape, store, stats);
    }
    out
}

/// 按替换区间重建文本（区间按捕获顺序升序且不重叠）。
fn splice_spans(text: &str, spans: &[(usize, usize, String)]) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    let total: usize = spans.iter().map(|(_, _, t)| t.len()).sum();
    let mut out = String::with_capacity(text.len() + total.min(1024));
    let mut last = 0usize;
    for (s, e, tok) in spans {
        if *s < last {
            continue; // 重叠（防御，正常不发生）
        }
        out.push_str(&text[last..*s]);
        out.push_str(tok);
        last = *e;
    }
    out.push_str(&text[last..]);
    out
}

/// 区间 [start,end) 是否落在任一已排序区间内（二分，O(log n)）。
fn overlaps_any(sorted_spans: &[(usize, usize)], start: usize, end: usize) -> bool {
    if sorted_spans.is_empty() {
        return false;
    }
    // 找最后一个 span.start <= start
    let idx = sorted_spans.partition_point(|(s, _)| *s <= start);
    if idx == 0 {
        return false;
    }
    let (ss, se) = sorted_spans[idx - 1];
    start >= ss && end <= se
}

fn json_escape_str(s: &str) -> String {
    // 与 Python json.dumps(orig, ensure_ascii=False)[1:-1] 等价
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn restore_pass(
    text: &str,
    rx: &regex::Regex,
    sid: &str,
    escape: bool,
    store: &SessionStore,
    stats: &mut RestoreStats,
    _strict: bool,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for caps in rx.captures_iter(text) {
        let m0 = caps.get(0).unwrap();
        let label_raw = caps.get(1).map(|g| g.as_str()).unwrap_or("");
        let suffix = caps.get(2).map(|g| g.as_str()).unwrap_or("");
        let canon = placeholder::canonicalize(label_raw, suffix);
        let orig = store.lookup(&canon, sid);
        out.push_str(&text[last..m0.start()]);
        match orig {
            Some(o) => {
                stats.restored += 1;
                if m0.as_str() != canon {
                    stats.degraded += 1;
                }
                out.push_str(&apply_escape(&o, escape));
            }
            None => {
                stats.unresolved += 1;
                if stats.samples.len() < 5 && !stats.samples.contains(&m0.as_str().to_string()) {
                    stats.samples.push(m0.as_str().to_string());
                }
                out.push_str(m0.as_str());
            }
        }
        last = m0.end();
    }
    out.push_str(&text[last..]);
    out
}

fn restore_pass_escaped(
    text: &str,
    rx: &regex::Regex,
    sid: &str,
    escape: bool,
    store: &SessionStore,
    stats: &mut RestoreStats,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for caps in rx.captures_iter(text) {
        let m0 = caps.get(0).unwrap();
        let label_raw = caps.get(1).map(|g| g.as_str()).unwrap_or("");
        let suffix = caps.get(2).map(|g| g.as_str()).unwrap_or("");
        let canon = placeholder::canonicalize(label_raw, suffix);
        let orig = store.lookup(&canon, sid);
        out.push_str(&text[last..m0.start()]);
        match orig {
            Some(o) => {
                stats.restored += 1;
                stats.degraded += 1;
                out.push_str(&apply_escape(&o, escape));
            }
            None => {
                // 只对真·转义形态计数（含反斜杠）
                if m0.as_str().contains('\\') {
                    stats.unresolved += 1;
                    if stats.samples.len() < 5 {
                        stats.samples.push(m0.as_str().to_string());
                    }
                }
                out.push_str(m0.as_str());
            }
        }
        last = m0.end();
    }
    out.push_str(&text[last..]);
    out
}

fn restore_pass_loose(
    text: &str,
    rx: &regex::Regex,
    sid: &str,
    escape: bool,
    store: &SessionStore,
    stats: &mut RestoreStats,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for caps in rx.captures_iter(text) {
        let m0 = caps.get(0).unwrap();
        let whole = m0.as_str();
        if whole.starts_with("{{") && whole.ends_with("}}") {
            continue; // 第一遍已处理
        }
        let tok_body = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|g| g.as_str().trim().to_string())
            .unwrap_or_default();
        let canon = format!("{{{{{}}}}}", tok_body);
        let orig = store.lookup(&canon, sid);
        let real = if orig.is_none() && whole.starts_with('{') {
            store.suffix_real_token(&canon)
        } else {
            None
        };
        let orig = orig.or_else(|| real.as_ref().and_then(|r| store.lookup(r, sid)));
        out.push_str(&text[last..m0.start()]);
        match orig {
            Some(o) => {
                stats.restored += 1;
                stats.degraded += 1;
                out.push_str(&apply_escape(&o, escape));
            }
            None => {
                // 前一字符是反斜杠 → 转义块内部片段，不重复计数
                let prev_backslash = m0.start() > 0 && text[..m0.start()].ends_with('\\');
                if !prev_backslash {
                    stats.unresolved += 1;
                    if stats.samples.len() < 5 && !stats.samples.contains(&whole.to_string()) {
                        stats.samples.push(whole.to_string());
                    }
                }
                out.push_str(whole);
            }
        }
        last = m0.end();
    }
    out.push_str(&text[last..]);
    out
}

fn apply_escape(orig: &str, escape: bool) -> String {
    if escape {
        json_escape_str(orig)
    } else {
        orig.to_string()
    }
}

// 凭据预览转发（供事件层使用）
pub fn preview(orig: &str, label: &str) -> String {
    if is_credential_label(label) {
        super::validators::cred_preview(orig, label)
    } else {
        super::validators::plain_preview(orig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_ctx(custom_words: &[(&str, &str)]) -> (Config, SessionStore, CustomWords) {
        let mut cfg = Config::default();
        // 全部规则打开（对齐 Python setUp）
        for k in crate::config::ALL_BUILTIN_RULES {
            cfg.mask.builtin_rules.insert(k.to_string(), true);
        }
        for (w, l) in custom_words {
            cfg.mask.custom_words.insert(w.to_string(), l.to_string());
        }
        let store = SessionStore::new();
        store.new_session("t");
        let custom = CustomWords::build(&cfg);
        (cfg, store, custom)
    }

    fn mask_with(ctx_parts: &(Config, SessionStore, CustomWords), text: &str) -> String {
        let ctx = MaskCtx::new(&ctx_parts.0, &ctx_parts.1, "t".into(), &ctx_parts.2);
        ctx.mask(text)
    }

    fn restore_with(ctx_parts: &(Config, SessionStore, CustomWords), text: &str) -> String {
        let mut stats = RestoreStats::default();
        restore_final(text, "t", false, &ctx_parts.1, &mut stats)
    }

    #[test]
    fn mask_phone_and_email() {
        let parts = test_ctx(&[]);
        let masked = mask_with(&parts, "电话13812345678 邮箱test@example.com");
        assert!(!masked.contains("13812345678"));
        assert!(!masked.contains("test@example.com"));
        assert_eq!(masked.matches("{{").count(), 2);
        // 还原
        let restored = restore_with(&parts, &masked);
        assert_eq!(restored, "电话13812345678 邮箱test@example.com");
    }

    #[test]
    fn mask_custom_words() {
        let parts = test_ctx(&[("张三", "NAME"), ("李四", "NAME")]);
        let masked = mask_with(&parts, "联系人张三和李四");
        assert!(!masked.contains("张三"));
        assert!(!masked.contains("李四"));
        assert_eq!(masked.matches("{{").count(), 2);
        let restored = restore_with(&parts, &masked);
        assert_eq!(restored, "联系人张三和李四");
    }

    #[test]
    fn single_char_word_boundary() {
        let parts = test_ctx(&[("密", "密级"), ("张三", "人名")]);
        let masked = mask_with(&parts, "文件密级是公开，联系人张三");
        assert!(masked.contains("密级"), "「密」不该吃掉「密级」");
        assert!(!masked.contains("张三"));
        // 独立单字仍命中
        let masked2 = mask_with(&parts, "密 与 公开");
        assert!(!masked2.contains("密 与"));
    }

    #[test]
    fn secret_no_nested_placeholder() {
        let parts = test_ctx(&[]);
        let masked = mask_with(&parts, r#"config api_key="sk-abcdefghijklmnop123456""#);
        assert!(!masked.contains("sk-abcdefghijklmnop123456"));
        assert_eq!(
            masked.matches("{{").count(),
            1,
            "只能有一个占位符，不得嵌套"
        );
        let restored = restore_with(&parts, &masked);
        assert!(!restored.contains("{{"));
        assert!(restored.contains("sk-abcdefghijklmnop123456"));
    }

    #[test]
    fn prefix_rules_short_words_not_masked() {
        let parts = test_ctx(&[]);
        let masked = mask_with(&parts, "sk-demo ah-test sk-abc ah-1234");
        assert_eq!(masked, "sk-demo ah-test sk-abc ah-1234");
    }

    #[test]
    fn multi_turn_reuses_token() {
        let parts = test_ctx(&[("张三", "PERSON")]);
        let m1 = mask_with(&parts, "客户张三");
        let t1 = placeholder::placeholder_rx()
            .find(&m1)
            .unwrap()
            .as_str()
            .to_string();
        // 第二轮同原文
        let store = &parts.1;
        store.new_session("t2");
        let ctx2 = MaskCtx::new(&parts.0, store, "t2".into(), &parts.2);
        let m2 = ctx2.mask("客户张三");
        let t2 = placeholder::placeholder_rx()
            .find(&m2)
            .unwrap()
            .as_str()
            .to_string();
        assert_eq!(t1, t2, "多轮对话同一实体同占位符");
    }

    #[test]
    fn connstr_email_avoidance() {
        let parts = test_ctx(&[]);
        // 口令尾@host：EMAIL 不得吃掉口令半截
        let masked = mask_with(&parts, "redis://default:Xk9mQ2zR@prod-db.internal:6379");
        // CONNSTR 密码被脱敏
        assert!(!masked.contains("Xk9mQ2zR"));
        // 不应出现残缺占位（EMAIL 吃一半）
        assert!(!masked.contains("@prod-db.internal:6379}}"));
    }

    #[test]
    fn restore_escape_in_json_args() {
        let parts = test_ctx(&[]);
        // 手工登记一个含引号的原文
        {
            let taken = token_taken();
            let mut s = parts.1.get_mut("t").unwrap();
            parts.1.remember(&mut s, "张\"三\n李四", "TERM", &taken);
        }
        let token = parts.1.get("t").unwrap().fwd["张\"三\n李四"].clone();
        let args = format!(r#"{{"name": "{token}"}}"#);
        let mut stats = RestoreStats::default();
        let out = restore_final(&args, "t", true, &parts.1, &mut stats);
        // 解析回 JSON
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["name"], "张\"三\n李四");
    }

    #[test]
    fn escaped_placeholder_restore() {
        let parts = test_ctx(&[]);
        {
            let taken = token_taken();
            let mut s = parts.1.get_mut("t").unwrap();
            parts.1.remember(&mut s, "1.2.3.4", "IP_PRIVATE", &taken);
        }
        let token = parts.1.get("t").unwrap().fwd["1.2.3.4"].clone();
        let suffix = placeholder::token_suffix(&token);
        // 构造转义形态 \{\{TERM_sfx\}\}
        let real_escaped = format!("addr \\{{\\{{TERM_{}}}\\}} end", suffix);
        let mut stats = RestoreStats::default();
        let out = restore_final(&real_escaped, "t", false, &parts.1, &mut stats);
        // 未登记 TERM → 原样放行（不猜）
        assert!(out.contains("\\{\\{TERM_"));
    }

    #[test]
    fn loose_placeholder_bare_token() {
        let parts = test_ctx(&[]);
        {
            let taken = token_taken();
            let mut s = parts.1.get_mut("t").unwrap();
            parts.1.remember(&mut s, "secret-value", "SECRET", &taken);
        }
        let token = parts.1.get("t").unwrap().fwd["secret-value"].clone();
        // 模型剥掉花括号：SECRET_b5a53c
        let bare = token.trim_matches(|c| c == '{' || c == '}');
        let mut stats = RestoreStats::default();
        let out = restore_final(bare, "t", false, &parts.1, &mut stats);
        assert_eq!(out, "secret-value");
    }

    #[test]
    fn hold_partial_placeholder_streaming() {
        // 半截占位符扣留判定（对齐 restore() 的 pending 逻辑）
        let text = "结尾{{NAME_ab";
        let rx = placeholder::partial_rx();
        let m = rx.find(text).unwrap();
        assert_eq!(m.end(), text.len());
        assert!(m.len() <= placeholder::PARTIAL_MAX);
    }

    #[test]
    fn unknown_placeholder_left_alone() {
        let parts = test_ctx(&[]);
        let mut stats = RestoreStats::default();
        let out = restore_final(
            "value {{EMAIL_bcdfgh}} end",
            "t",
            false,
            &parts.1,
            &mut stats,
        );
        assert!(out.contains("{{EMAIL_bcdfgh}}"), "查不到原文原样放行");
        assert_eq!(stats.unresolved, 1);
    }
}
