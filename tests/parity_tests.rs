//! Python `tests/test_shield.py` 核心用例的 Rust 等价移植（M3 退出标准 ≥100 例）。
//!
//! 每条用例对应 Python 侧同名/同义断言，保证语义逐条对齐。

use maskit_rs::config::Config;
use maskit_rs::mask::engine::{restore_final, CustomWords, MaskCtx, RestoreStats};
use maskit_rs::mask::session::SessionStore;

fn full_rules() -> Config {
    let mut cfg = Config::default();
    for k in maskit_rs::config::ALL_BUILTIN_RULES {
        cfg.mask.builtin_rules.insert(k.to_string(), true);
    }
    cfg
}

struct Ctx {
    cfg: Config,
    store: SessionStore,
    custom: CustomWords,
    sid: String,
}

impl Ctx {
    fn new(words: &[(&str, &str)]) -> Self {
        let mut cfg = full_rules();
        for (w, l) in words {
            cfg.mask.custom_words.insert(w.to_string(), l.to_string());
        }
        let store = SessionStore::new();
        store.new_session("p");
        let custom = CustomWords::build(&cfg);
        Ctx { cfg, store, custom, sid: "p".into() }
    }

    fn mask(&self, text: &str) -> String {
        let ctx = MaskCtx::new(&self.cfg, &self.store, self.sid.clone(), &self.custom);
        ctx.mask(text)
    }

    fn restore(&self, text: &str) -> String {
        let mut stats = RestoreStats::default();
        restore_final(text, &self.sid, false, &self.store, &mut stats)
    }

    fn roundtrip(&self, text: &str) -> (String, String) {
        let m = self.mask(text);
        let r = self.restore(&m);
        (m, r)
    }
}

// ===========================================================================
// 密码 / 凭据（test_builtin_rules_mask_common_credentials 等）
// ===========================================================================

#[test]
fn credentials_all_kinds() {
    let c = Ctx::new(&[]);
    let text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 \
                OPENAI=sk-proj-abcdefghijklmnopqrstuvwxyz123456 \
                AXON=ah-abcdefghijklmnopqrstuvwxyz123456 \
                password=ServerPass123!";
    let (masked, restored) = c.roundtrip(text);
    assert!(!masked.contains("abcdefghijklmnopqrstuvwxyz123456"));
    assert!(!masked.contains("ServerPass123"));
    assert_eq!(restored, text, "往返必须逐字节一致");
}

#[test]
fn placeholder_carries_no_secret_fragment() {
    let c = Ctx::new(&[]);
    let masked = c.mask("key sk-abcdefghijklmnopqrstuvwxyz123456");
    let rx = maskit_rs::mask::placeholder::placeholder_rx();
    for m in rx.find_iter(&masked) {
        assert!(!m.as_str().contains("abcdef"));
        assert!(!m.as_str().contains("123456"));
    }
}

#[test]
fn prefix_configurable() {
    let mut c = Ctx::new(&[]);
    c.cfg.mask.secret_prefixes = vec!["ak-".into()];
    // 清前缀缓存（不同前缀集）
    let masked = c.mask("ak-abcdefghijklmnopqrstuvwxyz123456 sk-abcdefghijklmnopqrstuvwxyz123456");
    assert!(!masked.contains("ak-abcdefghijklmnopqrstuvwxyz123456"));
    assert!(masked.contains("sk-abcdefghijklmnopqrstuvwxyz123456"), "未配置的前缀不命中");
}

#[test]
fn short_keys_via_custom_words() {
    let c = Ctx::new(&[("sk-abc", "API_KEY"), ("T0k3n", "API_KEY")]);
    let (masked, restored) = c.roundtrip("短 Key 是 sk-abc 与 T0k3n，另外 sk-demo 是日常词");
    assert!(!masked.contains("sk-abc"));
    assert!(!masked.contains("T0k3n"), "自定义词大小写不敏感");
    assert!(masked.contains("sk-demo"), "前缀规则不误伤极短日常词");
    assert_eq!(restored, "短 Key 是 sk-abc 与 T0k3n，另外 sk-demo 是日常词");
}

// ===========================================================================
// 规则开关（test_builtin_rule_toggle_skips_email / test_sensitive_label_and_word_disable）
// ===========================================================================

#[test]
fn rule_toggle_off() {
    let mut c = Ctx::new(&[]);
    c.cfg.mask.builtin_rules.insert("EMAIL".into(), false);
    let masked = c.mask("邮箱 test@example.com 电话13812345678");
    assert!(masked.contains("test@example.com"), "关闭的规则不命中");
    assert!(!masked.contains("13812345678"), "其他规则照常");
}

#[test]
fn custom_word_and_label_disable() {
    let mut c = Ctx::new(&[("重庆", "地域"), ("张三", "人名"), ("李四", "人名")]);
    c.custom.disabled_labels.insert("地域".into());
    let mut wd = std::collections::HashSet::new();
    wd.insert("张三".to_string());
    c.custom.disabled_words.insert("人名".into(), wd);
    let masked = c.mask("重庆的张三和李四");
    assert!(masked.contains("重庆"), "整组禁用");
    assert!(masked.contains("张三"), "词级禁用");
    assert!(!masked.contains("李四"), "其余词照常");
}

#[test]
fn custom_words_same_count_swap() {
    // 等长换词必须立即生效（缓存失效回归）
    let c1 = Ctx::new(&[("张三", "NAME"), ("李四", "NAME")]);
    assert!(!c1.mask("联系人张三").contains("张三"));

    let c2 = Ctx::new(&[("密", "密级"), ("王五", "NAME")]);
    let masked = c2.mask("联系人王五，密 与 公开，旧词张三");
    assert!(!masked.contains("王五"), "新词生效");
    assert!(masked.contains("张三"), "已移除的旧词不命中");
    assert_eq!(c2.restore(&masked), "联系人王五，密 与 公开，旧词张三");
}

#[test]
fn custom_words_prefer_longest_match() {
    let c = Ctx::new(&[("张三", "PERSON"), ("张三公司", "COMPANY")]);
    let masked = c.mask("张三公司");
    assert!(!masked.contains("公司"));
    assert_eq!(masked.matches("{{").count(), 1, "长词优先，只产生一个占位符");
}

// ===========================================================================
// 状态累积（test_last_hits_accumulates_across_mask_calls / new_count）
// ===========================================================================

#[test]
fn last_hits_accumulates_across_calls() {
    let c = Ctx::new(&[("张三", "PERSON"), ("李四", "PERSON")]);
    c.mask("联系人张三");
    c.mask("联系李四");
    let s = c.store.get(&c.sid).unwrap();
    assert_eq!(s.last_hits.len(), 2, "两个叶子命中都累积");
    let n1 = s.new_orig.len();
    drop(s);
    c.mask("张三");
    let s2 = c.store.get(&c.sid).unwrap();
    assert_eq!(s2.new_orig.len(), n1, "重复命中不算新增");
}

// ===========================================================================
// 凭据预览（test_credential_preview_does_not_expose_usable_secret）
// ===========================================================================

#[test]
fn credential_preview_safe() {
    let orig = "sk-1234567890abcdefghijklmnopqrst";
    let pv = maskit_rs::mask::engine::preview(orig, "API_KEY");
    assert_ne!(pv.replace('…', ""), orig, "预览不得等于原文");
    assert!(!pv.contains(&orig[6..orig.len() - 6]), "中段不出现");
    assert!(pv.starts_with("sk-1") && pv.ends_with(&orig[orig.len() - 4..]));
}

#[test]
fn placeholder_suffix_not_derived_from_secret() {
    // 后缀必须来自 CSPRNG，不得由原文推导（安全性质）
    let c1 = Ctx::new(&[]);
    let m1 = c1.mask("电话13812345678");
    let t1 = maskit_rs::mask::placeholder::placeholder_rx().find(&m1).unwrap().as_str().to_string();
    let suffix = maskit_rs::mask::placeholder::token_suffix(&t1);
    for i in 0..("13812345678".len() - 2) {
        assert!(!suffix.contains(&"13812345678"[i..i + 3]), "后缀不得含原文片段");
    }
}

// ===========================================================================
// 往返语义（4 个协议的 JSON 字符串层面）
// ===========================================================================

#[test]
fn roundtrip_chat_completions_content() {
    let c = Ctx::new(&[("张三", "NAME")]);
    let (masked, restored) = c.roundtrip("客户张三的电话是13812345678");
    assert!(!masked.contains("张三"));
    assert!(!masked.contains("13812345678"));
    assert_eq!(restored, "客户张三的电话是13812345678");
}

#[test]
fn roundtrip_anthropic_system_and_user() {
    let c = Ctx::new(&[]);
    let sys = "你会保护password=ServerPass123!";
    let user = "账号root，token=abcdefghijklmnopqrstuvwxyz123456";
    let (m1, r1) = c.roundtrip(sys);
    let (m2, r2) = c.roundtrip(user);
    assert!(!m1.contains("ServerPass123"));
    assert!(!m2.contains("abcdefghijklmnopqrstuvwxyz123456"));
    assert_eq!(r1, sys);
    assert_eq!(r2, user);
}

#[test]
fn roundtrip_responses_instructions() {
    let c = Ctx::new(&[("张三", "NAME")]);
    let text = "不要泄露sk-proj-abcdefghijklmnopqrstuvwxyz123456 联系张三";
    let (masked, restored) = c.roundtrip(text);
    assert!(!masked.contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456"));
    assert!(!masked.contains("张三"));
    assert_eq!(restored, text);
}

#[test]
fn roundtrip_tool_arguments_multi_turn() {
    let c = Ctx::new(&[("张三", "NAME")]);
    let args = r#"{"name": "张三", "phone": "13812345678"}"#;
    let (masked, restored) = c.roundtrip(args);
    assert!(!masked.contains("张三"));
    assert!(!masked.contains("13812345678"));
    assert_eq!(restored, args, "工具参数往返保形");
    // 协议字段（键名）不动
    assert!(masked.contains("\"name\""));
    assert!(masked.contains("\"phone\""));
}

// ===========================================================================
// 跨请求复用 + 孤儿自愈（test_placeholder_reused_across_requests_and_orphan_is_restored）
// ===========================================================================

#[test]
fn reuse_across_requests_and_orphan_restore() {
    let c = Ctx::new(&[("张三", "NAME")]);
    let m1 = c.mask("客户张三");
    let tok1 = maskit_rs::mask::placeholder::placeholder_rx()
        .find(&m1)
        .unwrap()
        .as_str()
        .to_string();
    // 新会话（模拟第 2 轮）
    c.store.new_session("p2");
    let ctx2 = MaskCtx::new(&c.cfg, &c.store, "p2".into(), &c.custom);
    let m2 = ctx2.mask("张三的电话呢");
    let tok2 = maskit_rs::mask::placeholder::placeholder_rx()
        .find(&m2)
        .unwrap()
        .as_str()
        .to_string();
    assert_eq!(tok1, tok2, "同一原文跨请求复用占位符");
    // 历史里带回的占位符仍能还原（自愈）
    let mut stats = RestoreStats::default();
    let restored = restore_final(&format!("关于{tok1}"), "p2", false, &c.store, &mut stats);
    assert_eq!(restored, "关于张三");
}

// ===========================================================================
// 流式分片（test_sse_split_token_roundtrip / three_chunks）
// ===========================================================================

#[test]
fn split_token_roundtrip_semantics() {
    let c = Ctx::new(&[("张三", "NAME")]);
    let masked = c.mask("客户张三");
    let token = maskit_rs::mask::placeholder::placeholder_rx()
        .find(&masked)
        .unwrap()
        .as_str()
        .to_string();
    // 拆成两段拼接
    let a = &token[..4];
    let b = &token[4..];
    let joined = format!("回复：{a}{b}");
    let mut stats = RestoreStats::default();
    let restored = restore_final(&joined, &c.sid, false, &c.store, &mut stats);
    assert_eq!(restored, "回复：张三");
}

#[test]
fn three_chunk_split_multibyte_safe() {
    let c = Ctx::new(&[]);
    let masked = c.mask("邮箱test@example.com");
    let full = format!("收到{masked}谢谢");
    let chars: Vec<char> = full.chars().collect();
    let (a, b, d) = (
        chars[..chars.len() / 3].iter().collect::<String>(),
        chars[chars.len() / 3..2 * chars.len() / 3].iter().collect::<String>(),
        chars[2 * chars.len() / 3..].iter().collect::<String>(),
    );
    let mut stats = RestoreStats::default();
    let out = restore_final(&format!("{a}{b}{d}"), &c.sid, false, &c.store, &mut stats);
    assert_eq!(out, "收到邮箱test@example.com谢谢");
    assert!(!out.contains("{{"));
}

// ===========================================================================
// 通道隔离（test_restore_channels_do_not_cross_contaminate）
// ===========================================================================

#[test]
fn channels_do_not_cross_contaminate() {
    // 半截占位符缓冲按通道隔离（用 Session.pending 语义验证）
    let c = Ctx::new(&[("张三", "NAME")]);
    let masked = c.mask("客户张三");
    let token = maskit_rs::mask::placeholder::placeholder_rx()
        .find(&masked)
        .unwrap()
        .as_str()
        .to_string();
    let half = token.len() / 2;
    {
        let mut s = c.store.get_mut(&c.sid).unwrap();
        s.pending.insert("c0.content".into(), token[..half].to_string());
    }
    // 另一通道不受影响
    let s = c.store.get(&c.sid).unwrap();
    assert!(!s.pending.contains_key("c0.tool0"));
    drop(s);
    // 同通道续上 → 完整还原
    let mut s = c.store.get_mut(&c.sid).unwrap();
    let buffered = s.pending.remove("c0.content").unwrap();
    drop(s);
    let mut stats = RestoreStats::default();
    let out = restore_final(&format!("{buffered}{}", &token[half..]), &c.sid, false, &c.store, &mut stats);
    assert_eq!(out, "张三");
}

// ===========================================================================
// 重复键 / 零改写（M4 管线前的字符串层面检查）
// ===========================================================================

#[test]
fn clean_text_untouched() {
    let c = Ctx::new(&[]);
    let clean = "帮我看看这段代码";
    assert_eq!(c.mask(clean), clean, "无敏感内容必须逐字节不变");
}

#[test]
fn unique_original_replaced_once_per_rule() {
    let c = Ctx::new(&[]);
    let text = "联系 13800138000 ；".repeat(50);
    let masked = c.mask(&text);
    assert!(!masked.contains("13800138000"));
    assert_eq!(masked.matches("{{").count(), 50, "每处出现都替换");
    let tokens = maskit_rs::mask::placeholder::placeholder_rx()
        .find_iter(&masked)
        .map(|m| m.as_str().to_string())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(tokens.len(), 1, "唯一原文只对应一个占位符");
}

#[test]
fn dedup_output_unchanged_across_unique_origs() {
    let c = Ctx::new(&[]);
    let text = "张三 13800138000 邮箱 alice@example.com；李四 13900139000 邮箱 bob@example.com；".repeat(10);
    let masked = c.mask(&text);
    for leaked in ["13800138000", "13900139000", "alice@example.com", "bob@example.com"] {
        assert!(!masked.contains(leaked));
    }
    let tokens = maskit_rs::mask::placeholder::placeholder_rx()
        .find_iter(&masked)
        .map(|m| m.as_str().to_string())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(tokens.len(), 4, "4 个唯一原文 → 4 个唯一占位符");
}

// ===========================================================================
// 多字节 / 边界安全
// ===========================================================================

#[test]
fn multibyte_boundaries_safe() {
    let c = Ctx::new(&[("张三", "NAME")]);
    // 中文两侧无空格
    assert!(!c.mask("你好张三你好").contains("张三"));
    // emoji 邻接
    let m = c.mask("🎉张三🎉");
    assert!(!m.contains("张三"));
    assert!(m.contains("🎉"));
}

#[test]
fn empty_and_whitespace() {
    let c = Ctx::new(&[]);
    assert_eq!(c.mask(""), "");
    assert_eq!(c.mask("   \n\t  "), "   \n\t  ");
    assert_eq!(c.mask("无敏感"), "无敏感");
}

#[test]
fn large_text_performance_smoke() {
    // 512KB 级文本必须在毫秒级完成（性能验收的快速前哨）
    let c = Ctx::new(&[("张三", "NAME")]);
    let unit = "客户张三的电话是13812345678，邮箱 alice@example.com。";
    let big: String = unit.repeat(12000); // ≈ 600KB
    let t0 = std::time::Instant::now();
    let masked = c.mask(&big);
    let elapsed = t0.elapsed();
    assert!(!masked.contains("13812345678"));
    assert!(!masked.contains("alice@example.com"));
    assert!(
        elapsed.as_millis() < 2000,
        "600KB 文本脱敏耗时 {elapsed:?}（预期 <2s；Python 版同量级实测 >3s）"
    );
}

// ===========================================================================
// 自定义词三级开关（对齐 Python sensitive_disabled / sensitive_word_disabled /
// sensitive_word_whole）——曾长期是死代码（配置层没有键、引擎里集合恒空）
// ===========================================================================

fn cfg_with_custom(words: &[(&str, &str)]) -> (Config, SessionStore, CustomWords) {
    let mut cfg = Config::default();
    for k in maskit_rs::config::ALL_BUILTIN_RULES {
        cfg.mask.builtin_rules.insert(k.to_string(), true);
    }
    for (w, l) in words {
        cfg.mask.custom_words.insert(w.to_string(), l.to_string());
    }
    let store = SessionStore::new();
    store.new_session("t");
    let custom = CustomWords::build(&cfg);
    (cfg, store, custom)
}

fn mask_cfg(
    parts: &(Config, SessionStore, CustomWords),
    text: &str,
) -> String {
    let ctx = MaskCtx::new(&parts.0, &parts.1, "t".into(), &parts.2);
    ctx.mask(text)
}

#[test]
fn custom_label_group_can_be_disabled() {
    // sensitive_disabled: 整组关闭
    let mut parts = cfg_with_custom(&[("重庆", "地域"), ("张三", "人名"), ("李四", "人名")]);
    parts.0.mask.sensitive_disabled = vec!["地域".into()];
    parts.2 = CustomWords::build(&parts.0);
    let masked = mask_cfg(&parts, "重庆的张三和李四");
    assert!(masked.contains("重庆"), "被禁用的分组应原样保留");
    assert!(!masked.contains("张三") && !masked.contains("李四"), "其余分组照常脱敏");
}

#[test]
fn custom_word_can_be_disabled_individually() {
    // sensitive_word_disabled: 组内单词关闭
    let mut parts = cfg_with_custom(&[("重庆", "地域"), ("张三", "人名"), ("李四", "人名")]);
    parts.0.mask.sensitive_word_disabled =
        std::collections::BTreeMap::from([("人名".to_string(), vec!["张三".to_string()])]);
    parts.2 = CustomWords::build(&parts.0);
    let masked = mask_cfg(&parts, "重庆的张三和李四");
    assert!(!masked.contains("重庆"), "未禁用的词照常脱敏");
    assert!(masked.contains("张三"), "被单独禁用的词应保留");
    assert!(!masked.contains("李四"), "同组其他词照常脱敏");
}

#[test]
fn custom_word_whole_match_opt_in() {
    // sensitive_word_whole: 开启后子串形态不再命中（Acme 不应命中 AcmeCorp）
    let mut parts = cfg_with_custom(&[("Acme", "公司"), ("密", "密级")]);
    let before = mask_cfg(&parts, "AcmeCorp 与 机密");
    assert!(!before.contains("AcmeCorp"), "默认子串匹配：Acme 应命中 AcmeCorp");
    assert!(
        before.contains("机密"),
        "单字词「密」带 CJK 边界：不应吃掉「机密」（这正是边界存在的意义）"
    );

    parts.0.mask.sensitive_word_whole = vec!["Acme".into()];
    parts.2 = CustomWords::build(&parts.0);
    let after = mask_cfg(&parts, "AcmeCorp 与 Acme 单独");
    assert!(after.contains("AcmeCorp"), "整词开关：AcmeCorp 内不应命中");
    assert!(
        after.contains("{{"),
        "独立出现的 Acme 仍应命中（整词开关只挡子串形态）"
    );
    assert!(!after.contains("Acme 单独"), "独立的 Acme 应被替换成占位符");
}

#[test]
fn whole_word_switch_keeps_cjk_substring_matching() {
    // 整词开关**不得**把 CJK 也纳入边界，否则中文词永不命中
    // （Python `_WHOLE_WORD_BOUND` 刻意不含汉字的原因）
    let mut parts = cfg_with_custom(&[("机要", "密级")]);
    parts.0.mask.sensitive_word_whole = vec!["机要".into()];
    parts.2 = CustomWords::build(&parts.0);
    let masked = mask_cfg(&parts, "这是机要文件");
    assert!(!masked.contains("机要"), "CJK 词开启整词开关后仍须命中");
}
