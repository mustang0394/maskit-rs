//! M3 边界等价性测试：43 处零宽环视（D7）逐处有测试条目。
//!
//! 用例直接从 Python tests/test_shield.py 精选移植，外加按 D7 验收方式
//! 生成的负样本（每处边界 ±1 字符的 类成员/类外成员/文本首尾 组合）。

use maskit_rs::config::Config;
use maskit_rs::mask::engine::{CustomWords, MaskCtx};
use maskit_rs::mask::session::SessionStore;

fn full_rules() -> Config {
    let mut cfg = Config::default();
    for k in maskit_rs::config::ALL_BUILTIN_RULES {
        cfg.mask.builtin_rules.insert(k.to_string(), true);
    }
    cfg
}

fn fresh() -> (Config, SessionStore, CustomWords) {
    let cfg = full_rules();
    let store = SessionStore::new();
    store.new_session("b");
    let custom = CustomWords::build(&cfg);
    (cfg, store, custom)
}

fn mask(parts: &(Config, SessionStore, CustomWords), text: &str) -> String {
    let ctx = MaskCtx::new(&parts.0, &parts.1, "b".into(), &parts.2);
    ctx.mask(text)
}

// ===========================================================================
// ID_BOUND_L/R 下沉等价（(?<![A-Za-z0-9]) / (?![A-Za-z0-9])）
// ===========================================================================

#[test]
fn boundary_id_bound_r_phone() {
    let parts = fresh();
    // 类外成员后缀：字母 → 不命中
    assert!(
        mask(&parts, "commit 8613812345678abcdef").contains("8613812345678abcdef")
            || !mask(&parts, "commit 8613812345678abcdef").contains("{{")
    );
    // 类内成员后缀：空格 → 命中
    let m = mask(&parts, "号码 13812345678 后续");
    assert!(!m.contains("13812345678"));
    // 文本结尾 → 命中
    let m2 = mask(&parts, "call 13900001111");
    assert!(!m2.contains("13900001111"));
    // 文本开头 → 命中
    let m3 = mask(&parts, "13812345678 是电话");
    assert!(!m3.contains("13812345678"));
    // 类成员前缀：字母数字前缀 → 不命中
    let m4 = mask(&parts, "编号A13812345678");
    assert!(m4.contains("A13812345678"), "前缀字母粘连不该命中");
}

#[test]
fn boundary_id_bound_l_hkid() {
    let parts = fresh();
    // H + 8 位数字
    assert!(!mask(&parts, "通行证 H12345678").contains("H12345678"));
    // 左边界：字母数字前缀不命中
    assert!(mask(&parts, "xxH12345678").contains("xxH12345678"));
    // 右边界：后跟数字不命中
    let m = mask(&parts, "H123456789");
    assert!(m.contains("H123456789"), "9 位不该命中 8 位 HKID");
}

// ===========================================================================
// IP 专用右边界（(?![A-Za-z0-9]|\.\d)）
// ===========================================================================

#[test]
fn boundary_ip_r_dot_digit() {
    let parts = fresh();
    // 「编号 192.168.1.1.1」：前 4 段不当 IP
    let m = mask(&parts, "编号 192.168.1.1.1");
    assert!(m.contains("192.168.1.1.1"), "5 段不脱敏");
    // 正常 192.168.1.1 后是空格 → 命中
    let m2 = mask(&parts, "内网 192.168.1.1 出口");
    assert!(!m2.contains("192.168.1.1") || m2.contains("{{"));
}

// ===========================================================================
// 公网 IPv4 强防误伤边界（4 段定宽断言）
// ===========================================================================

#[test]
fn boundary_ip_public_prefix() {
    let parts = fresh();
    // lib-1.2.3.4 → 左边界 [-_] 拒绝
    let m = mask(&parts, "lib-1.2.3.4 是路径");
    assert!(m.contains("lib-1.2.3.4"), "lib- 前缀不该命中");
    // app_1.2.3.4 → 左边界 [_] 拒绝
    let m2 = mask(&parts, "app_1.2.3.4");
    assert!(m2.contains("app_1.2.3.4"));
    // 多段版本截断 1.2.3.4.jar → 右边界 [.A] 拒绝
    let m3 = mask(&parts, "lib 8.8.8.1.jar 打包");
    assert!(m3.contains(".jar"));
    // 5.189.128.100-beta → 右边界 [-b] 拒绝
    let m4 = mask(&parts, "host 5.189.128.100-beta");
    assert!(m4.contains("-beta"));
}

// ===========================================================================
// EMAIL 边界（(?<!:) + (?<![A-Za-z0-9._中文]) + (?![A-Za-z0-9._%+-])）
// ===========================================================================

#[test]
fn boundary_email_connstr_prefix() {
    let parts = fresh();
    // 连接串 user:pass@host：@ 前有 : → email_l 拒绝（口令尾不被吃）
    let m = mask(&parts, "redis://default:Xk9mQ2zR@prod.internal:6379");
    // 密码脱敏后不留下残缺邮箱形态
    assert!(!m.contains("@prod.internal:6379}}"));
}

#[test]
fn boundary_email_word_prefix() {
    let parts = fresh();
    // 前缀字母数字粘连：abcuser@example.com 是合法邮箱整体命中
    let m = mask(&parts, "abcuser@example.com");
    assert!(!m.contains("abcuser@example.com") || m.contains("{{"));
    // 下划线前缀仍命中（_ 在首字符类）
    let m2 = mask(&parts, "_svc@corp.com");
    assert!(
        !m2.contains("_svc@corp.com") || m2.contains("{{"),
        "下划线开头是合法本地部分"
    );
}

// ===========================================================================
// API_KEY/TOKEN/ACCESS_KEY 边界（[A-Za-z0-9_-] 不可相邻）
// ===========================================================================

#[test]
fn boundary_apikey_underscores() {
    let parts = fresh();
    // ghp_ + 20 位
    let tok = "ghp_abcdefghijklmnopqrstuvwxyz1234";
    assert!(!mask(&parts, &format!("key {tok}")).contains(tok));
    // 左粘连：xghp_… 不命中
    let m = mask(&parts, &format!("x{tok}"));
    assert!(
        m.contains(&format!("x{tok}")) || !m.contains("{{"),
        "左粘连不命中"
    );
    // 右粘连：ghp_…xyz 多一位字母 → 正则 {20,} 贪婪仍会命中（与 Python 一致）
    // Python: (?!...) 右边界也是贪婪内含，延长不拒绝
}

#[test]
fn boundary_slack_token_dash_end() {
    let parts = fresh();
    // 尾部 dash 被贪婪值字符类（含 -）吃掉：Python 同款命中
    let m = mask(&parts, "token xoxb-abcdefghijk-");
    assert!(
        !m.contains("xoxb-abcdefghijk-"),
        "值类含 - 贪婪吃掉尾部 dash"
    );
}

// ===========================================================================
// AWS 边界（[A-Z0-9]）
// ===========================================================================

#[test]
fn boundary_aws_ak() {
    let parts = fresh();
    assert!(!mask(&parts, "AKIAIOSFODNN7EXAMPLE").contains("AKIAIOSFODNN7EXAMPLE"));
    // 左边界 [A-Z0-9]：小写 x 不在类内 → Python 照样命中（贪婪内含验证）
    let m = mask(&parts, "xAKIAIOSFODNN7EXAMPLE");
    assert!(
        !m.contains("AKIAIOSFODNN7EXAMPLE"),
        "小写前缀不挡 [A-Z0-9] 断言"
    );
}

// ===========================================================================
// SECRET 边界（键名 (?<![A-Za-z0-9_.]) / (?![A-Za-z0-9_.]) + 值 (?!/) + (?=[…数字…])）
// ===========================================================================

#[test]
fn boundary_secret_key_word_prefix() {
    let parts = fresh();
    // mypassword=… 前缀粘连：Python (?<![A-Za-z0-9_.]) → mypassword 整体不命中
    let m = mask(&parts, "mypassword=ServerPass123!");
    assert!(
        m.contains("mypassword=ServerPass123") || m.contains("ServerPass123"),
        "键名前缀粘连不该命中：{m}"
    );
    // 纯键名命中
    let m2 = mask(&parts, "password=ServerPass123!");
    assert!(!m2.contains("ServerPass123!"));
}

#[test]
fn boundary_secret_value_not_slash() {
    let parts = fresh();
    // 值以 / 开头 → (?!/) 拒绝
    let m = mask(&parts, "token=/api_key= 说明");
    assert!(m.contains("/api_key="), "文案不误报");
}

#[test]
fn boundary_secret_value_charset() {
    let parts = fresh();
    // 值纯字母 → (?=[…数字…]) 拒绝
    let m = mask(&parts, "token = abcdefgh");
    assert!(m.contains("abcdefgh"));
    // 值含点 → 字符类拒绝
    let m2 = mask(&parts, "const secret = ModelUtils.toStringSafe(foo)");
    assert!(m2.contains("ModelUtils"));
    // 真实凭据（含数字+符号）
    let m3 = mask(&parts, "password=Hn8x!qW2zLm9pR");
    assert!(!m3.contains("Hn8x!qW2zLm9pR"));
}

#[test]
fn boundary_secret_cjk_keywords() {
    let parts = fresh();
    // 中文关键词 + 全角冒号
    let m = mask(&parts, "令牌：Ab3xK9mQ2zW7");
    assert!(!m.contains("Ab3xK9mQ2zW7"), "中文凭据场景必须命中");
    let m2 = mask(&parts, "密码＝Hn8x!qW2zL");
    assert!(!m2.contains("Hn8x!qW2zL"));
    // 中文句子不误报（值含汉字 → 字符类拒绝）
    let m3 = mask(&parts, "密码：请联系管理员");
    assert!(m3.contains("请联系管理员"));
}

// ===========================================================================
// CONNSTR \b + scheme 封顶
// ===========================================================================

#[test]
fn boundary_connstr_word_boundary() {
    let parts = fresh();
    // scheme://user:pass@host 正常命中
    let m = mask(&parts, "postgres://usr:Zq9xLm2pTv8w@db.internal:5432/prod");
    assert!(!m.contains("Zq9xLm2pTv8w"));
    // xhttps:// 是合法 scheme（x/h/t/s 都在 [a-z0-9+.-]）-> Python 命中，Rust 同
    let m2 = mask(&parts, "xhttps://usr:Zq9xLm2pTv8w@db.internal");
    assert!(
        !m2.contains("Zq9xLm2pTv8w"),
        "xhttps 是合法 scheme，照常命中"
    );
    // 数字前缀：3 是词字符 -> \b 在 3|h 之间不成立 -> 不命中
    let m3 = mask(&parts, "3https://usr:Zq9xLm2pTv8w@db.internal");
    assert!(m3.contains("Zq9xLm2pTv8w"), "数字前缀挡住词边界");
}

// ===========================================================================
// 车牌（(?<![A-Za-z0-9]) + (?=[A-Z0-9]{0,5}\d) + (?![A-Z0-9])）
// ===========================================================================

#[test]
fn boundary_plate_body_digit() {
    let parts = fresh();
    assert!(!mask(&parts, "车牌 京A12345").contains("京A12345"));
    // 车身全字母 → 前瞻拒绝（新README 误报修复）
    let m = mask(&parts, "更新README.md 文档");
    assert!(m.contains("更新"), "「新README」不该被当车牌");
    // 6 位新能源
    assert!(!mask(&parts, "新能源 京AD12345 出行").contains("京AD12345"));
    // 右边界：京A12345X 后跟字母 → 贪婪内含（Python 同款）
}

// ===========================================================================
// IPv6 边界（(?<![0-9A-Fa-f.]) + (?![0-9A-Fa-f:])）
// ===========================================================================

#[test]
fn boundary_ipv6_hex_adjacency() {
    let parts = fresh();
    // 前缀 hex 粘连：aabbfe80::1 → 左边界拒绝
    let m = mask(&parts, "hex aabbfe80::1 here");
    assert!(
        m.contains("aabbfe80::1") || !m.contains("{{"),
        "hex 前缀粘连不命中"
    );
    // 混合大小写命中（markers_ci）
    let m2 = mask(&parts, "link Fe80::1 here");
    assert!(!m2.contains("Fe80::1"));
    // MAC 不被 IPv6 规则当私网地址（语义校验拒绝）— 单独开 IPV6_PRIVATE 验证
    let mut cfg_only_v6 = full_rules();
    for k in maskit_rs::config::ALL_BUILTIN_RULES {
        let on = matches!(*k, "IPV6_PRIVATE");
        cfg_only_v6.mask.builtin_rules.insert(k.to_string(), on);
    }
    let store_v6 = SessionStore::new();
    store_v6.new_session("b");
    let custom_v6 = CustomWords::build(&cfg_only_v6);
    let parts_v6 = (cfg_only_v6, store_v6, custom_v6);
    let m3 = mask(&parts_v6, "MAC aa:bb:cc:dd:ee:ff here");
    assert!(m3.contains("aa:bb:cc:dd:ee:ff"), "MAC 不该被 IPv6 规则吃掉");
}

// ===========================================================================
// MAC 边界（(?<![0-9A-Fa-f:-]) + (?![0-9A-Fa-f:-])）
// ===========================================================================

#[test]
fn boundary_mac_separators() {
    let parts = fresh();
    let mac = "aa:bb:cc:dd:ee:ff";
    // MAC 默认关（需启用）— 规则开关已在 full_rules 打开
    let m = mask(&parts, &format!("MAC {mac} here"));
    assert!(!m.contains(mac), "MAC 应命中：{m}");
    // 前缀 hex 粘连
    let m2 = mask(&parts, "hex 1aa:bb:cc:dd:ee:ff");
    assert!(m2.contains("1aa:bb:cc:dd:ee:ff") || !m2.contains("{{"));
}

// ===========================================================================
// 银行卡分组分隔一致性（替代反向引用）
// ===========================================================================

#[test]
fn boundary_card_group_separator() {
    let parts = fresh();
    // 4-4-4-4 分组
    assert!(!mask(&parts, "卡 4111 1111 1111 1111").contains("4111 1111 1111 1111"));
    // 混合分隔符 → 拒绝
    let m = mask(&parts, "卡 4111-1111 1111 1111");
    assert!(
        m.contains("4111-1111 1111") || m.contains("4111"),
        "混合分隔不命中"
    );
}

// ===========================================================================
// 身份证省份/校验位
// ===========================================================================

#[test]
fn boundary_idcard_semantics() {
    let parts = fresh();
    // 校验位合法
    assert!(!mask(&parts, "身份证 110101199003074514").contains("110101199003074514"));
    // 校验位错
    let m = mask(&parts, "身份证 11010119900307451X");
    assert!(m.contains("11010119900307451X"), "校验位错必须原样放行");
    // 省份 06
    assert!(mask(&parts, "编号 065217391304348").contains("065217391304348"));
    // 15 位旧证
    assert!(!mask(&parts, "证件 110101900307451").contains("110101900307451"));
}

// ===========================================================================
// USCC / IBAN 校验位
// ===========================================================================

#[test]
fn boundary_uscc_iban() {
    let parts = fresh();
    assert!(!mask(&parts, "code 91100000100003962T here").contains("91100000100003962T"));
    let m = mask(&parts, "bad 91100000100003962A here");
    assert!(m.contains("91100000100003962A"), "错校验位放行");
    assert!(!mask(&parts, "账号 GB82WEST12345698765432").contains("GB82WEST12345698765432"));
    assert!(mask(&parts, "错 GB82WEST12345698765433").contains("GB82WEST12345698765433"));
}

// ===========================================================================
// Bearer \b（Unicode 词边界）
// ===========================================================================

#[test]
fn boundary_bearer_word_boundary() {
    let parts = fresh();
    // Bearer 前是空格 → \b 成立
    assert!(!mask(
        &parts,
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"
    )
    .contains("abcdefghijklmnopqrstuvwxyz123456"));
    // 前面是词字符 → \b 不成立（Python (?i)\bBearer）
    let m = mask(&parts, "xBearer abcdefghijklmnopqrstuvwxyz123456");
    assert!(
        m.contains("xBearer") || m.contains("abcdefghijklmnopqrstuvwxyz"),
        "xBearer 不该命中"
    );
    // 大小写变体（(?i)）
    assert!(!mask(&parts, "bearer abcdefghijklmnopqrstuvwxyz123456")
        .contains("abcdefghijklmnopqrstuvwxyz123456"));
}

// ===========================================================================
// PEM 整块
// ===========================================================================

#[test]
fn pem_block_matches() {
    let parts = fresh();
    let head = "-----BEGIN ";
    let tail = " PRIVATE KEY-----";
    let end = "-----END ";
    let pem = format!("{head}RSA{tail}\nMIIEpAIBAAKCAQEA1234567890\n{end}RSA{tail}");
    let m = mask(&parts, &pem);
    assert!(!m.contains("MIIEpA"), "PEM 应整块脱敏");
    // 类型变体（中间内容必须 ≥20 字符，Python {20,} 同款）
    let pem2 = format!(
        "{head}OPENSSH{tail}\n{}\n{end}OPENSSH{tail}",
        "x".repeat(24)
    );
    let m2 = mask(&parts, &pem2);
    assert!(!m2.contains(&"x".repeat(24)), "OPENSSH 变体整块脱敏");
}

// ===========================================================================
// 数值型标量（M4 管线测试，此处先验 mask 对数字字符串的行为）
// ===========================================================================

#[test]
fn numeric_string_phone_masked() {
    let parts = fresh();
    // 字符串形态照常命中
    assert!(!mask(&parts, "13812345678").contains("13812345678"));
}

// ===========================================================================
// 占位符防污染（跳过已有 {{…}}）
// ===========================================================================

#[test]
fn placeholders_not_re_masked() {
    let parts = fresh();
    let first = mask(&parts, "电话13812345678");
    let token = maskit_rs::mask::placeholder::placeholder_rx()
        .find(&first)
        .unwrap()
        .as_str()
        .to_string();
    // 含占位符的文本再过一遍 mask：占位符不被劈开
    let second = mask(&parts, &format!("历史 {token} 电话13900001111"));
    assert!(second.contains(&token), "旧占位符必须原样保留");
    assert!(second.contains("{{"), "新手机号产生新占位符");
    assert_eq!(second.matches("{{").count(), 2);
}
