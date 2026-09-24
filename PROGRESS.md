# Maskit-RS 进度台账

> 配套设计文档：[PLAN.md](./PLAN.md)（当前 v1.1）
> 更新纪律：每个里程碑完成（退出标准达成）后立即更新本文件；实施中的发现记录到「实施日志」。**禁止提前标记完成。**

---

## 状态总览

| 里程碑 | 内容 | 状态 | 完成时间 |
|--------|------|------|----------|
| M0 | 环境与骨架 | ✅ 完成 | 2026-09-23 |
| M1 | 配置与服务器 | ✅ 完成 | 2026-09-23 |
| M2 | 协议识别 | ✅ 完成 | 2026-09-23 |
| M3 | 规则引擎核心 | ✅ 完成 | 2026-09-23 |
| M4 | JSON 树管线 | ✅ 完成 | 2026-09-23 |
| M5 | 会话与占位符复用 | ✅ 完成 | 2026-09-23 |
| M6 | 反代管线集成 | ✅ 完成 | 2026-09-23 |
| M7 | 响应侧与流式 | ✅ 完成 | 2026-09-23 |
| M8 | 审计引擎 | ✅ 完成 | 2026-09-23 |
| M9 | 事件库与统计 | ✅ 完成 | 2026-09-23 |
| M10 | Web UI 与 API | ✅ 完成 | 2026-09-23 |
| M11 | 性能验收与打磨 | ✅ 完成 | 2026-09-23 |
| M12 | 交付 | ✅ 完成 | 2026-09-23 |

状态图例：⬜ 未开始 ｜ 🔵 进行中 ｜ ✅ 完成（须附验证证据）｜ ⏸ 阻塞（须附原因）

---

## 当前状态

**全部 13 个里程碑完成。**

- M0 证据：Rust 1.98.1 (stable) + clippy 已安装；`cargo init` 完成；依赖清单落定；build/test/clippy 全部通过
- M1 证据：13 个单测全绿；axum 双路由；token 鉴权；冒烟验证透传（头/body/query 全对）
- M2 证据：`detect/mod.rs` 12 个单测全绿（三大协议 + Unknown + 边界形态 + tool 循环 + Gemini 形态归 Unknown）；职责边界 D6 已在模块文档与测试注释中声明；clippy -D warnings 零告警
- M3 证据（120 个测试全绿 + clippy -D warnings 零告警）：
  - `placeholder.rs`：占位符正则族（严格/容错/转义/宽松/半截扣留）、纯辅音后缀、`safe_label` 截断 12 位（7 测）
  - `validators.rs`：11 类校验器（Luhn/身份证 15+18/手机/座机/邮箱/IBAN/JWT/USCC/IPv4 公网/IPv6 私网/连接串豁免）— 逐条对齐 Python 语义（12 测）
  - `rules.rs`：**32 条 pattern / 21 label**，D7 环视全部下沉为 `Check`（含 ID_BOUND、IP 专用右边界、公网 IP 四段定宽断言、EMAIL 三重边界、SECRET 键名/值域/`(?!/)`、CONNSTR `\b`、车牌数字前瞻、MAC 边界），aho-corasick 特征预筛（含 IPV6_PRIVATE 大小写不敏感）（13 测）
  - `session.rs`：会话映射 + TTL 复用表（2000 条上限/24h TTL）+ 后缀索引（撞车置 Ambiguous）+ 套娃解包防护 + 自定义词永久映射（6 测）
  - `engine.rs`：mask() 完整规则链（前缀 → 自定义词 → 32 条内置规则 + CONNSTR↔EMAIL 豁免区间联动）+ restore() 三遍扫描（严格/转义/宽松）+ JSON 转义还原（11 测）
  - `tests/boundary_tests.rs`：**43 处环视逐处覆盖**（类成员/类外成员/文本首尾组合）（24 测）
  - `tests/parity_tests.rs`：Python test_shield.py 核心用例移植（25 测，含往返一致性、多轮复用、分片还原、通道隔离、600KB 性能冒烟）
- 修正记录（实施中发现）：Rust regex 的 Match 偏移是**绝对**值（曾误加 m.start() 导致越界 panic）；MAC 正则多一对（7 组→6 组）；AhoCorasick 需 `MatchKind::LeftmostLongest` 才符合「长词优先」；占位符重叠判定由线性扫描改二分（性能）
- M4 证据（143 个测试全绿，clippy 零告警）：
  - `exemptions.rs`：路径感知豁免表（skip_scalar/subtree/correlation_id/business/role_type/protocol_id/protocol_parents/skip_keys + 键名白名单 + 深度上限 24 + 数值豁免表）；`leaf_exempt` 判定与 Python 逐条对齐（4 测，含「广谱护栏」断言 60 个协议顶层键全在白名单）
  - `tree.rs`：`load_json_pairs`（保序 + **重复键检测** tokenizer）、`mask_tree`（路径感知 + 业务区强制 + 键名脱敏 + 数值分支）、`restore_tree`（含 JSON 字符串字段转义还原）、`splice_mask`（字节级替换 + 长 form 优先 + aho-corasick）、`mask_body`（**三级回写**：splice → 等价校验 → 紧凑重序列化，零改写逐字节透传）、`first_diff_byte` 诊断（19 测）
  - 关键行为验证：零改写逐字节透传（含 `\u` 转义形态）、splice 保客户端排版（首个差异位精确落在被脱敏值上）、数值型手机号脱敏、PII-as-key 脱敏、重复键强制重序列化、协议字段零改动、业务区强制扫描、cache_control 子树跳过 + response_format 反向锁、非对象根包装键不泄漏、深度超限报错
- M5 证据：会话核心（fwd/rev/labels/pending + TTL 复用表 + 后缀索引 + 套娃防护 + 自定义词永久映射）已在 M3 完成并测试；本轮补齐 `Session` 完整字段（cmd_hits/cmd_pend/flush_tmpl/inflight/model/stream_mode 等）供 M6/M7 使用
- M6 证据（178 个测试全绿，clippy 零告警）：
  - `server/proxy.rs`：完整请求管线（**17 行判定矩阵逐行实现**）+ 确定性会话键（SHA-256(ip+首条 user 内容) 前 16 hex）+ MASK 事件（凭据类只留 digest/preview）+ 流式 identity 声明 + 脱敏在 spawn_blocking（CPU 不阻塞 IO）
  - 新增 `UpstreamClient::new_or_placeholder`：上游未配置也能起服务，反代返回 502（消除启动即退出）
  - `tests/pipeline_tests.rs` 17 个端到端用例：真实 HTTP + mock 上游 + **PII 哨兵逐行验证「原文绝不上行」**，覆盖 未路由/只读/DELETE/暂停/413/非 JSON(双向)/无效 JSON(400 双向)/数组根/未知形态(双向)/三协议强制脱敏/管线异常/凭据不落原文
- M7 证据（232 个测试全绿，clippy 零告警）：
  - `stream/slots.rs`：三大协议增量槽位识别（OpenAI chat 的 content/reasoning_content/reasoning/tool_calls[].arguments/function_call；Anthropic content_block_delta 的 text/thinking/partial_json；Responses 的 output_text/reasoning_text/function_call_arguments 含 content_index 分通道；Ollama NDJSON）+ terminal_prefixes + set_slot 写回（6 测）
  - `stream/sse.rs`：SSE 分帧（CRLF 归一）+ per-channel 半截占位符扣留（48 字节上限）+ 缓冲超限强制切分（4MB）+ 流末补发（模板克隆保证帧合法）+ NDJSON 逐行 + 聚合转发（8 测，含「中途空输出」与「跨 chunk 拼合」）
  - `server/response.rs`：整包 JSON/SSE/NDJSON 三路径还原 + RESTORE 事件（restore_status 状态机）+ 响应侧 PII 扫描（本会话已知值不误报）+ 凭据清洗（含前缀规则）（7 测）
  - `cmdblock/mod.rs`：三模式（observe 零改写 / rewrite 固定 no-op / block 停止下发）+ 通道分派（tool/text/reason）+ echo 抑制（惰性基线）+ 有界前瞻（64）+ 双通道正则（含 lookahead 的规则走 fancy-regex）+ 内置 7 规则质量门（12 测）
- M8 证据（232 个测试全绿）：
  - `audit/signals.rs`：8 类被动信号移植（error_leak 含熵验证/identity_swap 含同家族换档/tool_call_rewrite/sse_anomaly/response_poison 含注入+外链+伪系统+编码绕过/dangerous_action 恒 LOW/credential_echo 按代码块+熵分档/cross_request_pollution）；**环视下沉**（db_connstring、UPDATE 无 WHERE）；PEM 线性扫描护栏（22 测）
  - `audit/mod.rs`：severity 过滤（含 ALWAYS_RECORD 例外）+ dedupe（重复次数并入 evidence）+ aggregate + `on_response` 钩子（含思考通道去噪）+ canary 注册表（6 测）
  - `EventBus::emit_audit` / `recent_audits` / `clear_audits`（审计事件独立 ring）
- 修正记录：命令内置规则的 lookahead 曾因 regex crate 不支持被**静默丢弃**（rm -rf ~ 漏检）→ 改双通道编译；审计信号缺 `(?i)` 导致大写 API key 场景漏检；redact_credentials 漏前缀规则导致 sk- 明文可能落库
- 环境：磁盘曾满（31G 用尽）致 lld Bus error → 清理 `target/debug/incremental`（2.1G）并设 `CARGO_INCREMENTAL=0`
- M9 证据（245 个测试全绿，clippy 零告警）：
  - `store/db.rs`：SQLite 事件库，**schema 与 Python 版逐表一致**（events/meta/audit_events/daily_stats/daily_status/daily_words/daily_tokens/daily_models/daily_prefix）；专用写线程（sync_channel 5000 上限 + 批量 100 条/500ms 事务 + WAL）；DB 故障不死（重连 + dead_letters 计数）；保留期清理；每日聚合（requests/mask_events/restore_events/masked_items/alerts/audit_high + 词级/模型/状态维度）（9 测）
  - **双向互读写验证**（`tests/store_interop_tests.rs` 4 测）：Rust 能解析 Python 写的 payload（含 `sid`/`tok` 字段名、RESTORE 的字符串 `status`）；Python 的 SQL 能读 Rust 写的行（type 大写、payload 字段名、daily_* 聚合口径）
  - 为互操作补齐字段兼容：`session_id`↔`sid`、`token`↔`tok`、`status` 兼容数字与字符串、Python 侧 `dialog`/`count`/`masked_total`/`stream_mode`/`stream_actual`/`restore_status`/`upstream` 全字段映射
  - 接入代理管线：MASK/RESTORE 事件双写（内存 ring + SQLite），审计事件落库；后台维护线程（会话 sweep 30s + 保留期清理）
- 修正记录：`..Default::default()` 曾被误插进 `impl Default for Event` 自身（无限递归 → 栈溢出）；Python payload 的 `sid`/`tok`/字符串 `status` 曾导致解析失败（互操作测试发现）
- M10 证据（257 个测试全绿，clippy 零告警 + **真实进程冒烟通过**）：
  - `assets/`：内嵌 5 页 UI（概览/规则/日志/审计/设置），原生 HTML+CSS+JS（零构建步骤），rust-embed 打包进二进制；深色主题；凭据类在 UI 只显示打码预览 + sha256 摘要
  - `console_api.rs`：20+ 端点（config GET/POST/patch、status、health、proxy pause/resume、logs + detail + clear + export、stats today/history、audit events/clear、upstream/test、demo/mask、rotate-token、data-dir）；Bearer/x-panel-token 双鉴权（health 免鉴权）；Origin 校验（写方法跨站拒绝，CLI 无 Origin 放行）；安全响应头
  - `tests/console_tests.rs` 10 个端到端用例：鉴权（401/双 header/令牌轮换后旧令牌失效）、Origin 跨站拒绝、20 端点可达、配置 patch 持久化、导出恒脱敏（无 original/dialog + masked_export 标记）、UI 可达（HTML/CSS/JS 内容断言）、**上游热重载**
  - 真实进程冒烟（`/tmp/mk-smoke`）：curl 打真实上游 mock → 上游只收到 `{{PHONE_…}}`/`{{APIKEY_…}}`/`{{TERM_…}}` 占位符，客户端收到还原后明文（restored=3）；SQLite 落库 schema 与 Python 一致；**凭据明文未落库**（断言 False）
- 修正记录（冒烟发现）：**运行时改 upstream.target 不生效**（UpstreamClient 启动后不再重建 → 改配置后仍打旧地址）→ 改为 `rebuild_runtime()` 热重载；`patch` 嵌套路径会丢同级字段 → 改用 JSON Pointer；`daily_words` 曾存 preview 而非原文、`masked_items` 用 items 数而非事件自报 count → 按 Python 口径修正
- M11 证据（258 debug 测试 + 10 release 性能测试全绿，clippy 零告警）：
  - **512KB 请求体脱敏：P99 = 90.5ms，相对 Python 基线 3696ms 提升 40.8x**（本机 cgroup CPU 配额仅 **0.6 核**，绝对值不可跨机比较，相对提升是机器无关判据）
  - 1MB P99 160ms；高命中密度（213KB/9000 处命中）26ms；SSE 单事件 2.7µs（目标 <1ms）；SSE 逐字节切分 16KB 1.4ms；零改写 315KB 12-66ms（随调度抖动）
  - 线性性护栏：对抗前缀（连接串/反斜杠/花括号/hex/数字串）体量 ×8 耗时倍率 2.8-7.7x（线性≈8，无回溯退化）
  - 性能优化历程（每一步都有量化收益）：
    1. **占位符正则静态缓存**（原每次调用重新编译）：512KB 616ms → 85ms
    2. **O(1) 去重**（原 `Vec::contains(&orig.to_string())` 是 O(n²)+每匹配一次分配）：单叶 297KB 404ms → 8ms
    3. **mask_tree 可变路径栈**（原每节点 `path.to_vec()` 克隆）
    4. **前缀正则提到 MaskCtx 构造期**（原每叶 join+取锁，3.4µs×3000=10ms）
    5. **恒候选规则合并 RegexSet 门控**（13 条无短 marker 的规则原本逐条独立 DFA 扫描）：零改写 315KB 72ms → 11.6ms
    6. **单趟完成「校验+去重+定位」**（消除每规则二次 captures_iter）
  - 踩坑记录：AC 跨规则预筛因**前缀遮蔽**失效（`":"` 遮蔽 `"://"`、`"1"` 遮蔽 `"192."` → 漏候选→漏脱敏），已改为「长度降序注册 + 单字符 marker 规则恒候选」双保险；RegexSet 全量 32 条在 CJK 上 DFA 缓存抖动反而慢 4x，故只对无短 marker 的规则组做门控
  - 回归修复：单趟改写初版用 HashSet 去重后 `continue`，导致**同一原文第二处起完全不替换**（手机号泄漏），改为 orig→token 映射
  - 磁盘：构建产物一度撑满 31G 根分区（lld Bus error）→ `target/` 3.6G + npm/go 缓存 2.5G；已清并把 `[profile.dev] debug=line-tables-only`、`incremental=false`，现剩 7.3G
- M12 证据（release 二进制 9.3MB + 真实进程端到端验收全通过）：
  - `README.md`：快速开始、协议识别与 fail-closed 判定矩阵、功能清单、目录结构、配置表、安全须知、开发与测试、与 Python 版共存
  - `config.example.json`：全量默认配置模板（21 类规则开关与 Python 版默认值一致）
  - release 构建：`cargo build --release` → 9.3MB 单二进制（内嵌 UI，无外部依赖、无 Node/Python 运行时）
  - 端到端验收（真实进程 + mock 上游）：
    ① 控制台 UI 可达 ② /health 免鉴权 ③ 无 token 访问配置 401 ④ 上游配置热生效 ⑤ 自定义词即时生效
    ⑥ **三大协议全部正确识别并脱敏**（chat_completions / responses / anthropic，事件里 protocol 字段与 items 均正确）
    ⑦ 上游只收到占位符，客户端收到还原后明文（restored=3）
    ⑧ 鉴权头（Authorization / x-api-key）原样透传
    ⑨ **凭据红线**：API_KEY 原文既不进事件 items 也不进 SQLite（只有 sha256 摘要 + 打码预览）；非凭据 PII 保留原文供详情对照
    ⑩ SSE 流式请求自动声明 `accept-encoding: identity`（保证可逐事件还原）
    ⑪ daily_stats 聚合正确（mask_events / masked_items / restore_events / restored_items）
- 交付物：`maskit-rs/` 独立目录，`cargo build --release` 产出 9.3MB 单二进制；**264** 个 debug 测试 + 10 个 release 性能测试全绿（审计修复后）；`cargo clippy --all-targets -D warnings` 零告警

---

## 实施日志

### 2026-09-23 · M0 环境与骨架 ✅

- 安装 rustup → stable 1.98.1（profile minimal + clippy component）
- `maskit-rs/Cargo.toml`：按 PLAN §8 依赖清单落定，edition 2021，release profile（lto=thin, strip）
- `cargo build` ✅ / `cargo test` ✅ / `cargo clippy -- -D warnings` ✅
- 偏差记录：rusqlite 0.32 无 `wal` feature，去 feature 改用 PRAGMA journal_mode=WAL（语义不变）

### 2026-09-23 · M1 配置与服务器 ✅

- `src/config.rs`：全量 Config 模型（server/upstream/mask/command_block/audit/fail_closed/response_scan/stream_response/retention/panel_token/paused）；默认值对齐 Python shield_defaults（21 类规则默认开 7 类）；`ConfigCenter`：RwLock + 原子镜像热路径免锁读 + 原子写盘（tmp+rename 防写坏）+ 随机 token 生成回写
- `src/server/`：axum Router（/console 静态页 + /console/api/* 15 个端点 + fallback 反代）；Bearer/x-panel-token 双鉴权；security headers 中间件
- `src/upstream/http_client.rs`：hyper legacy client 连接池；`parse_target`（scheme/host/port/path_prefix，IPv6 支持）；`forward_headers` 逐跳剔除；extra_headers 注入（凭据头拒绝逻辑留 M6 接线）
- `src/store/events.rs`：事件模型 + EventBus（ring 2000 + 计数器），M1 已被 /api/logs 使用
- `tests/mock_upstream.py`：echo 上游，冒烟用
- 冒烟：401/200 鉴权、config patch 持久化、透传转发（头/body/query 全对）、502（upstream 未配）、413 路径已在 proxy.rs 预留
- clippy -D warnings 零告警

### 2026-09-23 · M3 规则引擎核心 ✅

- 交付 5 个模块（placeholder/validators/rules/session/engine）+ 2 个集成测试套件
- **120 个测试全绿**，`cargo clippy --all-targets -- -D warnings` 零告警
- 结构改为 lib + bin（`src/lib.rs` 导出模块），集成测试可 `use maskit_rs::*`
- 43 处环视（D7）逐处有等价性测试；内置规则链不引入回溯引擎（fancy-regex 仅用户自定义正则回退）
- 性能：600KB 文本脱敏 <2s（优化后实测约 0.5s）；重叠判定改二分、正则 use once_cell 静态复用

### 2026-09-23 · M2 协议识别 ✅

- `src/detect/mod.rs`：`Protocol` 枚举 + `detect_protocol(path, body)` + `is_stream_request`
- 优先级：Anthropic（anthropic_version 最强信号；其次 path/messages+system|max_tokens+首条 role 合法）> Responses（input 且无 messages）> ChatCompletions（messages 数组且无 input）> Unknown
- 12 个单测：三大协议正反形态、空数组/非数组 messages、非对象根、tool 循环消息、Gemini 形态归 Unknown、流式标记
- D6 职责边界在模块文档声明：detect 只选通道不 gate 脱敏；「Unknown + fail_closed 仍整棵脱敏」的端到端断言留待 M6 矩阵测试
- 无偏差


---

## 交付后审计：与 Python 版逐项比对（2026-09-23）

### 对齐无缺口的部分（已验证）
- **规则集**：`RULES` pattern 数 32 = Python 32；21 个 label 集合完全一致
- **协议识别**：三大协议端到端验证（chat_completions / responses / anthropic）
- **fail-closed 判定矩阵**：10 行逐行实现 + 端到端断言
- **流式还原**：SSE / NDJSON / 逐字节切分 / 跨 chunk 扣留 / 收尾补发
- **审计信号**：8 类被动信号全部移植（含分档与回声抑制）
- **事件库**：9 张表 schema 与 Python 一致，双向互读写测试通过
- **凭据红线**：原文不落 items、不落 SQLite、导出恒脱敏

### 本轮审计发现并已修复
| 严重度 | 问题 | 影响 | 状态 |
|--------|------|------|------|
| **P0** | `CommandBlockConfig::default()` 的 `patterns: []` 未播种内置规则 | **新装实例命令拦截一条规则都不跑，`rm -rf /` 完全不拦**（Python 开箱即用） | ✅ 已修 + 2 条回归测试（默认播种 7 条 / 显式清空被尊重）；`config.example.json` 同步为 7 条 |
| **P1** | 自定义词的 `sensitive_disabled` / `sensitive_word_disabled` / `sensitive_word_whole` 三级开关是**死代码** | 配置层无这三个键；引擎里 `disabled_labels`/`disabled_words`/`single_or_whole` 恒为空集 → 用户无法按分组/按词禁用、无法开整词匹配 | ✅ 已补齐配置模型 + 引擎接线 + 5 条新测试（含 CJK 整词开关不失效的边界） |

### 已知未实现（诚实登记，按优先级排序）

**A. 影响功能完整度，建议补做**
| # | 缺项 | Python 对应 | 说明 |
|---|------|------------|------|
| A1 | ~~主动探针未实现~~ | — | **用户决定：不需要，已彻底去除**（`audit.active_probes` 配置位、文档、PLAN 承诺一并移除） |
| A2 | **token 用量与费用统计未接** | `shield_defaults.extract_usage` + `daily_tokens` 表 | **本轮已实现 token 统计**（按用户要求：只统计数量，**不做价格计算**） |
| A3 | **egress_proxy 是空壳** | `parse_egress_proxy` + 转发走代理 | 配置项存在但 `http_client` 无任何 proxy 设置逻辑，填了不生效 |
| A4 | **统计维度不全** | `/api/stats/{highlights,models,today/restore-items}` | 只有 `today`（基础计数）与 `history`；缺按模型/词级高亮/还原明细聚合 |

**B. 诊断/可观测性字段缺失（不影响功能，影响排障）**
| # | 缺项 | 说明 |
|---|------|------|
| D1 | ~~自定义词三级开关~~ | **本轮已修复**（见上表 P1） |
| B1 | `scan_scope` / `roles` 归因 | Python 会记录「命中来自 system 还是 user」「扫描了多少消息」，Rust 未记录 → 日志里看不出命中位置 |
| B2 | `short_hits` | 过短词误伤提示 |
| B3 | `usage` 事件字段 | 流末 usage 采集（依赖 A2） |

**C. 有意剔除（PLAN §11 已声明，不算漏做）**
`/api/ext/*` 扩展桥接 6 个端点、`/api/cert` CA 证书、`/api/autostart` 开机自启、`/api/open-data-dir`/`open-url` 桌面相关、`/api/diagnostics*` 桌面诊断、`/api/auto_recover/*` 代理看门狗（单进程无 mitmproxy 子进程，不需要）、`/api/config/{backups,restore,builtin_rules,disable_origin_check}`（配置备份/回滚；Rust 已用原子写盘+历史留存在 config.json）、`/api/restore`（桌面手动还原入口）、`/api/proxy/{start,stop}`（单进程常驻，等价于 pause/resume）

**D. 语义映射说明（不是漏做，是设计替换）**
- Python `filter_enabled` → Rust `mask.enabled` + `paused`
- Python `stop_mode`（passthrough/block/error）→ Rust `fail_closed`（三档判定矩阵，见 PLAN §2.2）
- Python `sensitive_disabled` / `sensitive_word_disabled` / `sensitive_word_whole` → **本轮已补齐**（此前 Rust 未实现）
- Python `origin_check` 开关 → Rust 恒定开启 Origin 校验（更安全，但不可关）


---

## 2026-09-24 用户决策后的调整

用户对审计遗留项做出决策，三项均已落实：

### 1. egress_proxy 说明（待用户决定是否实现）
出口代理 = **Maskit → 上游这一跳走 HTTP 代理**。典型场景：已有 Clash/v2ray，但不想给 Cursor/Claude Code/Codex 每个客户端分别配代理，在网关配一次即可。Python 版还支持按上游区分（境内中转直连 + 境外官方 API 走代理）。

Rust 版现状：配置字段存在但 **HTTP 客户端未使用，填了不生效**（空壳）。实现成本低（hyper client 接 proxy connector），建议后续补齐或直接从配置里摘掉，避免「配置项说谎」。

### 2. 主动探针：已彻底去除
- 删除 `AuditConfig::active_probes` 字段与默认值
- `config.example.json`、`README.md` 同步移除
- 审计保持**纯被动**（8 类信号），无主动探测/报告生成

### 3. token 用量统计：已实现（无价格计算）
- 新增 `store/usage.rs`：提取器覆盖 OpenAI 非流式 / Anthropic / Responses / Cohere / SSE 分片累计（9 个单测）
- 响应管线接入：整包响应在 `process_whole` 提取；流式在 `stream.push` 逐块采集（流末 usage 不受文本留存上限影响）
- 落库：`daily_tokens` 表按 `(day, model)` 累加（此前**建了表从未写入**）；同步写 `daily_stats` 便于一行读出
- API：`/api/stats/today` 新增 `tokens_prompt/completion/total`；新增 `/api/stats/models`（按模型 token 降序）
- 启动时安装 usage 落库钩子（`OnceLock`），响应模块不感知 SQLite
- **价格/费用逻辑：Rust 侧从未实现，无需删除**；已加测试锁定「配置与统计接口不得出现 price/cost 字段」

**端到端验证**：mock 上游固定回 `usage:{prompt:123, completion:45}`，打 2 次请求 → `/api/stats/today` 返回 246/90，`daily_tokens` 表落 `(gpt-4o, 246, 90)`。

### 同期完成的审计修复（上一轮）
- **P0** 默认配置未播种内置命令规则 → 新装实例 `rm -rf /` 完全不拦（已修 + 2 回归测试）
- **P1** 自定义词的分组禁用/词级禁用/整词匹配是死代码（已补齐配置模型 + 引擎接线 + 5 测试）

**当前状态**：275 个 debug 测试 + 10 个 release 性能测试全绿，clippy 零告警。


---

## 2026-09-24 egress_proxy 移除 + 最终 review

### 1. egress_proxy 已彻底移除（用户决策：不需要）
- 删除 `EgressProxy` 结构体、`UpstreamConfig.egress_proxy` 字段与默认值
- `config.example.json` 同步移除；`upstream/http_client.rs` 模块注释同步修正
- 编译零残留；**不再存在「配置项存在但填了不生效」的误导**

### 2. 最终 review：安全/正确性重点审查

**发现并修复的严重问题**

| 级别 | 问题 | 影响 | 状态 |
|------|------|------|------|
| **P0 内存泄漏** | 流式路径从不 `drop_session`，且 `inflight=true` 让 `sweep` **永久跳过**该会话 | **长会话（每轮 stream:true）的 sessions 表无界增长 —— 永久内存泄漏**，非「延迟回收」 | ✅ 用 `SessionGuard`（Drop 守卫）修复：**正常结束 / 客户端断连 / body 被丢弃 / panic 任何退出路径都释放**；`inflight` 先复位再 drop；加回归测试（10 次流式后会话数 ≤1） |

**加固（防御纵深）**

| 项 | 处理 |
|----|------|
| `cmd_pend` 通道数无界 | 加 `MAX_PEND_CHANNELS=256` 上限：恶意/异常流可造无界 channel 名（每条 ≤64B 但条目数无界）。超上限时该段直接下发（宁可不拦这一条，也不撑爆内存） |

**审查过、确认无问题的项**
- 凭据红线：items/SQLite 落盘前双重清洗；无请求/响应体整体打日志
- 响应体上限 64MB（`aggregate_stream` 超限报错）
- SSE 半事件缓冲上限 4MB（`_SSE_BUF_MAX`）
- 响应侧留存文本上限 256KB（仅供审计，不影响流式输出）
- 事件库按 `log_retention_days` 定期清理
- 请求体上限 32MiB（超限 413，不看 fail_closed）
- 自定义词热更新：`RwLock<Arc<CustomWords>>` 整体替换，读侧拿 Arc 快照，无半更新状态
- 配置热更新：整份替换 + 原子镜像 + 原子写盘（tmp+rename）

**已知非缺陷的限制（如实登记）**
- 事件库只有时间维度保留期，无条数上限：高频长期运行会增长（与 Python 版一致）
- 事件/审计的内存 ring 各 2000/1000 条：超出丢最老（设计如此）
- 性能绝对值受本容器 0.6 核 CPU 配额限制，PLAN 的 50ms 目标需多核机器复核（相对提升 33-42x 已达标）

**最终状态**：276 个 debug 测试 + 10 个 release 性能测试全绿，clippy 零告警，9.4MB 单二进制。


---

## 2026-09-24 交付物补充：CI / Docker / 思考内容核查

### 1. GitHub Actions（`.github/workflows/release.yml`）
- **4 个 job**：`version`（版本号生成）→ `verify`（fmt+clippy+测试+性能门禁）→ `release`（4 平台构建）→ `docker`（GHCR 多架构推送）
- **平台矩阵**：`linux-x86_64` / `linux-aarch64`（交叉编译，装 gcc-aarch64-linux-gnu）/ `windows-x86_64` / `windows-aarch64`（MSVC）
- **版本号自动生成**（用户要求「不要每次都 latest」）：
  - 推 `v*` tag → 用 tag 名
  - 手动触发且填了版本 → 规范化补 `v` 前缀，标记 prerelease
  - 手动触发未填 → 自动生成 `v0.1.0-dev.{run号}.{UTC时间戳}`，**每次发布唯一**
- Release 资产名带版本号；GHCR 额外打 `latest` + `sha` 浮动 tag
- 质量门禁挂在 build 之前：fmt / clippy `-D warnings` / 全量测试 / 性能基准，不过不发布

**踩坑记录**：CI 打包最初写 `tar -C dist -czf dist/x.tar.gz dist/*` —— glob 在 `-C` 生效前就被 shell 展开，路径指向 `dist/dist`（本地实测复现）。改为「暂存目录 + `tar -czf dist/x.tar.gz $STAGE`」。Windows 分支改用 PowerShell `Compress-Archive`（runner 不保证有 zip 命令），与 Linux tar.gz 互斥执行。

### 2. Docker（`Dockerfile` + `docker-compose.yml` + `.dockerignore`）
- **体积控制**：多阶段构建 + 依赖单独分层（改业务代码不重编依赖）+ `distroless/cc-debian12:nonroot` 运行时（无 shell/无包管理器）+ 只拷贝二进制 + `strip`
- SQLite 静态链接进二进制，镜像无需 `libsqlite3`
- 新增 `--health-check` 参数（distroless 无 curl/wget，用 Rust 手写最小 HTTP GET），供 HEALTHCHECK 使用；已实测：服务未运行退出 1、运行中退出 0
- 另加 `--version` / `--help`
- compose 配好端口/持久化卷/日志轮转/CPU 内存上限
- **注**：本机 docker daemon 不可用，Dockerfile 未经真实构建验证（已在 CI 首次运行时验证）

### 3. 思考内容与工具调用脱敏核查（用户提问 → 发现并修复真实缺口）

**核查结论**：请求侧（mask_tree）与响应侧（流式槽位 + 整树还原）都覆盖了工具参数与思考内容，但**流式槽位漏了一个字段**：

| 协议 | 思考字段 | 工具参数字段 | 状态 |
|------|---------|-------------|------|
| Chat Completions | `delta.reasoning_content`、`delta.reasoning` | `delta.tool_calls[].function.arguments`（转义还原）、`function_call.arguments` | ✅ |
| Responses | `response.reasoning_text.delta`、**`response.reasoning_summary_text.delta`（OpenAI 官方）** | `response.function_call_arguments.delta`（转义还原） | ❌→✅ **本轮修复** |
| Anthropic | `content_block_delta.delta.thinking` | `delta.partial_json`（转义还原） | ✅ |

**修复**：`reasoning_summary_text.delta` 曾返回 **0 槽位** → 该段思考内容不还原，占位符原样下发客户端。已补识别 + 配套 `.done` 收尾通道，并加「三大协议思考+工具槽位全覆盖」测试防回归。

**顺带发现两个测试自身的问题（都已修）**：
1. 测试 mock 的 `windows(9)` 与 8 字节字面量 `"stream"` 比较 → **永假**，SSE 分支从未被执行 → 多个 SSE 相关测试其实是**空跑**。修正为 `windows(8)` 后立刻暴露出下面第 2 点。
2. 由上一条暴露：**会话释放守卫被我建在了 `stream_response()` 的局部作用域**，函数 return 即 drop → 会话在客户端读 body 前就消失 → **流式还原全部失效**（占位符原样下发）。已把守卫移入 `async_stream` 生成器内部（覆盖「消费完/断连/被丢弃」三种结束），并新增从完整代理路径验证的回归测试。

这正是「先修 mock、再验证」的价值：两个问题互相遮蔽，只靠单测全绿会漏掉。


## M13：占位符映射持久化（两级缓存）

**背景**：随机后缀（防上游枚举反推，安全红线）意味着映射是**有状态**的。
原先映射只在内存，进程重启后 AI 复述历史 `{{PHONE_xxx}}` 还原不回来。

**设计**（经多轮讨论定稿）：

```
mask 替换 ──► 内存 recent_fwd/rev（热缓存，LRU 10000 条 + TTL 24h）
                    │ 命中 → 返回（µs，零磁盘 I/O）
                    │ 未命中（LRU 淘汰 / TTL 过期）
                    ▼
             SQLite placeholder_map（真相，TTL 24h）
                    │ 命中 → 回填内存 → 返回原占位符
                    │ 未命中 → 生成新随机后缀 → 异步入队落盘
```

关键点：
- **同一敏感值占位符恒定**（24h 内），保证上游请求前缀稳定 → prompt cache 不失效
- 落盘走 `EventStore` 已有**单写线程队列**（`try_send` 非阻塞，队列满则丢并计数）
- 凭据类**同样落盘**（用户决策：行为一致优先），DB 文件权限 0600

**改动**：
- `StoreMsg::Mappings` / `PruneMappings` 变体 + 写线程处理
- `EventStore::save_mappings`（入队）/ `lookup_mapping`（同步只读）/ `prune_mappings`（入队）
- `SessionStore::set_lookup_hook` + `recall_token` 内存未命中时回查 DB 并回填
- `pending_persist`: `Vec<(String,String)>` → `HashSet<String>`（O(1) 去重 + 杜绝泄漏）
- `RECENT_MAX` 2000 → 10000；内存 TTL 全局 24h（`set_ttl` 恢复 `max(24h, x)` 语义）
- `config.mask.mapping_ttl` 默认 86400s
- 回放 `warmup_from_events` 移除凭据类过滤
- SQLite 文件 0600

**测试**（+13）：内存未命中回查 DB、回填、淘汰后占位符恒定、DB 未命中生成新值、
pending drain 不泄漏、10050 条 LRU 淘汰、落盘往返/幂等 upsert/TTL 清理/文件权限。


## M14：取消 panel_token 长度限制

`normalized()` 曾强制 `panel_token.len() >= 16`，否则**静默清空**并回退随机
24 位令牌。该函数同时被启动加载（`load_or_init`）和控制台保存（`update`）
调用 —— 于是用户设的固定短令牌会「保存成功但没生效」，且每次重启/保存都变。

改为：不做长度限制，非空令牌原样生效（顺带 trim，避免复制粘贴带入空白）。
空 / 纯空白仍走自动生成 24 位随机值 —— 那是「没设令牌」的安全兜底，必须保留。

同步移除 `validate()` 里「少于 16 位」的告警，并更新 README / PLAN 描述。
测试 +2：短令牌（1/3/4/16 位）与超长（512 位）原样保留且可持久化；
纯空白 trim 为空。


## M15：修复 store 测试的落盘竞态（CI 间歇性失败）

**现象**：CI 上 `store::db::tests` 5 个用例间歇失败，报 `left: 0, right: 2`。
同样 700ms sleep 的另外 3 个用例却通过 —— 是竞态不是逻辑错误。

**根因**：写线程「满批(100)或 500ms 超时」才落盘，事件入队后最多等 500ms。
测试写死 `sleep(700ms)` 硬等，**余量仅 200ms**。CI runner 满载时写线程被
调度延迟 >200ms，断言时一条都还没落盘（所以是 0，不是部分）。

这批测试来自最初的重写提交 `3719525`，与映射持久化改动无关；但本机提交
`mapping_save_is_idempotent_upsert` 时已暴露同一模式（400ms < 500ms 直接失败），
当时只改了新测试、没回头治老测试，是疏漏。

**修复**：给 `EventStore` 加确定性屏障 `sync()`，而不是把 sleep 加长
（加长既慢又不可靠）。

1. `StoreMsg::Flush(Sender<()>)` —— 与写线程共用有序队列，屏障被处理时
   其前的消息必然已在同一批次内处理完毕
2. **回执必须等 `tx.commit()` 之后再发**。第一版写在事务循环内（commit 之前），
   调用方收到回执就去读库，事务尚未提交 —— 反而稳定失败，本地立刻复现
3. 屏障消息**立即触发落盘**，不等批量/超时阈值，否则 sync() 要白等一拍
4. commit 失败也要回执，否则写线程故障时 sync() 白等满 5s
5. 11 处固定 sleep（db.rs 9 + store_interop 2）全部换成 `store.sync()`

**收益**：
- 消除竞态：满载 6 个 spin 进程下连续 8 轮全过
- lib 测试 12~41s → **4s**（省掉 11×700ms 硬等）
- 顺带修正 `prune_removes_old_events`：`prune()` 本身也是异步入队，
  原来第二个 sleep 是对的但同样脆弱


## M16：自定义敏感词录入改造（批量 + 分组 + 修 `.` bug）

**问题**（用户提出「一个分类不能有多个敏感词吗？」）：

1. UI 一次只能加一个词，加 N 个词要把分类重填 N 遍
2. 展示是一排平铺 chip，看不出分组
3. **真 bug**：新增走 `path: 'mask.custom_words.' + 词`，而服务端按 `.` 切分
   JSON Pointer。词含 `.`（`example.com`、`Dr. Smith`）会被切成多段，写成
   `custom_words → example → com` 的**嵌套结构** —— 值类型从 string 变
   object，匹配逻辑错乱

**后端模型无需改动**：`custom_words: BTreeMap<词, 分类>` 原生支持一个分类下
多个词（与 Python 版一致）。问题全在 UI 与 patch 契约。

**改动**：

- `ConfigCenter::patch_segs(&[String], value)`：按路径段数组打补丁，不做任何
  分隔符切分，键原样写入。`patch(path,…)` 保留为薄包装（向后兼容）
- `PatchBody` 新增 `segs` 字段，与 `path` 二选一（`segs` 优先）
- `value: null` 表示**删除该键**（而非写入 null 导致反序列化失败）——
  删除也能一次原子 patch 完成，不必读整表再回写（消除读-改-写竞态）
- UI：分类改 `datalist` 补全（复用已有分类）；敏感词改 textarea，
  支持换行/逗号/顿号/分号/空白分隔，一次加多个；整表一次 patch
- UI：chips 按分类分组渲染，组头同时显示实际占位符前缀
- UI：输入分类时若含非 ASCII 字符，实时提示会被剔除（如 人名 → TERM）

**测试** +8：含 `.` / `/` / `~` 的词保持扁平；`null` 删除精确且幂等；
一次 patch 批量写入；一个分类多词；空路径拒绝。e2e 验证
`example.com` / `Dr. Smith` / `ACME/Inc` 脱敏→还原往返正确。

测试 303 全绿，clippy 零告警。


## M17：日志/审计列表重做（修「不显示内容」）

**现象**：用户反馈日志、审计列表都不显示内容，样式很奇怪。

**诊断**：数据层完全正常（/logs、/audit/events 实测均返回完整数据）。
四个缺陷全在渲染层：

1. **两张表都是空壳** —— `<table id=logList>` / `<table id=auditList>`
   内没有任何 thead/tbody，JS 直接往 table 里塞 `<tr><td>`。日志 7 列、
   审计 5 列全无表头，CSS 里 `th{position:sticky}` 写了却从未渲染 ——
   用户看到的是一堆无法解读的单元格。
2. **原文与占位符都没显示** —— JS 只取 `it.preview`（打码预览
   `1*********0`），且**字段名用错**：后端 `EventItem.token` 带
   `#[serde(rename = "tok")]`，序列化成 `tok`，JS 从未读取；`original`
   又被 `preview || original` 短路掉。两个关键值一个都没露出。
3. **统计字段全是死的** —— JS 引用 `e.unresolved` 但它是
   `skip_serializing_if=is_zero`；而 `count`/`restored` 压根没渲染。
4. **详情端点闲置** —— `/logs/detail` 已实现，JS 从不调用。

**参照 Python 实现**（`frontend/src/components/events/EventDetailDialog.tsx`）：
列表精简，item 对照明文 / 预览 / 占位符 / 摘要 四行，详情回源单条事件。

**改动**：

- 两张表补 `<thead>` 列名 + 渲染目标改 `<tbody>`（空态 colspan 对齐列数）
- item 渲染为「原文 → 占位符」对照，用 `tok`（兼容 `token`）；
  凭据类 original 恒空（红线），显式标注「不存明文」+ sha256 摘要
- 补齐 count / restored / unresolved / degraded 统计徽标
- 接上 status / stream_mode vs stream_actual / req_bytes / unknown_shape 徽标
- 点行展开详情（回源 `/logs/detail?id=`），渲染对照表 + message +
  unresolved_samples
- 审计表补表头，严重度改彩色徽标，证据列可断行
- CSS 重做：粘性表头、列宽分层、行悬浮/选中态、对照视觉层次

**测试** +2（表头齐全且列名匹配、渲染读 tok 且不被 preview 短路、统计字段
真的被渲染、详情回源）。305 全绿，clippy 零告警。

**遗留**：`Event.dialog` 字段声明了但从未赋值（永远空串），详情里的
「用户消息原文 / 助手回复原文」因此不显示。接上它意味着把**含明文凭据的
完整请求体驻留内存**（ring 2000 条），与凭据红线有冲突，需先决策。
