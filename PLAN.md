# Maskit-RS：Rust 重构详细设计方案

> 版本：v1.1（2026-09-23 修订）
> 状态：设计定稿（v1.1 修复评审 P0），进入实施
> 源项目：`/config/Desktop/maskit`（Python：panel.py ~7600 行 + transparent.py ~7600 行 + event_store.py ~2700 行 + audit*.py ~2900 行）
> v1.1 修订：D6（fail-closed 语义对齐 Python）+ D7（零宽环视断言移植策略），详见 §12 修订记录

---

## 0. 决策记录（已与用户确认）

| # | 决策项 | 结论 |
|---|--------|------|
| D1 | 重构范围 | **全功能对齐**：脱敏/还原、单上游反代、三大协议识别、事件日志与统计看板、被动审计信号引擎、危险命令拦截。**去除**：桌面端（Tauri）、浏览器扩展桥接、NER（模型文件本就缺失、默认关闭）、mitmproxy/透明代理模式、系统代理托管、hosts 管理 |
| D2 | Web 界面 | **内嵌精简新 UI**：Rust 二进制内嵌静态页面（rust-embed），不依赖 Node 构建，保留 Dashboard / 规则 / 日志 / 审计 / 设置 5 页 |
| D3 | 失败策略 | **混合策略**：非三大协议内容直接透传；已识别协议但脱敏过程异常时返回 503 拒绝放行。**v1.1 修订：透传范围以 D6 为准——「非三大协议一律透传」已废止** |
| D4 | 端口模型 | **单端口单上游**：Web UI / 管理 API / LLM 反代共用一个端口；上游只有一个，任何协议都转发到它 |
| D5 | 进度管理 | `PLAN.md`（本文件）+ `PROGRESS.md`（进度台账）落地在 `maskit-rs/`，每完成一个里程碑即时更新 |
| **D6** | **fail-closed 语义**（v1.1 新增，取代 D3 中「非三大协议一律透传」） | **与 Python 版逐条对齐**：是否脱敏只由「是否落在已配置上游路由 + `fail_closed` + body 能否解析」决定，**与协议识别结果无关**。已路由 + `fail_closed=true`：非 JSON → 503；JSON 解析失败 → 400；body > 32MiB → 413；形态未知（含非对象根）→ 整棵脱敏并记 `unknown_shape`。仅当 `fail_closed=false` 或脱敏暂停（pause）时才透传，并记 `BYPASS` 事件。详见 §2.2 判定矩阵 |
| **D7** | **零宽环视断言移植策略**（v1.1 新增） | `RULES` 含 **43 处零宽环视**（19×`(?<!`、21×`(?!`、3×`(?=`），`regex` crate 不支持且 `fancy-regex` 会引入回溯。**内置规则一律不引入回溯引擎**：环视下沉为「零宽断言校验器」（`BoundaryCheck`），与既有 `_card_ok/_idcard_ok/...` 同层，**匹配区间与 `value_group` 语义逐字节不变**。用户自定义正则例外：`regex` 编译失败才回退 `fancy-regex`，强制单规则预算熔断。详见 §4.4 |

---

## 1. 现状分析与性能瓶颈（重构依据）

### 1.1 Python 版架构

```
客户端(Cursor/Claude Code/…)          上游(OpenAI/Anthropic/中转站)
        │ 多端口反代 18701~18799                ▲
        ▼                                      │ HTTPS
┌──────────────────┐  spawn 子进程   ┌──────────┴─────────┐
│ panel.py (Flask)  │ ──────────────▶ │ mitmdump +          │
│ 5801 Web面板      │                 │ transparent.py       │
│ fallback 直连兜底 │                 │ (mitmproxy addon)    │
└──────────────────┘                 └────────────────────┘
```

### 1.2 实测瓶颈（源码注释自证）

| 瓶颈 | 证据（transparent.py 注释） | 影响 |
|------|------------------------------|------|
| 单线程 event loop 同步脱敏 | "256KB 请求体：命中 11037 次…替换环节 930ms；512KB 达 3696ms。mitmproxy addon 跑在 asyncio event loop 上同步执行，这几秒会**冻结全部 upstream 端口的所有连接，包括进行中的 SSE 流**" | CPU 跑满 → 全局卡死、打字机卡顿 |
| Python re 回溯退化 | 多条规则注释记录 O(N²) 回溯修复史（`\\*`→`\\{0,3}` 等） | 恶意/极端输入放大 CPU |
| 规则逐条全文扫描 | 21 条正则顺序 finditer，仅靠 `_rule_may_hit` 特征预筛 | 大 body 成本 = 规则数 × 文本长 |
| 多进程模型 | Flask(threaded) + mitmdump 子进程 + fallback http.server | GIL 争用、内存 ×3、启动慢 |
| 事件库写队列 | queue.Queue(5000) + 单写线程 sqlite | 高流量积压 |

### 1.3 Rust 版性能设计对策

| 对策 | 实现 |
|------|------|
| 线性时间正则（内置规则） | `regex` crate（RE2 语义，天然无灾难回溯）+ `aho-corasick` 多模式单趟预筛（自动机一次扫描判断哪些规则可能命中）。**43 处零宽环视断言下沉为校验器（D7/§4.4），内置规则链内不出现回溯引擎** |
| 用户正则的隔离 | 一级用 `regex`；仅当编译失败（含环视/反向引用）才回退 `fancy-regex`，且该规则单独施加墙钟预算（默认 100ms/次）+ 超限自动停用并告警（§4.2、§4.4）。回溯风险被限制在「用户自己填的表达式」内，不污染内置规则链，因此 §1.3 的线性时间承诺依然成立 |
| CPU/IO 分离 | tokio 异步 IO 主线程绝不做脱敏；请求/响应体改写放 `spawn_blocking`（rayon 池），池大小 = 核数，大 body 并行不阻塞 SSE 转发 |
| 零拷贝流式 | SSE/NDJSON 逐事件 `BytesMut` 增量处理，还原映射查 `HashMap` O(1)；占位符跨 chunk 缓冲与 Python 版 `_PARTIAL_RX` 逻辑等价 |
| 并发模型 | 每连接一个 tokio task；会话映射表 `DashMap`，事件写入 `crossbeam-channel` + 专用写线程（WAL 模式 sqlite，批量事务） |
| 单二进制 | axum + rust-embed 内嵌 UI，无 Python 运行时，冷启动 <100ms，常驻内存目标 <50MB |

**验收基线**（迁移测试中量化）：
- 512KB 请求体脱敏 P99 < 50ms（Python 实测 3696ms）
- 单条 SSE 事件处理 < 1ms，并发 100 路 SSE 转发 CPU < 20%
- 空载内存 < 50MB

---

## 2. 总体架构

### 2.1 部署形态（单端口单上游）

```
                    ┌─ http://127.0.0.1:18701 ─────────────────────┐
客户端 ──▶           │  /            → 内嵌 Web UI (rust-embed)      │
(Cursor/Claude      │  /api/*       → 管理 API（配置/日志/审计/统计）│
 Code/任何工具)      │  其余所有路径  → LLM 反代管线                   │──▶ 唯一上游
                    │    (按请求体识别协议)                          │   (可配中转站)
                    └───────────────────────────────────────────────┘
```

- 客户端 `base_url` 只需指向 `http://127.0.0.1:<port>`（可带任意路径前缀，原样拼接转发）。
- Web UI 与 `/api/*` 占用保留前缀；若上游路径恰好冲突，通过 `config.server.web_prefix` 可改（默认 `/` 端口根、`/api`），计划中默认 UI 挂在 `/console`，避免与常见 `/v1`、`/api` 类上游路径冲突：**最终定稿：UI 挂 `/console`，管理 API 挂 `/console/api/*`，其余路径全部进反代管线**。
- 端口默认 `18701`（沿用 Python 版习惯），`config.server.port` 可改。

### 2.2 请求管线（核心状态机）

> **v1.1 按 D6 重写。** 总原则：是否脱敏只由三个事实决定 —— **请求是否落在已配置的上游路由上**、**`fail_closed`**、**body 能否被解析**。
> `detect_protocol` 只决定「用哪套解析/还原通道 + 哪套路径感知豁免表」，**不决定是否脱敏**。
> 这与 Python 版一致：`transparent.py` 对「已路由 + fail_closed」的未知形态一律整棵脱敏（`unknown_shape` 分支），
> `SECURITY.md`「fail-closed 设计」把「绝不放行未脱敏原文上行」写成公开承诺。

```
收到请求
  │
  ├─ ① 路由判定：未命中已配置上游 → 404 no_reverse_route
  │
  ├─ ② 只读方法 GET/HEAD/OPTIONS → 纯转发（记 PASS，reason=readonly_method）
  │      ※ 与 Python `_READONLY_METHODS` 一致，**不含 DELETE**（DELETE 可带 body，须走下面管线）
  │
  ├─ ③ 脱敏暂停（pause / filter_enabled=false）→ 纯转发（记 BYPASS，reason=filter_disabled）
  │      ※ 暂停语义完整：此时不再做任何 fail-closed 阻断，否则「关了脱敏还 503」等于没关
  │
  ├─ ④ 读 body（上限 max_body_bytes=32MiB，超限一律 413，不看 fail_closed 与协议形态）
  │
  ├─ ⑤ Content-Type 声明非 JSON（multipart/二进制/表单…）
  │      ├─ fail_closed=true  → 503 non_json_body（无法确认其中无原文）
  │      └─ fail_closed=false → 转发（记 BYPASS，reason=non_json_body）
  │
  ├─ ⑥ JSON 解析（保序 + 重复键检测）
  │      ├─ 解析失败 + fail_closed=true  → 400 invalid_json（注意是 400，不是 503）
  │      ├─ 解析失败 + fail_closed=false → 转发（记 BYPASS，reason=invalid_json）
  │      └─ 解析成功 → ⑦
  │
  ├─ ⑦ 协议探测 detect_protocol(body, path)（**仅选择脱敏/还原通道**）
  │      ├─ ChatCompletions / Responses / Anthropic → 协议感知脱敏
  │      └─ Unknown（含非对象根、非白名单路径）
  │            ├─ fail_closed=true  → 整棵脱敏（事件标 unknown_shape=true；豁免表退化为「无协议容器」模式）
  │            └─ fail_closed=false → 转发（记 BYPASS，reason=non_llm_json）
  │
  └─ 脱敏管线（spawn_blocking）——以下与协议识别结果无关，只与「走哪套豁免表」有关
        ├─ 非对象根（list/str/number）：包合成根键 → 脱敏 → 拆包（Python `_ROOT_WRAP_KEY` 等价）
        ├─ _mask_tree 等价物：路径感知递归脱敏（协议位置豁免表照搬 Python；Unknown 形态下协议容器判据恒假）
        ├─ 规则引擎：aho-corasick 预筛 → 逐启用规则 regex 替换 + 零宽断言校验器（§4.4）
        │   （校验器：Luhn/身份证 mod11-18/15、Email、IBAN mod97、JWT 三段
        │     header 校验、连接串密码组、+86 手机号、座机、车牌、HKID、USCC、
        │     IPv4/IPv6 私有公网、MAC、PEM 整块、SECRET 键值对、前缀规则 sk-…）
        ├─ 自定义词表：aho-corasick 单趟替换（长词优先语义由自动机保证）
        ├─ 会话登记：orig → {{LABEL_suffix}} 映射（TTL 复用，多轮一致性）
        ├─ 键名脱敏（结构键白名单外一律扫描）
        ├─ 命令拦截：请求体文本窗口扫描（`_SCAN_BODY_MAX` 等价 512KiB，**Unknown 形态同样扫描**）
        └─ 重序列化 → 转发上游
              │ 脱敏过程异常（深度超限 / 内部错误 / 捕获到的 panic）→ 503 fail-closed（与协议无关）
              ▼
        上游响应
        │
        ├─ Content-Type: text/event-stream → SSE 流式管线（见 2.3）
        ├─ application/x-ndjson → NDJSON 逐行还原
        ├─ application/json → 整包 JSON 树还原
        └─ 其他 → 原样透传
              │
              ├─ 被动审计信号扫描（error_leak / identity_swap /
              │   tool_call_rewrite / sse_anomaly / response_poison /
              │   cross_request_pollution / credential_echo / dangerous_action）
              ├─ 响应侧 PII 扫描（模型幻觉泄漏，只告警不改写）
              └─ 命令拦截（observe/rewrite/block 三模式，tool 通道）
```

**fail-closed 判定矩阵（D6；与 Python 版逐条对照，即 M6 的验收清单）**

| 场景 | `fail_closed=true`（默认） | `fail_closed=false` | Python 对照 |
|------|---------------------------|---------------------|-------------|
| 未命中已配置上游路由 | 404 `no_reverse_route` | 同左（路由失败与策略无关） | reverse 路由分支 |
| GET / HEAD / OPTIONS | 转发 + PASS | 同左 | `_READONLY_METHODS` |
| 脱敏暂停 | 转发 + BYPASS | 同左 | `filter_disabled` |
| body 超 32MiB | **413** | 413（不看 fail_closed） | `request_too_large` |
| 声明非 JSON | **503** `non_json_body` | 转发 + BYPASS | `non_json_body` |
| JSON 解析失败 | **400** `invalid_json` | 转发 + BYPASS | `invalid_json` |
| 顶层非对象（数组/标量） | **整棵脱敏**（包装后） | 转发 + BYPASS | 非对象根分支 |
| 已路由的未知形态 JSON | **整棵脱敏** + 事件 `unknown_shape` | 转发 + BYPASS | `unknown_shape` |
| 协议已识别、脱敏抛异常 | **503** | 503 | 主管线异常 |
| 路径不在 `paths` 白名单 | 不改变「是否脱敏」，只改变「脱敏模式」（→ 走 unknown_shape 全树） | 转发 + BYPASS | `_upstream_path_ok` 之后的 fail_closed 分支 |

> 事件侧：`unknown_shape` / `non_json_body` / `invalid_json` / `request_too_large` 各自独立 reason 入库，
> 便于在日志页区分「用户主动关掉了 fail_closed」与「确实没有原文」。

### 2.3 SSE 流式还原管线（对齐 Python `_sse_stream_factory`）

- 事件按 `\n\n` 分帧（兼容 CRLF→LF 归一）；半事件缓冲，缓冲超限（`_SSE_BUF_MAX` 等价 512KB）强制按最后换行切分。
- 占位符跨 chunk：每 delta 通道（`content`/`reasoning_content`/`tool arguments`/`partial_json`/Responses 各通道）独立 pending 缓冲，`_PARTIAL_RX` 等价规则扣留半截占位符（上限 48 字节），流末 `_flush_pending` 补发。
- JSON 字符串内原文按 JSON 转义还原（`escape=true` 路径，等价 Python restore escape 参数）。
- `data: [DONE]`、Anthropic `event:` 行、usage 尾帧全部原样保留；只重写 delta 文本字段。
- 中途块无输出时保持连接打开（绝不下发空 chunk 终止块——Python 版实测踩坑，注释已记录）。

### 2.4 会话与多轮一致性

- 会话键：`SHA-256(client_ip + first_user_content_hash)` 前 16 hex（Python 版用 uuid4 不可复现，改为确定性键以支持多轮复用命中；若同 body 哈希冲突场景，退化为每请求新会话也不影响正确性，只影响复用率）。
- 映射表：`DashMap<sid, Session>`；`Session { fwd: HashMap<orig,token>, rev, labels, pending, ttl }`。
- 跨请求复用表：全局 LRU（容量 100k，TTL 600s 默认）+ 自定义词永久映射；语义与 Python `_RECENT_FWD/_RECENT_REV/_CUSTOM_WORD_*` 一致。
- 凭据类标签（API_KEY/TOKEN/SECRET/ACCESS_KEY/JWT/CONNSTR/PRIVATE_KEY）：原文**永不落库**，只记 preview + sha256 摘要 + 长度（`CREDENTIAL_LABELS` 等价）。
- 占位符后缀：6 位纯辅音字母表 `bcdfghjkmnpqrstvwxz`（新）+ hex6 兼容（旧），还原正则接受两种。

---

## 3. 协议识别规则（D2 核心新增）

```
detect_protocol(method, path, body_json) -> Protocol
```

优先级（自上而下，首个命中即返回）：

| 协议 | 判据 |
|------|------|
| **Anthropic** | path 含 `/messages` 且 body 含 `messages` 数组且（`system` 或 `max_tokens` 存在）且首条 message.role ∈ {user,assistant}；或 body 含 `anthropic_version` |
| **Responses** | body 顶层含 `input`（string 或数组）且不含 `messages`；或 path 含 `/responses` |
| **ChatCompletions** | body 顶层含 `messages` 数组（元素含 role/content）且不含 `input`；或 path 匹配 `chat/completions` / `completions` |
| Unknown | 其余全部 |

- path 仅作辅助信号，body 形态是主判据（中转站 path 千奇百怪，但 body 形态稳定）。
- `stream: true` 时响应按 SSE 处理；`stream` 缺省按非流式。
- **职责边界（D6，v1.1 修订）**：`detect_protocol` 只决定「用哪套脱敏/还原通道 + 哪套路径感知豁免表」，**不决定是否脱敏**。Unknown 形态在 `fail_closed=true` 时走**整棵脱敏**（豁免表退化为「无协议容器」模式），在 `fail_closed=false` 时才透传；命令拦截的文本窗口扫描对 Unknown 形态同样生效（Python 版在请求体上按 `_SCAN_BODY_MAX` 文本窗口扫描，与形态识别无关）。

---

## 4. 脱敏规则引擎

### 4.1 内置规则（21 类，对齐 `shield_defaults.DEFAULT_BUILTIN_RULES`）

默认开启 7 类：`API_KEY, CARD, CONNSTR, EMAIL, IDCARD, LANDLINE, PHONE`；其余默认关闭可开。每条规则的 regex/校验器从 `transparent.py` RULES 表**逐一移植**，包括：
- 全部边界断言（`ID_BOUND_L/R`、IP 专用边界、公网 IP 强防误伤定宽断言）→ 按 §4.4 的 D7 方案下沉为零宽断言校验器，**逐条附等价性测试**
- 连接串 scheme 封顶 `{0,63}`（防 O(N²)）、EMAIL 中文本地部分、CONNSTR 排在 EMAIL 前的豁免区间机制
- 秘密键值对规则的中英文关键词 + 全半角分隔符 + 值字符类（排除 `{}`/`.`/`/`）
- 数值形态标量脱敏（`{"phone": 13800138000}` → 占位符字符串）

Rust 侧用 `aho-corasick` 对每条规则建立「必含特征串」预筛（等价 `_rule_may_hit`），未命中特征直接跳过该规则。两个硬约束：
- 特征串必须由规则定义**自动派生**，**不得手工维护第二张表**——环视下沉后规则文本形态已变，手工表必然漂移；派生结果须与 Python `_RULE_MARKERS` 做集合等价断言。
- `_RULE_MARKERS_CI` 的「比对前统一小写」语义须与 AC 的大小写折叠模式锁定一致（Python 曾因漏掉 CI 归一而让 `Fe80::1` 这类混合大小写被静默跳过）。

### 4.2 自定义规则

- 自定义敏感词：`{词: 分类}`，aho-corasick 单趟扫描，IGNORECASE 语义，长词优先；永久占位符映射。
- 自定义正则：用户填 regex，编译后并入规则链。**编译顺序为 `regex` → 失败才回退 `fancy-regex`**（环视/反向引用的专用通道，见 §4.4 第 6 条）；两条路径都带超时熔断（单次匹配 >100ms 自动停用该规则——Python `CMD_MATCH_BUDGET` 思路推广到所有用户正则）。
- 前缀规则：`sk-`、`ah-` 等前缀 + 长度阈值。

### 4.3 路径感知豁免表（照搬 Python 语义）

- `role`/`type` 仅在协议容器内豁免；`id`/`tool_call_id`/`tool_use_id`/`call_id` 关联 ID 全局豁免
- `model/finish_reason/stop_reason/encoding_format…` 标量豁免；`cache_control` 子树豁免
- 业务区键（`input/arguments/parameters/partial_json/documents`）内一律扫描
- 键名脱敏：结构键白名单（`_MASK_PROTECTED_KEY_NAMES` 等价）外一律扫描
- 递归深度上限 24，超限 → 异常 → fail-closed 503

### 4.4 零宽环视断言的移植策略（D7，v1.1 新增）

**问题**：`RULES` 共 32 条 pattern / 21 个 label，内含 **43 处零宽环视**（19×`(?<!…)`、21×`(?!…)`、3×`(?=…)`）。`regex` crate 是 RE2 语义，**不支持环视与反向引用**；`fancy-regex` 支持但要引入回溯，直接违反 §1.3 的线性时间承诺。原计划同时写了「RE2 线性时间」与「规则逐一移植」，二者不可兼得——D7 就是这个岔路口的决策。

**决策**：

1. **内置规则一律保持 `regex` crate，不引入 `fancy-regex`。** 43 处环视全部是**零宽**断言，删除后匹配区间（`m.start()..m.end()`）**逐字节不变**，因此方案是「保留区间、把断言下沉为校验器」：
   - `(?<!CLASS)` → 匹配后检查 `text[..start]` 的**末字符**是否属于 CLASS（CHAR 级，O(1)）
   - `(?!CLASS)` → 检查 `text[end..]` 的**首字符**；覆盖 `(?!/)`、`(?![A-Za-z0-9_-])` 这类值尾边界
   - `(?=CLASS…)` → 值域断言（如「值须含数字或特殊符号」），改写为对捕获组的谓词检查
2. 校验器与既有 11 个语义校验器（`_card_ok` / `_idcard_ok` / `_phone_ok` / `_landline_ok` / `_email_ok` / `_iban_ok` / `_jwt_ok` / `_ip_public_ok` / `_ipv6_private_ok` / `_uscc_ok` / `_connstr_ok`）**同层同签名**：

   ```rust
   /// 返回 true = 该匹配成立。text = 全文本，m = 本次匹配区间。
   type Check = fn(text: &str, caps: &Captures, m: Match) -> bool;

   struct Rule {
       rx: Regex,
       label: &'static str,
       value_group: usize,   // 等价 Python RULES 第三元 group_idx：0 = 整段替换；>0 = 只替换捕获组区间、保留其余文本（如 Bearer 规则）
       checks: &'static [Check],
   }
   ```

   `value_group` 语义是本次移植的**不变量**：环视下沉不改变它，替换拼接仍按 `m[..gs] + token + m[ge..]` 进行。
3. **边界字符类必须显式 ASCII**：Python 的环视类都是 `[A-Za-z0-9_-]` 风格显式类，Rust 侧照抄为 ASCII 类，**不使用 `\w`/`\d`** 以避免 Unicode 语义漂移。仅 3 处 `\b`（如 `(?i)\bBearer\s+`）保留 Unicode 词边界模式，并单独补 CJK 邻接样本（Python `re` 与 `regex` crate 的 Unicode 词边界定义存在细微差异，由黄金样本裁定）。
4. **CONNSTR ↔ EMAIL 的豁免区间联动属于跨规则状态**，不能塞进单规则 `Check`。它来自 `_connstr_ok` 否决时把 `(start,end)` 压入 `exempt_conn`、随后 EMAIL 命中与之重叠则跳过——实现为规则链的显式阶段：

   ```rust
   enum Vet {
       Ok,
       Reject,
       RejectAndExempt { start: usize, end: usize },   // 与 Python mask() 的一轮循环结构一一对应
   }
   ```

   M3 需有「CONNSTR 排在 EMAIL 前 + 重叠跳过」的专项用例。
5. **替换语义保持一致**：Python 是「逐规则、按唯一原文去重后整篇替换，且跳过已生成的占位符」。Rust 侧同样按唯一原文去重（等价 `dict.fromkeys`），避免复现 `str.replace` 的 O(命中数 × 文本长) 退化。
6. **用户自定义正则的隔离通道**：走 `regex` → 失败才 `fancy-regex`，并单独施加墙钟预算（默认 100ms/次，触发即停用该规则并告警入库）。回溯风险因此被限制在用户自己填写的表达式内。

**验收方式（写入 M3 退出标准）**：为每条规则生成负样本集（每处边界各取 ±1 字符的「类成员 / 类外成员 / 文本首尾」组合）与正样本集，与 Python 版逐条比对；**43 处环视必须逐处有对应测试条目，缺一即视为未移植**。

---

## 5. 审计与命令拦截

### 5.1 被动审计信号（对齐 audit_signals.py 8 类）

| 信号 | 移植要点 |
|------|----------|
| error_leak | 上游 4xx/5xx body 中的堆栈/内部主机/凭据形态检测 |
| identity_swap | 响应 model 字段与请求 model 家族不匹配（`_model_family` 等价） |
| tool_call_rewrite | 请求/响应工具调用参数差异比对（echo 分类） |
| sse_anomaly | SSE 事件序异常（无 DONE、usage 缺失、事件序错乱） |
| response_poison | 响应中注入指令/伪造系统轮次/提示词注入形态 |
| cross_request_pollution | canary nonce 跨请求出现 |
| credential_echo | 凭据回流（`CREDENTIAL_ECHO_KINDS` 20+ 形态） |
| dangerous_action | 高危命令形态（只记录，与拦截清单分开维护） |

严重级别 `LOW/MEDIUM/HIGH/CRITICAL`，`severity_floor` 过滤后入库；主动探针（active_probes）一期实现生成器+矩阵执行（对齐 audit_engine.py build_probe_plan/aggregate_matrix）。

### 5.2 危险命令拦截

- 内置 7 条规则（rm -rf /、rm -rf ~、Windows del、format/mkfs、DROP DB、dd of=/dev/、fork 炸弹）+ 用户自定义/白名单
- 三模式：`observe`（默认，只记录）/ `rewrite`（改写为无害占位说明）/ `block`（截断下发，非流式整包 503）
- 通道：`tool`（工具参数）。**边界如实声明**：仅明文形态、仅已识别协议的响应管线；浏览器扩展链路不存在了。
- echo 抑制：请求体里已出现的命令不再触发（对齐 `_remember_request_cmd_snippets`）。

---

## 6. 数据层

### 6.1 SQLite（沿用 Python 版库结构与文件名，可平滑共存/迁移）

- 文件：`<data_dir>/shield-events.sqlite3`；表结构对齐：`events, meta, audit_events, daily_stats, daily_status, daily_words, daily_tokens, daily_models, daily_prefix`
- 写入：跨线程 channel + 专用写线程 + WAL + 每 100 条或 500ms 批量事务
- 保留期：`log_retention_days`（默认 7）每日清理
- 凭据红线：items 中凭据类原文不落库（摘要+preview）
- 不做 Python 库迁移工具（同文件兼容，Rust 版直接读写同一张表；Python 停用即可）

### 6.2 配置（`<data_dir>/config.json`）

```jsonc
{
  "server": { "port": 18701, "bind": "127.0.0.1" },
  "upstream": {                       // 单一上游（D4）
    "target": "https://api.your-relay.com",   // 支持带路径前缀
    "extra_headers": {},               // 非凭据协议头注入（凭据头拒绝注入）
    "egress_proxy": { "enabled": false, "url": "" }
  },
  "mask": {
    "enabled": true,
    "builtin_rules": { ... 21 类 ... }, // 对齐 DEFAULT_BUILTIN_RULES
    "custom_words": { "张三": "人名" },
    "custom_regexes": [],
    "secret_prefixes": ["sk-", "ah-"],
    "max_body_bytes": 33554432,
    "session_ttl": 600
  },
  "command_block": { "mode": "observe", "channels": ["tool"], "patterns": [...], "allow_patterns": [] },
  "audit": { "enabled": true, "passive": true, "active_probes": false, "severity_floor": "MEDIUM", "signals": {...} },
  "fail_closed": true,                // D6：已路由流量绝不放行原文（非 JSON→503 / 解析失败→400 / 超限→413 / 未知形态→整棵脱敏）；false 仅用于排查
  "response_scan": true,
  "stream_response": true,
  "log_retention_days": 7,
  "panel_token": "..."               // Web 登录令牌（≥16 位）
}
```

启动时不存在则生成默认配置；schema 校验 + 未知字段告警；热更新（词表/规则开关即时生效）。

---

## 7. Web UI（内嵌精简版，D2）

- `rust-embed` 打包 `assets/`，原生 HTML/CSS/vanilla JS（无构建步骤），深色主题
- 5 页：
  1. **Dashboard**：运行状态、今日请求/脱敏/还原计数、上游连通性、端口监听状态
  2. **规则**：21 类内置规则开关 + 自定义词表 CRUD + 自定义正则 + 前缀规则
  3. **日志**：事件流（类型/协议/上游/耗时/命中明细），凭据脱敏展示，未还原样本
  4. **审计**：审计事件列表 + 严重度过滤 + 主动探针触发 + 报告查看
  5. **设置**：上游地址、端口、egress 代理、命令拦截模式、响应扫描、保留期、令牌
- Token 登录（`/console` 输入一次，localStorage 保存，API 走 `Authorization: Bearer`）
- Origin 校验 + 安全响应头（对齐 Python 版 `api_guard` 的核心语义，去除桌面特有项）

### 7.1 管理 API（`/console/api/*`，精简为 ~20 个）

```
GET  /console/api/config          POST /console/api/config
POST /console/api/config/patch
GET  /console/api/status
POST /console/api/proxy/pause    POST /console/api/proxy/resume   // 脱敏暂停=纯透传
GET  /console/api/logs           GET  /console/api/logs/detail
POST /console/api/logs/clear     GET  /console/api/logs/export
GET  /console/api/stats/today    GET  /console/api/stats/history
GET  /console/api/audit/events   POST /console/api/audit/clear
POST /console/api/audit/run      GET  /console/api/audit/job
GET  /console/api/audit/report/latest
POST /console/api/upstream/test
GET  /console/api/health
```

---

## 8. 目录结构

```
maskit-rs/
├── PLAN.md                    # 本文件
├── PROGRESS.md                # 进度台账（每里程碑更新）
├── Cargo.toml
├── assets/                    # 内嵌 UI
│   ├── index.html  app.js  style.css
├── src/
│   ├── main.rs                # 入口：配置加载、服务启动
│   ├── config.rs              # 配置模型/加载/保存/热更新/默认值
│   ├── server/
│   │   ├── mod.rs             # axum router 装配（console + 反代分流）
│   │   ├── console_api.rs     # 管理 API handlers
│   │   ├── proxy.rs           # 反代管线（请求/响应两侧状态机）
│   │   └── static_ui.rs       # rust-embed 静态资源 + token 鉴权
│   ├── detect/
│   │   ├── mod.rs             # Protocol 枚举 + detect_protocol()
│   │   └── tests.rs
│   ├── mask/
│   │   ├── mod.rs             # 管线编排（mask_tree / restore_tree）
│   │   ├── rules.rs           # 内置 21 类规则定义 + 特征预筛（特征串自动派生）
│   │   ├── validators.rs      # Luhn/IDCard/IBAN/JWT/USCC/车牌/HKID 校验器
│   │   ├── boundaries.rs      # D7：43 处零宽环视下沉后的 BoundaryCheck + 跨规则豁免区间（CONNSTR→EMAIL）
│   │   ├── custom.rs          # 自定义词/正则/前缀规则 + aho-corasick
│   │   ├── placeholder.rs     # 占位符生成/解析/后缀字母表/转义形态
│   │   ├── session.rs         # 会话映射 + TTL 复用表 + 后缀索引
│   │   └── exemptions.rs      # 路径感知豁免表 + 业务区判定 + 键名白名单
│   ├── stream/
│   │   ├── sse.rs             # SSE 分帧 + 事件改写 + 跨 chunk 扣留
│   │   ├── ndjson.rs          # NDJSON 逐行
│   │   └── channels.rs        # delta 通道管理（content/arguments/…）
│   ├── audit/
│   │   ├── mod.rs             # 被动信号聚合 + severity
│   │   ├── signals/*.rs       # 8 类信号各自模块
│   │   └── probes.rs          # 主动探针（生成器+矩阵）
│   ├── cmdblock/
│   │   ├── mod.rs             # 命令拦截三模式 + echo 抑制
│   │   └── builtin.rs         # 内置 7 条规则
│   ├── store/
│   │   ├── events.rs          # sqlite 事件库（channel+写线程+WAL）
│   │   └── stats.rs           # 每日聚合
│   └── util/
│       ├── json.rs            # 保序 JSON + 重复键检测 + 深度限制
│       ├── cred.rs            # 凭据标签/摘要/preview
│       └── http_client.rs     # 上游 HTTP 客户端（连接池/代理/超时）
└── tests/
    ├── integration/           # 端到端：起服务 → 真实 HTTP 断言
    ├── golden/                # Python 版行为对照黄金样本
    └── bench/                 # 512KB body 基准
```

**依赖**：axum, tokio, hyper, reqwest(或 hyper client), serde, serde_json, regex, aho-corasick, **fancy-regex（仅用户自定义正则的回退引擎，D7；不进入内置规则链）**, rusqlite(bundled), dashmap, crossbeam-channel, rust-embed, tracing, uuid, sha2, base64, once_cell, rand

---

## 9. 里程碑计划（每步完成即更新 PROGRESS.md）

| 阶段 | 内容 | 退出标准 |
|------|------|----------|
| **M0 环境与骨架** | 安装 Rust 工具链；cargo init；CI 可编译；PROGRESS.md 建立 | `cargo build` 通过 |
| **M1 配置与服务器** | config.rs + axum 双路由（/console + 反代占位）+ 透传转发到上游 | curl 配置 API 正常；任意请求原样转发上游 |
| **M2 协议识别** | detect 模块 + 单测（三大协议 + Unknown + 边界形态）；**明确 detect 只选通道、不 gate 脱敏（D6）** | 单测全绿，覆盖 path/body 双判据；**断言「Unknown + fail_closed 仍整棵脱敏」** |
| **M3 规则引擎核心** | rules + validators + **boundaries（D7 环视下沉）** + placeholder + custom + 特征预筛；纯文本 mask/restore 单测 | 对齐 Python test_shield.py 关键用例（首批 ≥100 条，与 §10 一致）；**43 处环视逐处有等价性测试条目，缺一不算完成** |
| **M4 JSON 树管线** | mask_tree/restore_tree + 豁免表 + 键名脱敏 + 深度上限 + 重复键 | 黄金样本对照：与 Python 输出逐字节一致 |
| **M5 会话与占位符复用** | session.rs + TTL 复用表 + 后缀索引 + 多轮一致性 | 多轮对话映射稳定单测 |
| **M6 反代管线集成** | proxy.rs 请求侧全流程 + **fail-closed 判定矩阵（§2.2 表，逐行实现）** + 事件记录 + 命令拦截(请求侧 echo 基线) | e2e：真实脱敏请求往返；**§2.2 矩阵 10 行逐行断言状态码与事件 reason** |
| **M7 响应侧与流式** | 整包 JSON/NDJSON/SSE 三路径 + 通道缓冲 + 命令拦截(响应侧) + 响应扫描 | 流式还原 e2e（跨 chunk 边界用例全覆盖） |
| **M8 审计引擎** | 8 类被动信号 + 主动探针 + 报告 | 对齐 audit 单测核心用例 |
| **M9 事件库与统计** | sqlite 写线程 + 每日聚合 + 保留期清理 | 与 Python 库文件互读写验证 |
| **M10 Web UI 与 API** | 内嵌 5 页 + 20 个 API + token 鉴权 + Origin 校验 | 手工全功能过一遍 + e2e |
| **M11 性能验收与打磨** | 基准测试达 §1.3 指标；压测；内存调优 | P99<50ms@512KB；100 路并发 SSE |
| **M12 交付** | README、构建脚本（cargo build --release）、与 Python 版共存说明 | 单二进制可交付 |

**风险与对策**：
- **fail-closed 语义回归（最危险的失败模式）** → §2.2 判定矩阵直接作为 M6 验收清单；`fail_closed=false` 分支单独测试，防止「用户显式关闭」与「代码退化」被混为一谈
- 正则移植语义差异（含 43 处环视下沉）→ M3 用 Python 版逐用例生成黄金样本做差异断言 + 逐条边界等价性测试（§4.4）
- JSON 重序列化改变键序/空格 → 用保序 Map + 原始字节 splice 策略（Python `_splice_mask` 思路）：零命中时不改写任何字节，保住上游前缀缓存
- sqlite schema 兼容 → M9 直接对 Python 生成库做读写测试
- reqwest 不支持流式回写细粒度控制 → 用 hyper 客户端直连，body 用 `Body::channel` 双向流

---

## 10. 测试策略

1. **单元测试**：每模块 `#[cfg(test)]`；规则引擎用例直接从 `tests/test_shield.py`（223 条）精选移植 ≥100 条核心；每条规则的边界断言另有正/负样本专项（§4.4）
2. **黄金样本**：脚本驱动 Python 版对样本集生成输入→输出对，Rust 版断言一致（`tests/golden/`）
3. **集成测试**：`tests/integration/` 内起 mock 上游（axum 测试服务），全链路断言
4. **fail-closed 语义矩阵测试**：按 §2.2 判定矩阵逐行构造请求（未路由 / 只读 / 暂停 / 超限 / 非 JSON / 解析失败 / 非对象根 / 未知形态 / 脱敏异常 / 白名单外路径），断言 HTTP 状态码与事件 reason，并**断言原文绝不出现在上游收到的字节里**（每行都用真实 PII 哨兵样本）
5. **流式边界测试**：占位符在 1..N 字节切点全遍历（Python `repro_chunk_terminator.py` 思路），确保 0 残渣
6. **基准测试**：`tests/bench/` 用 8KB/256KB/512KB 真实形态 body 测吞吐与 P99
7. **回归门禁**：`cargo test` 全绿 + `cargo clippy` 无 warning 为合入标准

---

## 11. 明确不做（一期）

- Tauri 桌面壳 / 系统托盘 / 自动更新
- 浏览器扩展及其桥接 API（`/api/ext/*`）
- NER ONNX 推理（模型缺失且默认关闭；预留 `mask.ner_enabled` 配置位，置 true 时告警未实现）
- 透明代理/显式代理捕获模式、CA 证书生成、系统代理/hosts/环境变量托管
- Office 文档脱敏（属于扩展链路）
- Python 版配置自动迁移 UI（同库文件直接兼容，不需要）

---

## 12. 修订记录

### v1.1（2026-09-23）—— 修复评审 P0

| 编号 | 问题 | 处理 |
|------|------|------|
| **P0-1** | D3 把 Python 的 fail-closed 语义反转：原计划「非三大协议一律透传」，与 `SECURITY.md`「绝不放行未脱敏原文上行」的公开承诺、以及 `transparent.py` 对 `unknown_shape` / `non_json_body` / `invalid_json` 的实际阻断行为冲突（后者是外部审计 `SHIELD-UNLISTED-PASSTHROUGH-001`、`SHIELD-NONOBJECT-BYPASS-001` 的修复结果） | 新增 **D6**；§2.2 重写为状态机 + **判定矩阵（含 Python 对照列）**；同步修订 §3（detect 不 gate 脱敏）、§6.2（新增 `fail_closed` 配置）、§9（M2/M6 退出标准）、§10（新增矩阵测试） |
| **P0-2** | `regex` crate 不支持环视，而 `RULES` 含 43 处零宽环视；原计划同时承诺「RE2 线性时间」与「规则逐一移植」，二者不可兼得且未做决策 | 新增 **D7** 与 §4.4：内置规则环视一律下沉为零宽断言校验器（保留匹配区间与 `value_group` 语义），`fancy-regex` 仅作自定义正则回退并强制预算熔断；同步修订 §1.3、§4.1/§4.2、§8（依赖 + `boundaries.rs`）、§9（M3）、§10（边界等价性测试） |

顺带在同一批被改写段落内修正的既存笔误（均属段落内部一致性，非新增决策）：§2.2 只读方法集合去掉 DELETE（Python `_READONLY_METHODS` 仅 GET/HEAD/OPTIONS）；`invalid_json` 状态码 503→400；删除与 32MiB 闸门冲突的「128MB 硬上限」表述；M3 用例数 60→100（与 §10 对齐）。

**尚未处理**（评审 P1/P2，另开修订）：`_SSE_BUF_MAX` 实为 4MB（非 512KB）、`RULES` 实为 32 条 pattern、§1.2 性能证据引用了去重修复前的数字、多上游与 `paths` 白名单的取舍、`config.json` 同路径覆盖风险、代理正确性清单（content-encoding/长度、panic 隔离、优雅关闭、h2c）、配置键缺失清单（`record_plaintext_words` / `sensitive_word_whole` / `model_prices` 等）。
