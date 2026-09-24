# Maskit-RS

本地 LLM 敏感信息脱敏网关（Rust 重构版）。单进程、单端口、单上游：Web 控制台、管理 API 与 LLM 反代共用一个监听端口。

相对 Python 版的两个核心变化：

1. **性能**：请求体脱敏 P99 相对 Python 版提升 **40x**（512KB 请求体：90ms vs 3696ms），不再出现「跑满 CPU 卡死」。
2. **形态**：一个端口 + 一个上游（原先是「一端口一上游」的多端口模式），三大协议按请求体自动识别。

---

## 快速开始

```bash
# 构建（需 Rust 1.75+；磁盘紧张时建议 export CARGO_INCREMENTAL=0）
cargo build --release

# 运行（默认监听 127.0.0.1:18701，数据目录 ./data）
./target/release/maskit-rs

# 或指定数据目录
MASKIT_RS_DATA_DIR=/var/lib/maskit-rs ./target/release/maskit-rs
```

启动后：

1. 打开控制台：<http://127.0.0.1:18701/console>
2. 令牌见 `config.json` 的 `panel_token`（首次启动自动生成并打印在日志里）
3. 在「设置」页填入**上游地址**（如 `https://api.your-relay.com`），保存后**立即生效**，无需重启
4. 客户端 `base_url` 指向本机：

   | 客户端 | base_url |
   |--------|----------|
   | OpenAI SDK / Cursor / Codex | `http://127.0.0.1:18701/v1` |
   | Anthropic SDK / Claude Code | `http://127.0.0.1:18701` |

   路径原样转发到上游，鉴权头（`Authorization` / `x-api-key`）透传。

---

## 协议识别与处理策略

请求体形态决定用哪套解析/还原通道（`detect` 模块）：

| 协议 | 判据 |
|------|------|
| **Chat Completions** | 顶层 `messages[]`（含 `role`/`content`），无 `input` |
| **Responses** | 顶层 `input`（string 或数组），无 `messages`；或路径含 `/responses` |
| **Anthropic Messages** | body 含 `anthropic_version`；或路径 `/messages` + `messages[]` + (`system` 或 `max_tokens`) + 首条 role 合法 |
| **Unknown** | 其余全部 |

**是否脱敏不由协议识别决定**（PLAN D6），而由三个事实决定：请求是否落在已配置上游路由、`fail_closed`、body 能否解析。判定矩阵：

| 场景 | `fail_closed=true`（默认） | `fail_closed=false` |
|------|---------------------------|---------------------|
| 上游未配置 | 502 `no_reverse_route` | 同左 |
| GET / HEAD / OPTIONS | 转发 + PASS | 同左 |
| 脱敏暂停 | 转发 + BYPASS | 同左 |
| body 超上限（默认 32MiB） | **413** | 413 |
| 声明非 JSON | **503** `non_json_body` | 转发 + BYPASS |
| JSON 解析失败 | **400** `invalid_json` | 转发 + BYPASS |
| 顶层非对象（数组根） | **整棵脱敏** | 转发 + BYPASS |
| 已路由的未知形态 JSON | **整棵脱敏** + 事件标 `unknown_shape` | 转发 + BYPASS |
| 脱敏过程异常（深度超限等） | **503** | 503 |
| DELETE | 走完整管线（可带 body） | 同左 |

`fail_closed=true` 的含义：**已路由流量绝不放行未脱敏原文上行**。

---

## 功能

- **21 类内置规则**（API Key / 银行卡 / 连接串密码 / 邮箱 / 身份证 / 座机 / 手机号 默认开启；PEM 私钥 / JWT / Token / 云厂商 AK / 内网 IP / IPv6 / MAC / 车牌 / IBAN / USCC 等可按需开启），逐条对齐 Python 版语义与边界
- **自定义敏感词 / 自定义正则 / 密钥前缀**（如 `sk-`）
- **多轮一致性**：同一原文在 TTL 内复用同一占位符（`session_ttl`，默认 600s）
- **路径感知脱敏**：协议位置字段（`role`/`model`/`id` 等）不动，业务区（工具参数）强制扫描
- **流式还原**：SSE / NDJSON 逐事件还原，跨 chunk 的半截占位符扣留后拼合
- **命令拦截**：observe（只记录，默认）/ rewrite（改写为 no-op 说明）/ block（停止下发）
- **8 类被动审计信号**：错误泄露 / 换芯 / 工具重写 / 流异常 / 响应投毒 / 跨请求污染 / 凭据回流 / 危险动作
- **token 用量统计**：按模型统计输入/输出 token（`/api/stats/today`、`/api/stats/models`）。**只统计数量，不做价格/费用计算**
- **事件与统计**：SQLite（与 Python 版同 schema，可互读写）、每日聚合、保留期清理
- **凭据红线**：凭据类命中（API_KEY/TOKEN/SECRET/ACCESS_KEY/JWT/CONNSTR/PRIVATE_KEY）原文**永不落库**，只存 sha256 摘要与打码预览

---

## 目录结构

```
maskit-rs/
├── PLAN.md              # 设计方案（里程碑、决策记录 D1-D7）
├── PROGRESS.md          # 进度台账（每个里程碑的验证证据）
├── Cargo.toml
├── assets/              # 内嵌 Web 控制台（原生 HTML/CSS/JS，无构建步骤）
└── src/
    ├── main.rs          # 入口：配置加载、后台维护、优雅关闭
    ├── config.rs        # 配置模型/校验/热更新/原子写盘
    ├── detect/          # 三大协议识别
    ├── mask/
    │   ├── engine.rs    # mask()/restore() 编排、规则链、自定义词
    │   ├── rules.rs     # 21 类规则 + 环视下沉校验器（D7）
    │   ├── validators.rs# Luhn/身份证/IBAN/JWT/USCC 等校验器
    │   ├── placeholder.rs # 占位符格式与正则族
    │   ├── session.rs   # 会话映射 + TTL 复用表 + 后缀索引
    │   ├── exemptions.rs# 路径感知豁免表
    │   └── tree.rs      # mask_tree/restore_tree + 字节级 splice
    ├── stream/          # SSE / NDJSON 流式还原
    ├── server/          # axum 路由、反代管线、管理 API、内嵌 UI
    ├── audit/           # 8 类审计信号
    ├── cmdblock/        # 命令拦截
    ├── store/           # 内存事件总线 + SQLite 事件库
    └── upstream.rs      # 上游 HTTP 客户端
```

---

## 配置

配置文件：`<数据目录>/config.json`（首次启动自动生成）。主要项：

| 键 | 说明 |
|----|------|
| `server.port` / `server.bind` | 监听端口与地址（默认 `18701` / `127.0.0.1`） |
| `upstream.target` | 唯一上游地址，可带路径前缀（改后热生效） |
| `upstream.extra_headers` | 注入的静态请求头（凭据类头会被拒绝注入） |
| `mask.builtin_rules` | 21 类规则开关 |
| `mask.custom_words` | 自定义敏感词 `{词: 分类}` |
| `mask.sensitive_disabled` | 禁用的词分组（整组关闭） |
| `mask.sensitive_word_disabled` | 词级禁用 `{分组: [词...]}` |
| `mask.sensitive_word_whole` | 整词匹配开关（词两侧加边界；单字词自动带 CJK 边界） |
| `mask.secret_prefixes` | 密钥前缀（默认 `sk-`、`ah-`） |
| `mask.max_body_bytes` | 请求体上限（默认 32MiB，超出返回 413） |
| `mask.session_ttl` | 占位符复用窗口（秒，默认 600） |
| `fail_closed` | 已路由流量是否绝不放行未脱敏原文（默认 `true`） |
| `command_block.mode` | `observe` / `rewrite` / `block` |
| `audit.*` | 审计开关、严重度门槛（**无主动探针**，只做被动检测） |
| `panel_token` | 控制台令牌（不限制长度，原样生效；留空自动生成 24 位随机值） |
| `mask.log_credential_plaintext` | 事件日志是否保留凭据类**明文原文**（默认 `true`）。⚠️ 为 `true` 时 API Key / 私钥 / 连接串等明文会写入 SQLite，**备份必须加密**；多人可读的主机建议设为 `false` |

---

## 安全须知

- 默认只监听 `127.0.0.1`。要让局域网访问，改 `server.bind` 为 `0.0.0.0` 并**务必设置强令牌**。
- 管理 API 有 Bearer 令牌鉴权 + Origin 校验（拒绝跨站写操作）+ 安全响应头。
- 凭据类命中不进事件库、不进日志导出、不进控制台明细。
- 事件库路径：`<数据目录>/shield-events.sqlite3`。备份该文件即可备份历史统计。

---

## 开发与测试

```bash
# 单元 + 集成测试（debug）
cargo test

# 性能验收（必须 release + 串行，否则计时无意义）
cargo test --release --test perf_tests -- --test-threads=1 --nocapture

# 静态检查
cargo clippy --all-targets -- -D warnings
```

性能测试会打印本机 CPU 配额（容器 cgroup 可能是 0.6 核），绝对耗时不可跨机比较，**相对 Python 基线的提升倍数**才是有效判据。

磁盘紧张时：`export CARGO_INCREMENTAL=0`，并按需 `cargo clean --profile dev`。

---

## 与 Python 版共存

两者事件库 schema 相同，可读写同一个 `shield-events.sqlite3`（但**不要同时运行**写同一个库）。
配置格式不同，Python 版的 `config.json` 不能直接复用；自定义词表/规则开关需要在控制台重新配置，或从旧 `config.json` 手动拷贝 `sensitive` / `sensitive_word_disabled` / `builtin_rules` 三项。

---

## Docker 部署

镜像随 Release 自动推送到 GHCR（多架构：`linux/amd64` + `linux/arm64`）。

```bash
# 拉取运行（把 <版本> 换成 Release 里的版本号，如 v0.1.0）
docker run -d --name maskit-rs \
  -p 127.0.0.1:18701:18701 \
  -v "$(pwd)/data:/data" \
  -e MASKIT_RS_DATA_DIR=/data \
  ghcr.io/<你的账号或组织>/maskit-rs:<版本>
```

镜像基于 **distroless/cc**（非 root、无 shell、无包管理器），只含二进制本体 —— SQLite 已静态链接进二进制，不依赖系统库。首次启动令牌打印在容器日志：

```bash
docker logs maskit-rs 2>&1 | grep token
```

### Docker Compose

```bash
cd maskit-rs
docker compose up -d
# 控制台：http://127.0.0.1:18701/console
```

`docker-compose.yml` 已配好端口、持久化命名卷、日志轮转与 CPU/内存上限，
默认用命名卷 `maskit-data`，**无需任何宿主机目录权限改动即可启动**。
默认是本地构建；要用 GHCR 镜像，把 compose 里 `build` 段换成 `image: ghcr.io/<账号>/maskit-rs:<版本>` 即可（文件末尾有注释示例）。

### 访问地址

| 用途 | 地址 |
|------|------|
| **Web 控制台** | <http://127.0.0.1:18701/console> |
| 根路径 `/` | 上游未配置时显示引导页；已配置时透传给上游 |
| 健康检查 | <http://127.0.0.1:18701/console/api/health> |

> 端口根路径 `/` 走的是反代管线（转发给上游），**控制台不在根路径，而在 `/console`**。

### 部署注意

- 默认只映射到 `127.0.0.1`。要让局域网访问，改成 `18701:18701` 并**务必设置强令牌**。
- 数据目录（`config.json` + `shield-events.sqlite3`）务必挂卷持久化，否则容器重建会丢配置与历史统计。
- 镜像内无 shell，无法 `docker exec` 排障；用 `docker logs` 看运行日志。

---

## 命令行参数

```bash
maskit-rs                  # 启动网关
maskit-rs --version        # 打印版本
maskit-rs --help           # 用法与环境变量
maskit-rs --health-check   # 健康检查（容器 HEALTHCHECK 用，退出码 0/1）
```

| 环境变量 | 说明 |
|----------|------|
| `MASKIT_RS_DATA_DIR` | 数据目录（默认 `./data`） |
| `MASKIT_RS_BIND` | 监听地址（默认取 `config.json` 的 `server.bind`；**容器内必须为 `0.0.0.0`**，否则 `-p` 端口映射接不到） |
| `RUST_LOG` | 日志级别（默认 `info`） |

---

## 从源码构建正式版

```bash
export CARGO_INCREMENTAL=0   # 磁盘紧张时强烈建议
cargo build --release         # 产物：target/release/maskit-rs（约 9.4MB）
cargo test                    # 280 个测试
cargo test --release --test perf_tests -- --test-threads=1   # 性能基准
```

---

## 许可

GNU AGPL-3.0（与 Python 版一致）。
