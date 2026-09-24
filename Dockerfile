# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Maskit-RS —— 多阶段构建
#
# 体积控制要点：
#   1. builder 阶段用 debian slim（需要 glibc 链接），不用 alpine 交叉编译，
#      避免 musl 静态链接带来的兼容性与调试成本；
#   2. **依赖单独分层**：先把 Cargo.lock 的依赖编译成独立层，业务代码改动
#      不会让依赖重新编译（CI 缓存命中率高）；
#   3. runtime 用 distroless/cc-debian12：非 root、无 shell、无包管理器，
#      比 debian slim 小一个数量级；
#   4. 只拷贝二进制本体，SQLite 静态链接进二进制，无需 libsqlite3；
#   5. 不需要 CA 证书以外的任何系统包。
# ---------------------------------------------------------------------------

# ---------- 阶段 1：依赖层（仅依赖，利用 Docker 缓存） ----------
FROM rust:1.83-slim-bookworm AS deps
WORKDIR /build
# openssl 不需要（无 TLS 依赖），仅装 pkg-config 供极少数构建脚本探测用
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
# 生成最小 src 让 cargo 能解析依赖图（避免 dummy build 反复触发）
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src \
 && find target/release -maxdepth 1 -type f \
      \( -name '*.d' -o -name 'maskit-rs*' \) -delete || true

# ---------- 阶段 2：构建业务代码 ----------
FROM deps AS builder
WORKDIR /build
COPY . .
# 复用依赖层已编译的产物
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked \
 && strip target/release/maskit-rs \
 && ls -lh target/release/maskit-rs

# ---------- 阶段 3：运行时（distroless，非 root） ----------
# 需要 HTTPS 上游：distroless/cc 含 CA 证书；sqlite 已静态链接进二进制
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app

# 数据目录（config.json / shield-events.sqlite3 落这里）
COPY --chown=nonroot:nonroot --from=builder /build/target/release/maskit-rs /usr/local/bin/maskit-rs
COPY --chown=nonroot:nonroot config.example.json /app/config.example.json

# 建议挂载 /data 持久化配置与事件库
VOLUME ["/data"]
ENV MASKIT_RS_DATA_DIR=/data \
    RUST_LOG=info

USER nonroot:nonroot
EXPOSE 18701

# 无 shell 环境下用二进制自身做健康检查（distroless 无 curl）
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/maskit-rs", "--health-check"]

ENTRYPOINT ["/usr/local/bin/maskit-rs"]
