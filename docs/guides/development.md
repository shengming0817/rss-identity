# 开发与验证

使用系统 `/usr/bin/git`。Rust 工具链以 [rust-toolchain.toml](../../rust-toolchain.toml) 为准；需要 Python 3.11+、Docker，以及 CI 配置选定的 cargo-deny。依赖由 manifest/lock 持有，provider 镜像由 [providers.lock.json](../../deployment/providers.lock.json) 持有。私有 RSS Git 依赖需要读取权限。

[Makefile](../../Makefile) 提供 `make check`、`make test`、`make test-pg`、`make test-federated`、`make test-assembly`、`make test-gateway` 等专项入口；`make ci` 是完整工程入口。项目证据边界见[验证范围](../rules/verification-scope.md)。

真实 provider 的 ignored 测试通过已有 runner 执行；runner 校验实际用例和执行结果，缺少 Docker/provider 失败，不把零测试或部分执行当通过。工作树可直接测试，无需预先提交。Make 共用 Identity 主 checkout 的 Cargo target；显式 CARGO_TARGET_DIR 可覆盖，保留可用缓存。

`make dependencies` 检查 RSS 来源和实际生产/测试 feature；`make licenses` 检查许可证与公告。Azure job 凭据只用于 fetch，随后移除凭据并离线构建。配置流水线不等于已运行通过。

产品 PG 验收覆盖会话、管理、WebAuthn 与维护；联邦验收使用真实 Keycloak。安装和校验使用固定提交中各库导出的 migration 与签名，操作见[操作指南](../deployment/operations.md)。

Web 接入由 rss-web 的现有联合测试持有；MDM 接入归其产品。需要真实浏览器、部署和恢复闭环时，独立评估并使用[参考运行入口](../deployment/images.md#功能验收)，不重复模拟 consumer 或容量验证。

在 Cargo.toml 固定的 RSS checkout 中，运行 `cargo test --locked -p identity-postgres-integration -p identity-oidc-integration` 执行库级 PostgreSQL 和 Keycloak 验收。私网 Keycloak 需要从测试进程可达的 RFC1918 IPv4 地址；使用远程 Docker 时，将 `IDENTITY_TEST_PRIVATE_HOST` 设为远端 Docker 发布监听器的可达私网地址。四个公共包的独立 Git 消费验证见[凭据库指南](https://dev.azure.com/shengming0923/rss/_git/rss?path=/crates/identity-web-credentials/README.md&version=GC8f50018ade8b32f797698b7b0290d11ea90502bf)。
