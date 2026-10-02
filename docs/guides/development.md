# 开发与验证

使用系统 `/usr/bin/git`。Rust 工具链以 [rust-toolchain.toml](../../rust-toolchain.toml) 为准；需要 Python 3.11+、Docker，以及 CI 配置选定的 cargo-deny。依赖由 manifest/lock 持有，provider 镜像由 [providers.lock.json](../../deployment/providers.lock.json) 持有。私有 RSS Git 依赖需要读取权限。

[Makefile](../../Makefile) 提供 `make check`、`make test`、`make test-pg`、`make test-oidc`、`make test-federated`、`make test-assembly`、`make test-gateway` 等专项入口；`make ci` 是完整工程入口。项目证据边界见[验证范围](../rules/verification-scope.md)。

真实 provider 的 ignored 测试通过已有 runner 执行；runner 校验实际用例和执行结果，缺少 Docker/provider 失败，不把零测试或部分执行当通过。工作树可直接测试，无需预先提交。Make 共用 Identity 主 checkout 的 Cargo target；显式 CARGO_TARGET_DIR 可覆盖，保留可用缓存。

`make dependencies` 检查 RSS 来源和实际生产/测试 feature；`make licenses` 检查许可证与公告。Azure job 凭据只用于 fetch，随后移除凭据并离线构建。配置流水线不等于已运行通过。

修改组件 schema 时，用 `python3 hack/schema_signature.py` 在临时 PG 中计算签名；不得用业务库漂移充当声明。配置、迁移及实际安装查询见[操作指南](../deployment/operations.md)。

私网 OIDC 接缝需要本机拥有的 RFC1918 接口。可用 `IDENTITY_TEST_PRIVATE_HOST` 显式选择已有接口；不能用 loopback、保留或非本机地址放宽生产策略。单独运行 `python3 hack/providers.py private-oidc` 时设置与本仓一致的 CARGO_TARGET_DIR。

Web 接入由 rss-web 的现有联合测试持有；MDM 接入归其产品。需要真实浏览器、部署和恢复闭环时，独立评估并使用[参考运行入口](../deployment/images.md#功能验收)，不重复模拟 consumer 或容量验证。
