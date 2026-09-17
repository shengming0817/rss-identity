# rss-identity

可嵌入 Rust 产品的本地认证、租户 OIDC 联合身份与实例内会话组件。宿主提供数据库 runtime、实例与租户、管理授权策略和资源生命周期；Identity 提供认证事实，产品持有资源授权。

公开能力包为 `rss-identity-core`、`rss-identity-postgres`、可选 `rss-identity-oidc` 和可挂载的 `rss-identity-http-axum`。本地登录只需 Authority；OIDC 通过 Federation 单独装配。HTTP 仅提供 `/api/v2`，全新数据库使用 schema v9；没有旧中央模式、Hydra bridge、client/contracts 或旧 schema 兼容分支。

- [嵌入指南](docs/guides/embedding.md)：公共 API、宿主责任与两种消费者。
- [当前方案 ADR](docs/architecture/adr/202609170001-2435-embedded-authentication.md)、[实施计划](docs/architecture/implementation-plan.md)。
- [产品需求](docs/product/rss-identity-prd.md)、[开发与验证](docs/guides/development.md)、[HTTP v2](docs/architecture/identity-wire-v2.md)。
- [文档导航](docs/README.md)、[协作规则](AGENTS.md)、[历史参考](reference/README.md)。

`app/identity` 是最小参考宿主，输出 identity-server、identity-migrate、identity-admin。[参考部署与固定 UI 候选](docs/deployment/README.md) 由 #2436 与 Web #2368 交付；实际候选的浏览器、恢复和容量 T3 属于 #2366，MDM 接入属于 #2437。历史验收记录不证明本次重构的产品部署能力。
