# rss-identity

可嵌入 Rust 产品的本地认证、租户 OIDC 联合身份与实例内会话组件。宿主提供数据库 runtime、实例与租户、管理策略和资源生命周期；Identity 提供可信认证事实，产品持有资源授权。

core、postgres、可选 oidc 和 http-axum 四个能力包由宿主显式装配；具体 package 与依赖见 [workspace](Cargo.toml)。本地认证不依赖 OIDC 或参考应用。仅支持当前接口和全新安装，无旧中央服务、Hydra bridge、旧 schema/config 兼容分支。

- [嵌入指南](docs/guides/embedding.md)：宿主责任、本地与 OIDC 装配。
- [架构决定](docs/architecture/README.md)、[产品需求](docs/product/rss-identity-prd.md)。
- [开发与验证](docs/guides/development.md)、[HTTP 接入](docs/architecture/identity-wire-v2.md)。
- [参考部署](docs/deployment/README.md)：app/identity 的构建、安装、维护与恢复。
- [文档导航](docs/README.md)、[协作规则](AGENTS.md)、[来源与恢复](reference/README.md)。

实际消费产品拥有自己的接入和生产验收；历史运行结果不证明当前版本已验收。
