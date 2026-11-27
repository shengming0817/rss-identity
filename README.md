# rss-identity

独立 Identity 服务提供本地认证、租户 OIDC 联合身份与实例内会话。本仓维护产品 HTTP 契约、服务装配、安装、维护和部署。公共认证库、Audit 和基础库从同一个 RSS 提交构建，固定版本见 [Cargo.toml](Cargo.toml)。

- [嵌入指南](docs/guides/embedding.md)：宿主责任、本地与 OIDC 装配。
- [产品需求](docs/product/rss-identity-prd.md)。
- [开发与验证](docs/guides/development.md)、[HTTP 接入](docs/architecture/identity-http.md)。
- [参考部署](docs/deployment/README.md)：app/identity 的构建、安装、维护与恢复。
- [文档导航](docs/README.md)、[协作规则](AGENTS.md)、[来源与恢复](reference/README.md)。

实际消费产品拥有自己的接入和生产验收；历史运行结果不证明当前版本已验收。
