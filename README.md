# rss-access

面向 RSS 系产品的本地认证、租户联合身份接入与服务端会话服务。拥有独立数据库、装配、二进制、发布与产品 T3；资源级业务授权由 MDM/ZT 持有。

当前提供身份协议 ADR、本地账户 Rust API、PG 原子安全事件、access-admin 本机工具、OIDC 接缝、独立 CI 和真实 provider 测试。会话服务、HTTP/UI 和生产部署由后续工作项实现；本次不构成生产认证服务。集成分支为 `develop`。

- [产品 PRD](docs/product/rss-access-prd.md)：需求、分级、消费者和验收目标。
- [实施与 Issue 计划](docs/architecture/implementation-plan.md)：依赖顺序、真实工作项链接和验收责任。
- [开发与验证](docs/guides/development.md)：固定 Git 消费、工具链、真实 provider 测试与证明边界。
- [文档导航](docs/README.md)、[协作规则](AGENTS.md)。
- [历史参考](reference/README.md)、[证据索引](docs/reference/sources.md)。

本地材料通过 `.git/info/exclude` 排除；克隆后按历史参考说明恢复。当前不包含业务数据库或密钥。
