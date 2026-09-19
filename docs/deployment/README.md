# 可部署参考应用

参考宿主默认本地认证，可选上游企业 OIDC。持久拓扑为 Identity、专属 TLS PostgreSQL 和固定 UI 的同源 TLS 网关；Keycloak 仅用于测试，不是本地部署依赖。配置版本 3、HTTP v2、全新 schema v9；不升级旧中央数据库，也不提供兼容路由。

- [镜像构建](images.md)：一个后端镜像、一个独立前端镜像，Compose 固定实际 image ID。
- [安装和操作](operations.md)：同一输入生成 runtime/maintenance/migration/UI，初始化与只读核验。
- [备份、隔离恢复和轮换](recovery.md)：显式关闭与重新开放，无未知写入重试。
- [旧环境退役](retirement.md)：owner、保留条件和消费者迁移前置。

日期命名的旧验收及 `t3/` 记录保留历史来源。当前代码和 T2 不使这些记录自动成为新候选的验收；#2366 持有实际浏览器、部署恢复和容量 T3。

2026-09-17 的候选与修复验证归属 [PR #1030](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1030)。旧清单与结果通过 Git 历史追溯，当前部署不消费这些文件。
