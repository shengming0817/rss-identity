# 可部署参考应用

参考宿主默认本地认证，可选上游企业 OIDC。持久拓扑为 Identity、专属 TLS PostgreSQL 和固定 UI 的同源 TLS 网关；Keycloak 仅用于测试，不是本地部署依赖。配置版本 3、HTTP v2、全新 schema v9；不升级旧中央数据库，也不提供兼容路由。

- [候选构建](candidate.md)：双方 SHA、locks、RSS features、三个 binary 与三种镜像。
- [安装和操作](operations.md)：同一输入生成 runtime/maintenance/migration/UI，初始化与只读核验。
- [备份、隔离恢复和轮换](recovery.md)：显式关闭与重新开放，无未知写入重试。
- [旧环境退役](retirement.md)：owner、保留条件和消费者迁移前置。

日期命名的旧验收及 `t3/` 记录保留历史来源。当前代码和 T2 不使这些记录自动成为新候选的验收；#2366 持有实际浏览器、部署恢复和容量 T3。

本次固定候选与可再生证据见 [20260917 #2436 联合记录](verification/20260917-2436/README.md)。

PR #1030 修复后的固定候选与 25 步真实 operator 记录见 [20260917 修复验证](verification/20260917-1030/README.md)。
