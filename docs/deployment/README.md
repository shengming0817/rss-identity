# 可部署参考应用

参考宿主默认本地认证，可选上游企业 OIDC。持久拓扑为 Identity、专属 TLS PostgreSQL 和固定 UI 的同源 TLS 网关；Keycloak 仅用于测试，不是本地部署依赖。配置版本 4、HTTP v2、全新 schema v9；不升级旧中央数据库，也不提供兼容路由。

- [镜像构建](images.md)：一个后端镜像、一个独立前端镜像，Compose 固定实际 image ID。
- [安装和操作](operations.md)：同一输入生成 runtime/maintenance/migration/UI，初始化与只读核验。
- [备份、隔离恢复和轮换](recovery.md)：显式关闭与重新开放，无未知写入重试。
- [旧环境退役](retirement.md)：owner、保留条件和消费者迁移前置。

组件 T2 不替代实际部署验收；#2366 持有实际浏览器、部署恢复和容量 T3。
