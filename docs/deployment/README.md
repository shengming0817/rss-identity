# 参考宿主与历史部署证据

当前 app/identity 是最小参考宿主，配置格式为 3，所有配置 JSON 字段使用 camelCase（例如 `formatVersion`、`instanceId`、`passwordFile`），拒绝旧字段别名；样例见 [example.json](../../deployment/example.json)。支持 identity-server、identity-migrate、identity-admin；数据库角色由宿主预建，Identity schema 仅全新 v9 安装。公共 Rust 装配见 [嵌入指南](../guides/embedding.md)。

此目录其余文档与 t3 中已保存的证据属于旧中央模式。旧可执行装配/验收入口已退役，源码可从 fa7019922162158704cc47c6ac7ad36a67c8ae5a 恢复。完整部署、UI 候选、运维和 T3 由 #2436 更新验收，本次不声明这些旧记录覆盖新组件。

`bootstrapAccounts` 为每个 `storage.tenants` 租户提供唯一 `{tenantId, principalId}`。迁移输入包含 `formatVersion`、`instanceId`、`database`、`storage`、`runtimeRole`、`maintenanceRole`；维护命令输入包含 `instanceId`、`database`、`storage`。安装提交前验证目标角色属性、继承权限和有效授权；异常会回滚 RSS 与 Identity schema。`make test-assembly` 用真实 TLS PostgreSQL 验证安装及参考进程启停，不构成部署 T3。
