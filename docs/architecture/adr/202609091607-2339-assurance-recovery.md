# #2339：Assurance 与恢复（历史决定）

适用时期：#2435 嵌入架构之前的中央模式。由 [#2435](202609170001-2435-embedded-authentication.md) 替代，不作为当前操作说明。

## 当时的决定与取舍

只将选定 IdP 已验证的 MFA/认证时间解释为可信 assurance，不能由浏览器声明或普通登录推断。应急本地账户需预先建立；数据库恢复使用原生备份与隔离核对，不另建 seal 或业务激活状态机。

## 替代关系

中央下游 assurance 传播已退出；当前宿主直接消费请求级可信事实。恢复不能复活旧撤销状态，历史固定环境的性能批准不成为当前目标。

历史实现与当时的验证记录通过 [#2339 工作项](https://dev.azure.com/shengming0923/rss/_workitems/edit/2339) 和本文件 Git 历史追溯。历史结果不表示当前版本已验证；来源与许可证见[来源索引](../../reference/sources.md)。

- [openidconnect 4.0.1 verification](https://github.com/ramosbugs/openidconnect-rs/blob/b639b5d39eac6903238867aeb2b29326502e6b26/src/verification/mod.rs)
- [Keycloak 26.7.3 export](https://github.com/keycloak/keycloak/blob/26.7.3/docs/guides/server/importExport.adoc)
- [Kanidm v1.9.4 restore](https://github.com/kanidm/kanidm/blob/v1.9.4/server/core/src/lib.rs#L429-L486)
- [PostgreSQL 17 pg_verifybackup](https://www.postgresql.org/docs/17/app-pgverifybackup.html)
- [Hydra key rotation](https://www.ory.com/docs/hydra/self-hosted/secrets-key-rotation)
