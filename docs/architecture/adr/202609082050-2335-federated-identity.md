# #2335：租户联合身份（历史决定）

适用时期：#2435 嵌入架构之前的中央模式。由 [#2435](202609170001-2435-embedded-authentication.md) 替代，不作为当前操作说明。

## 当时的决定与取舍

上游客户端复用 openidconnect，产品持有登录事务与租户关联。OIDC 状态、浏览器绑定、nonce、PKCE 和配置版本原子消费；身份键来自已验证 issuer/subject，不按邮箱自动合并。JIT、显式关联和凭据加密保持独立授权与事务边界。

## 替代关系

这些认证规则继续适用，但中央 Router、管理角色和旧配置形状已退出；宿主通过可选 Federation 组合当前接口。

历史实现与当时的验证记录通过 [#2335 工作项](https://dev.azure.com/shengming0923/rss/_workitems/edit/2335) 和本文件 Git 历史追溯。历史结果不表示当前版本已验证；来源与许可证见[来源索引](../../reference/sources.md)。
