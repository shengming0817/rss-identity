# 产品范围

Access 拥有本地身份认证、租户与成员身份、联合 IdP 登录事务、身份关联、中央登录会话、下游受控身份交接、自身管理授权与安全事件。拥有其 schema、生产迁移、配置、composition、assembly、binary 和产品 T3。

RSS 提供可复用 runtime、事务消息及必要基础库；只消费实际需要的已发布包，不要求 RSS 全部组件一起发布。发行包尚不可用时登记外部依赖，不使用跨仓 path 绕过。

MDM/ZT 拥有资源权限、业务角色与 ABAC、设备证书、attestation、posture、产品浏览器会话及其请求边界。Access 仅规范化可信认证事实，不铸造产品授权结论。Access 管理员不自动成为 MDM 管理员。

中央 Access 登录会话与产品浏览器会话分开。产品后端通过受认证的服务端接缝消费身份；跨产品不共享宽域 cookie。完整 OAuth BFF 的代理路径须先决策，不能仅凭 cookie 宣称所有产品 token 均不进入浏览器。

核心与 adapter 分 package；adapter 按能力和 provider 命名，物理保留 `adapters/`。初始不按每个模型拆 crate。产品注入共享连接池，业务写入与 Outbox 在同一数据库事务内组合；各 schema owner 导出自己的 migration，产品决定执行顺序。

不建设通用 IAM、OAuth 授权服务器平台、通用 API proxy、中央业务 ABAC 或设备 authority。SAML/LDAP/SCIM、M2M、自助注册、passkey 等按 PRD 分级和真实消费者另行接纳。
