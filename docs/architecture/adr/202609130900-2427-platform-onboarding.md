# #2427 / #2428：系统管理域、租户开通与受认证 CLI

状态：用户已批准实施；验证结果由 PR 的实际命令记录持有。

## 唯一授权与不兼容替换

schema v8 仅初始安装，拒绝旧库，不自动迁移或清理。一次 initialize 原子创建系统管理域、首位本地平台管理员、成员和事件；系统域不是业务租户。平台角色只有一个 owner，系统账户不同时标记为租户 administrator。平台角色授撤和系统账户安全变更推进认证 epoch，保护最后一名可用本地平台管理员。维护 recover 只替换既有合格管理员的密码，不改变角色、启用或成员状态。

平台可以创建业务租户及首位本地管理员，也可以给已有业务租户新建本地管理员。后者允许平台以已知密码接管租户身份管理，是本次明确授权的权限边界；MDM 资源授权仍由消费产品决定。不提供平台禁用/恢复租户账户、改旧密码、提升既有账号、仿冒会话或额外 hold 状态。新增账号此后由租户现有管理 API 管理。

## 原子开通与运行绑定

系统域事务内复核平台 session/角色，按系统域到目标租户顺序锁定；通过窄范围 registrar 函数原子插入租户 epoch、账户、凭据、成员、操作回执和平台安全事件。重复 operation/principal/login 冲突，不覆盖已有账户。未知提交只提供操作 ID，不自动重放；查不到回执不证明原事务未提交。

系统域 ID、storage target/lineage 和单一 deployment generation 来自数据库外配置。先通过系统域 fencing 再读取注册表；使用外部 generation 构造精确不可变 binding。Runtime 与 Maintenance 使用分开的完整构造入口；Runtime 的外部来源和 keyring 是构造必需参数，无后置注入 setter。Authority 只替换 PgRuntime 与 Outbox 的组合，每个事务固定一个组合，串行切换且排空真实在途使用。201 表示提交且可登录；202 表示提交已确认、运行绑定尚待激活。不存在另一份持久化激活工作流或数据库外 journal。

## 自助 OIDC 与秘密

删除静态租户/IdP 清单、ApprovedProvider、deployment_approval、secret_ref 和启动审批同步，不保留兼容入口。系统域与业务租户使用相同 OIDC 模型、不同授权。租户可提交 client secret 和可选专用 CA；不做部署审批和 IP/CIDR 限制，因此协议请求可到达 Identity 运行环境可达的地址。保留 HTTPS、证书、issuer/state/nonce/PKCE 和有界网络工作；自助配置不能自动授予可信 MFA 等级。系统域只关联既有账户，不由 JIT/email/claims 授予平台权限。

秘密由数据库外 keyring 和 AES-256-GCM 加密；AAD 绑定 authority、tenant、provider、凭据版本和用途。秘密不返回、不记录、不写入事件。配置和凭据变化原子更新版本并使旧流程/会话失效。重加密有界，移除旧钥前核验引用；恢复必须保留对应解密密钥。

## CLI

identity-platform 只通过 HTTP 工作，纯协议 binding 与中央会话/平台响应由 identity-contracts 持有，CLI 不依赖服务端 core 或 PG。密码登录和浏览器 SSO 获得同一种中央会话，支持 login/logout、tenant create、tenant admin add、tenant list、operation status。秘密由私有文件输入；会话使用 0700 目录、0600 文件、跨进程锁与原子保存。管理员闲置十五分钟、绝对四小时，仅用户活动刷新；刷新未知不发业务写入，logout 未确认保留 logout_pending。

浏览器 SSO 使用外部浏览器、loopback 和 PKCE S256，唯一上游 callback 仍为 /api/v1/oidc/callback。五分钟登录事务完成后签发一分钟单次 CLI code，HTTPS 兑换时重新验证身份和平台权限后创建会话；浏览器不接收中央 session cookie。已验证的 CLI binding 在后续完成失败时接收封闭错误回传；无法验证绑定时维持原同源错误页及五分钟总等待上限。不存在长期 token、M2M 或自动写重试。

## 交付与证据

同一个 rss-identity PR 关联 #2427/#2428；主 agent 实施、测试与修复。T1/T2 覆盖角色、原子性、并发、结算未知、动态运行绑定、三域 OIDC 隔离、秘密轮换及 CLI 会话/SSO。完整 make ci 收尾统一运行。网页 #2368 消费新接口，固定候选双租户 SSO T3 由 #2342 持有，旧 UI 与旧 T3 记录不是新版本验收。

参考：Keycloak AdminRoles.java@06f4cad3925fd2cd95dc81d55b58b6d0282a7806；ZITADEL administrator-hardening；RFC 8252；oauth2-rs src/types.rs@f3424b4b2190c83c6d031fdc71eed2351d49e0df；ring 0.17.14 src/aead/less_safe_key.rs；固定 RSS 93ce684 的 fence.rs/transaction.rs。只采纳具体机制，不引入通用 IAM 或全局 runtime 平台。
