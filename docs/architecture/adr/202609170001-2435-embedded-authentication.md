# #2435 内嵌认证组件与参考宿主

状态：已实施，交付证据见[实施与验收记录](../../reviews/202609170600-2435-embedded-authentication.md)；PR/看板持有实时交接状态。替代中央认证运行模式的当前规则；历史 ADR 保留原始决策和验收语境。

## 原则复核

彻底：账户、会话、联合身份与原子安全事件只有一套实现；删除 contracts/client/Hydra、下游 grant、中央平台租户注册与 CLI SSO 源码及当前构建入口。管理角色、防锁死策略和资源授权由宿主持有，组件没有 administrator、emergency、platform_administrator 或替代角色标记。

不向后兼容：仅提供 HTTP `/api/v2` 和 `/api/v2/oidc/callback`，没有 v1 别名或 legacy feature。schema v9 是全新安装基线；拒绝旧库，不提供 v8 升级、双读或旧配置回退。保留旧候选、数据和密钥的历史证据，不操作既有部署。

优雅简洁：保留 core、postgres、oidc、http-axum 四个能力 crate；应用层只有参考宿主。宿主注入现有 PgRuntime、显式实例与租户列表、KDF、事件预算、SessionPolicy 和必选 ManagementPolicy。Authority 不创建、替换或关闭宿主连接池，不发现中央租户。OIDC 的密钥、状态签名、callback、return target、group policy 单独配置，本地模式不要求这些字段。

## 调用与信任边界

`login_local` 完成限流、密码验证、最新账户/成员状态复核和会话/事件原子提交。密码候选和底层会话签发仅组件内部可见。`reauthenticate_local` 从当前会话确定账户并轮换该账户的会话。刷新只更换凭据及更新 idle，保留原 auth_time、absolute deadline 和 group snapshot 的过期时间。

宿主每次管理操作提供窄 `ManagementPolicy`。组件在 PG 事务中锁定并加载当前账户、成员、会话、epoch、provider 状态后调用策略；实例、租户、主体绑定与再认证期限由组件检查。序列化 JSON 不能构造 AuthenticatedSession、ManagementContext 或 TrustedGroups。组只表达来源明确、有期限的认证事实，不成为产品权限结论。

参考宿主用配置的 bootstrap AccountKey 决定管理权限，并拒绝停用该账户或其成员关系。独立 Maintenance 权限仅执行每租户一次初始化和指定本地账户密码恢复；恢复推进 epoch，保留 enabled/member_active。没有在线角色提权票据。

HTTP DTO 由适配层私有持有。`router` 装配本地登录、会话及账户管理；`federated_router` 独立装配可选 OIDC/IdP 管理，宿主明确 merge。HTTP body 不接受服务端授权凭证。

会话保存签发时的 idle/absolute 策略，后续宿主配置变更影响新会话；旧会话继续受原期限约束。参考配置为 900/14400 秒。组保持 #2433 的 version、provider/issuer、snapshot、观察时间和硬过期语义；available、unavailable、expired 不混淆。

## 持久化与事件

schema owner 导出 fresh install 与有效权限 profile 授权函数；宿主决定数据库角色名和 RSS migration 顺序，独立配置 tenant fence。结构摘要校验、FORCE RLS、列级维护权限、PUBLIC/继承权限/GRANT OPTION 探测仍由组件执行。账户事件变更为 v3，移除角色字段；联合事件变更为 v2，移除 CLI 授权动作。session v1 形状不变。

所有成功凭据及远端测试报告只在本地事务提交确认后释放。NotStarted、RolledBack、RollbackFailed、CommitUnknown、Fenced 保持不同内部错误，未知提交不返回 cookie。OIDC 使用原有 openidconnect 校验及持久 state/nonce/PKCE、JIT、link、step-up 流程，远程请求不伪装为 PG 原子操作。

## 实施 DAG 与验证

主 agent 是所有代码、测试、文档 owner：领域类型/策略 → PG facade/schema/事务 → HTTP/参考宿主 → 当前测试与独立消费者 → PR/review/fix/交接。探索与 reviewer 可以并行，实施不派发。

已取得的 RED：新增 embedded core 测试在旧 API 上因缺少 InstanceId、SessionPolicy 和无角色构造而失败；实现后最初 3 项通过。持续回归保留原有 PG fault、并发锁序、OIDC 和组快照场景；内部密码/签发竞态测试移到 postgres 的私有测试模块，HTTP 与独立消费者只消费公开 facade。完整验证结果写入交付记录，不用本 ADR 的设计承诺代替运行证据。

独立消费者分本地、可选 OIDC 两种，必须各有 workspace/lock/target/PG，在仓库祖先配置之外执行；从产品 Git URL 和完整 revision 获取四个公开能力包，只运行公开 API。先提交生产实现 A，再固定 A 执行消费者并提交证据 B；验证 B 的生产源码没有漂移。OIDC 消费者使用真实 Keycloak，不能用 reference app 或 Hydra 充当组件依赖。

## 范围与交接

[#2436](https://dev.azure.com/shengming0923/rss/_workitems/edit/2436) 承接完整 reference app 部署、UI candidate、运维迁移及独立 T3；本次只保证参考宿主最小装配。MDM 迁移归 [#2437](https://dev.azure.com/shengming0923/rss/_workitems/edit/2437)，Web UI 归 [#2368](https://dev.azure.com/shengming0923/rss/_workitems/edit/2368)。不修改 MDM/Web，不引入新 MFA/passkey、多存储或 OAuth 授权服务器。

## ASP.NET Core Identity 能力对照

| 上游职责 | 本次对应 | 保留差异 / 范围 |
| --- | --- | --- |
| UserManager 账户操作 | Authority 创建/启停/成员/改密，Maintenance 初始化/恢复 | 角色和防锁死由宿主策略持有，不复制全套用户管理框架。 |
| SignInManager 登录及重新认证 | login_local / reauthenticate_local / Federation | facade 完成限流、验证及事务签发；宿主不拆拼流程。 |
| Store 持久化扩展 | 第一个正式 PG 实现及宿主 migration 接缝 | 不提前建立多数据库 Store/DI 框架；账户、会话和安全事件同事务。 |
| 宿主 authentication/authorization | AuthenticatedSession / 可组合 Axum Router / ManagementPolicy | 每请求读取当前权威状态；不采用 SecurityStamp 成功缓存窗口。 |
| 用户确认、邮件恢复、原生 TOTP/恢复码、Passkey | 本次不新增 | OIDC step-up 继续复用上游已验证 assurance；本地恢复是受控维护操作。 |

## 对标来源

- [ASP.NET Core v10.0.0 UserManager](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Identity/Extensions.Core/src/UserManager.cs)、[SignInManager](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Identity/Core/src/SignInManager.cs)：区分账户操作、登录流程与宿主策略；不复制 SecurityStamp 的缓存窗口。
- [openidconnect-rs verification](https://github.com/ramosbugs/openidconnect-rs/blob/b639b5d39eac6903238867aeb2b29326502e6b26/src/verification/mod.rs)：保留已选上游的令牌验证语义。
- [Axum State](https://github.com/tokio-rs/axum/blob/c59208c86fded335cd85e388030ad59347b0e5ae/axum/src/extract/state.rs)：宿主状态与 Router composition。
