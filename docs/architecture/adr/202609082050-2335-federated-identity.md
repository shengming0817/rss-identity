# #2335 租户 IdP 与联合身份

状态：I05 实现决定。按用户决定在一个 PR 内原子替换旧接缝，不保留旧 API/schema 兼容；实际 SHA、lock、provider digest 与 T1/T2 结果随 PR 记录。UI、Hydra bridge、生产 binary/TLS 装配与产品 T3 分别归 I07/I06/I08/T33。

## 账户和配置唯一 owner

`accounts` 只持有账户状态；`local_credentials` 以 tenant/principal 为一对零或一的本地密码 owner。纯联合账户没有本地登录名或假密码。auth_epoch 统一失效密码候选、会话和关联证明，成员 epoch 保留；移除重复 credential_version。账户事件切 `identity.account.security` V2，session 事件保持 V1，新增 federation 事件 V1。没有旧事件生产器或旧 schema reader。

账户/成员/凭据快照和所有写操作使用同一 tenant guard，避免独立凭据表与账户代际的并发混读。只有 active、administrator 且存在本地凭据的账户计入最后本地管理员保障；维护恢复只能更新已有本地管理员密码，不能给联合账户增加密码。

每个 tenant/provider 一行当前配置，含 enabled、单调 config_version 与 revocation_epoch。issuer 创建后不可修改，换 issuer 显式创建新 provider。其它编辑提升 config_version；从 enabled 转为 disabled 额外提升 revocation_epoch；重新启用不回退。没有历史配置表、自动迁移、配置删除或测试激活状态机。

ProviderSettingsInput 仅作为编辑 DTO；构造/反序列化均产生字段私有的已验证 ProviderSettings，issuer/client 使用现有值对象，注入 adapter 不能绕过核心校验。配置由租户管理员自助提交；callback 固定为部署 origin 的唯一 OIDC callback。IdP 不再需要部署或 IP 范围批准，凭据独立绑定 tenant/provider/version 加密保存。

#2337/#2427 后的管理只接受 AuthenticatedSession，并在事务内复核业务租户管理员或系统域平台角色。Federation 持有管理门面；Authority 包内持有配置、凭据及事件原子写入。create/update 接受只写 client secret 和可选 CA；list/disable 不解密秘密。连接测试检查 TLS/discovery/JWKS 及协议能力，核对前后权限/版本并结算审计；它不证明 secret 可兑换真实 code。数据库外 keyring 加密凭据，变更配置/凭据推进版本并撤销旧认证状态，不再存在 secret_ref 或静态批准的备用路径。

## 浏览器事务

服务构造时注入唯一受信 UpstreamOidc port、部署 state key 和静态 client/return-target 注册集合。只有生产 HttpOidc adapter 的验证结果进入联合登录结算；回调不能提交 subject/claims JSON 作为身份。

旧内存 LoginAttempt 已删除。协议 adapter 只构造请求/兑换/验证；PG 唯一持有 durable attempt。state 的 canonical base64url payload 为版本字节、purpose 字节、tenant UUID 字节、256-bit 随机 attempt id，随后是 HMAC-SHA256。MAC 域包含固定协议域及长度编码的部署 origin；独立 32 字节密钥由部署注入，不复用 client/session secret。先验证完整编码和 MAC，再解析可信 tenant、进入 tenant-bound PgRuntime。HMAC 不提供租户隐私；TenantId 在此协议中不是秘密。单 current key 轮换会终止全部旧在途登录，不保留 key ring。

`__Host-identity-oidc-browser` 是独立随机浏览器 cookie，Secure/HttpOnly/Lax/Path=/、无 Domain；已有值不在每次 begin 覆盖。首次无 cookie 时，消费方先完成一次 begin 再并发其它 flow。数据库只保存 state/browser 的摘要，nonce/verifier 只存在于受限短期事务行和内存，不进入事件或日志。

登录事务绑定 provider/config_version、purpose、浏览器、目标 client/受控回跳、可选原会话/link intent，默认 5 分钟。开始路径复用账户尝试预算；临时行每次最多清理 128 条过期记录，事务行上限 10000。未知 tenant/provider 不创建登录 authority。

回调：MAC+browser+必需 RFC 9207 iss（领取前检查与 exact issuer 相同） → PG 锁内领取 pending attempt、读取 exact version 配置、清除 nonce/verifier 并 confirmed commit → 有界远程兑换 → PG 最终复核配置版本/启用状态、attempt/purpose/期限和原认证状态 → 原子写入业务与安全事件。配置编辑在领取前或兑换中发生都拒绝，不重读 latest 偷换 authority。code/远端请求不能回滚；领取后失败、中断或提交未知均需新登录，不重新兑换。只有 confirmed commit 返回中央 cookie。成功回跳 URL 来自保存的注册目标，并由当前部署注册集合复核。

## JIT、关联与会话来源

JIT 默认关闭；显式启用后，未知外部键 `(tenant,provider,issuer,subject)` 原子创建新账户、有效普通成员、关联、session 和事件。已存在但失效的账户/成员拒绝，不自动恢复。邮箱仅作属性，即使 email_verified=true 也不查询邮箱合并账户。groups 有界规范化并记录 config_version 作为 mapping_version；不生成 MDM 资源权限。

显式关联必须有当前 session、Origin/CSRF 保护和原账户的新认证。本地账户重新验证本人密码；纯联合账户固定原 session 的 exact external identity，用 prompt=login/max_age=0 重新认证并检查 auth_time（与本轮请求比较，允许 30 秒上游时钟偏差），之后才启动目标 provider 认证。

link stage 使用闭合集合与带预期前态的推进操作。link intent 绑定 principal、session ID、auth/member epoch、browser、原认证来源、目标 provider/version 和总期限。cookie digest 不作为长期 intent 身份：正常 refresh 的新 cookie 可继续；旧 cookie、current/all logout、禁用/成员变化、source provider 撤销都使关联失败。两阶段复用同一 OIDC attempt 机制，不新增 session 授权票据。目标 key 属于本人时报告 already-linked；属于别人时报告不泄漏归属的 conflict，不合并账户。

成功关联推进 auth_epoch、创建新 session 并写事件；新 session 来源继承本轮原账户重新认证（密码为 local，联合为原 identity）。联合 session 保存 external_identity_id、provider epoch 和有界 claims 快照。每次认证/刷新/列表统一校验来源，provider 停用永久失效其旧 session；重新启用不复活，本地 session 不受影响。普通配置编辑不比较 session config_version，不撤销既有会话。不声明 Keycloak/Hydra 全局退出。

## 结算、权限与验证

所有账户/JIT/关联/session 和必要事件通过原有 PgRuntime/Outbox 结算，单事务事件批次有界；没有独立池或第二套 commit/rollback 实现。保留 NotStarted、RolledBack、RollbackFailed、CommitUnknown 和 Fenced；失败不释放成功凭据。新表全部 FORCE tenant RLS。schema version 4 只支持显式开发库重建。

启动校验 schema 完整结构摘要（列/约束/index/RLS/trigger/function）及独立的精确有效权限/角色检查。结构摘要由 `hack/schema_signature.py` 在固定 PG 上安装唯一 migration 生成；源变更必须一起更新 migration、摘要和行为测试，摘要不是另一份迁移定义。运行漂移拒绝，维护角色不获得 session/federation 表权限。

T1 证明类型/编码/claims；真实 PG 证明并发、重启、原子事件和未知提交；`test-federated` 使用固定 Keycloak HTTPS + PG + in-process Axum 证明 JIT/关联/cookie 接缝和 TLS/egress；原有 Keycloak/Hydra protocol carrier 保留同一 adapter 的负向回归。

来源：openidconnect 4.0.1 `src/verification/mod.rs` @ b639b5d39eac6903238867aeb2b29326502e6b26；RustCrypto hmac 0.12.1；固定 RSS bf5dd1350997d01aa834094a3347fce30247814e `transaction.rs` 的 tenant-bound local_tx 与私有 pool。没有新增跨租户 SECURITY DEFINER、全局 locator 或原始 SQL 连接旁路。

当前系统域与自助 IdP 威胁边界由 [#2427/#2428 ADR](202609130900-2427-platform-onboarding.md) 补齐；独立可信 assurance profile 只解释验证后的 ACR/AMR，不决定 IdP 准入。
