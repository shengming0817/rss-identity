> 历史决策记录；中央模式相关决策由 [#2435 ADR](202609170001-2435-embedded-authentication.md) 替换。仍适用的安全机制以当前源码与验证为准。

# I09：可信认证事实与原生恢复接缝

本项一个实现 PR 闭合 T1/T2；新增产品 T3 独立交付。I09 的历史初始版本为 v7；当前按 #2427 使用 v8。没有旧数据，旧库只拒绝，不自动清理，无升级、降级、双读或兼容配置。#2339 在目标冻结及适用产品验收完成前保持未完成。

## Assurance

首版唯一 MFA profile 是锁定 Keycloak 的 password + TOTP、ACR `2`。`keycloak_totp` 由部署 owner 在 issuer/client/tenant 的完整绑定内配置为可信解释（#2427 删除 IdP 接入审批及 secret_ref），不能由租户 ProviderSettings 或浏览器修改。渲染器使用 `deployment/keycloak-totp.json` 给新 realm 安装 LoA1/password、LoA2/required OTP 的条件 flow；无用户、口令或 OTP seed。已有 realm 不以重新 import 代替管理员核验。

`AuthenticationMode` 区分 Login、Reauthenticate、StepUp；不再用 reauth bool。正常登录不强制 MFA，关联再认证不推断 MFA。step-up 使用 `prompt=login`、`max_age=0`、`acr_values=2`，请求模式随现有 OIDC transaction 持久化；callback 即使收到浏览器降低强度后的有效 token，也必须满足原持久要求。

openidconnect 先验证签名、issuer、audience、nonce；adapter 仅从已验证 token 提取事实。`Assurance` 保存规范化的 `auth_time/acr/amr`，其构造和 DB hydration 都拒绝非法值。只有已批准 profile 的 ACR 2 且有认证时间才能映射 `mfa`；其它正常登录为 `unspecified`。AMR 仅保留已验证的 pwd/otp/mfa 方法，缺失为空，不按 ACR 编造方法。step-up 额外以 PG 锁后时钟验证认证时间不早于 attempt.created−30 秒、不晚于 now+30 秒；普通旧 SSO 事实不因此冒充新认证。

step-up 复用 Login purpose、replacement_session 和唯一 callback，必须当前会话、Origin/CSRF、同一已关联主体；不 JIT、不 linking。回调重检会话、账户/member epoch、provider 版本，原子消费事务、轮换 session、写 stepped_up 事件。CommitUnknown 不返回新 cookie。不增加管理操作门禁。

会话创建时刻继续拥有 idle/absolute lifetime，认证时间独立存在 auth_facts 中。共用 session lookup 解码事实，在线下游从同一事实投影，Rust client 接受闭合的 `unspecified/mfa` 和已知 AMR。Keycloak ACR 2 的请求/响应映射由 OIDC adapter 单独持有，core 只验证规范化事实。Hydra v26.2.0 login accept 不接受上游 auth_time；标准 ID Token 固定 unspecified/无上游 AMR，避免把 Hydra 当前时间与旧 MFA 强度组合。完整 assurance 只从在线 validate/Rust client 消费（ref: ory/hydra v26.2.0 oauth2/handler.go:1315–1322）。新会话不会提升指向旧 session 的 grant；产品仍需在线验证并自行决定动作要求和认证新鲜度。

## 恢复与轮换

采用 PG 原生 pg_basebackup/pg_verifybackup 与真实恢复验证；部署负责停写、隔离、选取完整切点、保管配置/密钥、核验后开放。Identity/Hydra/Keycloak 在单一集群中仍保持独立数据库/schema owner。没有独立恢复产品 binary、seal、库外激活工作流或自动放行逻辑。#2427 的外部 storage target/lineage 与单一 deployment generation 持有恢复 fencing，不能从恢复数据库反填期望代际。

恢复严格回到所选备份切点；后续禁用、改密或撤销不会凭空保留。T2 同时验证当前切点拒绝旧凭据、历史切点确实带回历史事实；后一场景不得作为生产开放证明。无法证明所需安全状态被包含时，部署保持隔离。增加库内 epoch 不能替代完整恢复材料。

应急账户维持已有 enabled/emergency 语义，凭据独立封存、使用后立即维护改密并验证失效，不扩大 maintenance 权限。普通服务秘密采用停机同步替换；state key 单 current key，替换终止在途登录。Hydra 原生 system/cookie keyring 分域、新钥优先，旧钥按实际加密数据依赖退出；不自行迁移 Hydra 密文或凭时间删除旧钥。Identity 的 IdP 凭据另由 #2427 的 AES-GCM/keyring 及有界 owner rekey 持有。

## 验证与限制

T1 证明 claims/配置/时钟边界；真实 PG、Keycloak TOTP 和 Hydra T2 证明事务、回调、下游、原生恢复及轮换。`measure-capacity` 是有限组件测量，不进入 CI 性能门禁；记录资源/架构、源码/lock、请求数、成功/失败和耗时。清理指标只代表一次失效处理，不等于安全窗口末端的最终删除。

当前未冻结真实生产容量、RPO/RTO；单次本机组件结果不证明其它执行环境或生产 SLO。实际浏览器 MFA、恢复后重新开放与秘密注入/轮换 join 由独立 T3 持有。

## Primary upstream

- [openidconnect 4.0.1 verification](https://github.com/ramosbugs/openidconnect-rs/blob/b639b5d39eac6903238867aeb2b29326502e6b26/src/verification/mod.rs)：默认 ACR/auth_time verifier 不负责业务 step-up 判定。
- [Keycloak 26.7.3 export](https://github.com/keycloak/keycloak/blob/26.7.3/docs/guides/server/importExport.adoc)：realm export 不包含持久 session 和 revoked token。
- [Kanidm v1.9.4 restore](https://github.com/kanidm/kanidm/blob/v1.9.4/server/core/src/lib.rs#L429-L486)：离线恢复、事务及内部一致性核验，不构成外部 freshness authority。
- [PostgreSQL 17 pg_verifybackup](https://www.postgresql.org/docs/17/app-pgverifybackup.html)：manifest 校验不能替代实际恢复测试。
- [Hydra key rotation](https://www.ory.com/docs/hydra/self-hosted/secrets-key-rotation)：旧数据不自动重新加密，原生列表的第一项用于新加密。

可信 assurance profile identity 由 OIDC adapter 按部署 owner 配置生成并持久保存在 provider 上，不由租户或浏览器提供；它只决定经过验证的 ACR/AMR 如何解释，不批准 IdP 接入。应用在单副本维护窗口启动时、监听入口开放之前同步该解释；指纹变化在既有租户锁和事务中推进 config_version/revocation_epoch 并写 provider_updated 事件。退出或恢复解释都会撤销旧认证状态，但不控制 provider.enabled；IdP 接入、配置、凭据和启停由租户管理员或系统域平台管理员管理，不设部署审批或 IP/CIDR 限制。凭据更新独立推进 credential_version 及认证状态版本。同步未知提交或失败时启动不开放入口，不支持多个不同 assurance 配置的副本同时运行。

规范化 ACR/AMR 的唯一闭集位于 contracts，core/adapter/client 直接消费类型；JSON wire 拼写保持 unspecified/mfa 与 mfa/otp/pwd，不保留旧字符串 API。当前前端 capability 发现与按钮继续由 #2368 联合交付。
