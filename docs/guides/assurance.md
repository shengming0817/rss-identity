> 历史中央模式文档（基线 fa7019922162158704cc47c6ac7ad36a67c8ae5a）。下文的接口、命令与 schema 仅描述该历史版本，不适用于当前嵌入式组件，也不作为当前验收证据。当前用法见[嵌入指南](embedding.md)与[部署运维](../deployment/operations.md)。

# MFA assurance 与显式 step-up

Identity 验证并传递可信认证事实；管理员权限与 MDM 动作授权继续由既有 owner 判定，本功能不增加管理门禁。

## 部署批准

新配置中每个 OIDC provider 显式填写 `keycloak_totp: false|true`。只有确认锁定 Keycloak 使用 `deployment/keycloak-totp.json` 的 password + TOTP / ACR 2 profile 才设为 true。部署渲染器给新 realm 安装该 flow；已有 realm 由 Keycloak 管理员核验配置、用户 OTP 注册及当前 client，重复 import 不修复漂移。配置不创建默认用户或 OTP seed。

## HTTP

`POST /api/v1/tenants/{tenant}/oidc/{provider}/step-up`

body 与正常联合登录相同：`{"client_id":"identity-ui","return_target":"resume"}`。两个值必须来自当前服务的允许回跳表。请求必须携带当前 `__Host-identity-session` cookie、同源 Origin、`X-Identity-Request: 1`、当前会话的 `X-CSRF-Token`。无会话、错误租户、未批准 profile 或无效回跳均拒绝。

返回 `{"authorization_url":"..."}` 后由浏览器跳转 Keycloak。服务端持有 state/nonce/PKCE，浏览器不得改写认证要求、构造认证事实或自行兑换 code。成功通过唯一 `/api/v1/oidc/callback` 设置轮换后的 cookie，再返回已有回跳目标；没有新的兼容 callback 或成功查询参数。失败沿用安全错误页，不重试 code 或未知结果。

仅支持同一主体已存在的 provider 关联。未关联的本地账户须先完成既有显式关联流程；step-up 不按邮箱绑定、不创建账户。刷新中的同一 session 按当前 cookie 重验；退出、禁用、provider 变化和跨主体切换不能被回调覆盖。

## 消费事实

`/internal/v1/identity/validate` 与 `VerifiedIdentity` 继续使用 `auth_time/amr/acr`：

- `acr=mfa`：批准 profile 的已验证认证；`auth_time` 来自上游真实认证时间。
- `acr=unspecified`：没有足够 MFA 证据；不表示认证失败。
- `amr`：实际可验证的已知方法；Keycloak 未提供时为空。不能用数组非空或本地口令恢复推断 MFA。

普通联合登录若未提供认证时间，低强度结果沿用中央会话建立时间；只有 MFA 或显式重新认证必须具有上游时间。会话续期不刷新认证时间。产品按动作判断允许强度和新鲜度，仍必须逐请求在线验证；旧 grant 不会自动升级为新 session 的 MFA。

Hydra v26.2.0 的标准 ID Token 中 `auth_time` 由 Hydra 登录处理时刻持有，不能作为上游 MFA 新鲜度。其标准 `acr` 固定为 `unspecified`，不投影上游 AMR；完整 `acr/amr/auth_time` 仅由上述在线入口从同一中央会话返回。产品需要 MFA 或新鲜度时消费在线结果，不从 ID Token 时间推断。

中央前端按钮与展示由 rss-web [#2368](https://dev.azure.com/shengming0923/rss/_workitems/edit/2368) 消费；实际双仓版本和联合运行结果以该项交付记录为准。

验证：`make test-federated` 包含真实 password/TOTP、浏览器降级和换用户拒绝；`make test-downstream` 验证延迟复用 MFA 会话时 Hydra ID Token 不宣称 MFA、在线 client 保留真实强度/认证时间；`make test-pg` 覆盖配置/撤销竞态、事件和未知提交。

部署批准的 profile identity 由 OIDC adapter 生成并持久保存在 provider 上，不由租户或浏览器提供。应用在单副本维护窗口启动时、监听入口开放之前同步当前部署批准；指纹变化或绑定退出在既有租户锁和事务中推进 provider config_version/revocation_epoch，并写 provider_updated 事件。版本冻结在途 attempt，epoch 撤销既有联合 session 与关联 grant；恢复旧批准也推进 epoch，不会复活旧会话。退出绑定同时停用 provider，重新批准不会自动启用。秘密轮换不改变 profile identity。profile 同步未知提交或失败时启动不开放入口；不支持多个不同批准配置的副本同时运行。

规范化 ACR/AMR 的唯一闭集位于 contracts，core/adapter/client 直接消费类型；JSON wire 拼写保持 unspecified/mfa 与 mfa/otp/pwd，不保留旧字符串 API。当前前端 capability 发现与按钮通过以下唯一会话投影消费。

## 浏览器当前会话投影（#2368）

`GET /api/v1/tenants/{tenant}/session/security` 使用同源中央 cookie，返回 `session_id`、
`authentication: {auth_time, acr, amr}` 和 `eligible_step_up_providers: [{provider_id, label}]`。
响应为 no-store；无有效会话、错租户或撤销后的 proof 均拒绝。认证时间与在线验证使用同一持久 assurance，
不把中央 session 建立时间误称为上游 MFA 时间；普通弱认证缺少上游时间时沿用既有 fallback 语义。

Federation 在同一次租户锁定读取中重检会话及当前主体关联，仅列出 issuer 匹配、启用、
profile 已同步并支持 step-up 的 provider。查询不探测远端健康；列表为空不等于身份认证失败。
资格查询与 step-up POST 前后使用同一检查；上游网络请求不持有数据库锁，callback 仍重检
版本、issuer/subject、会话和撤销状态。浏览器的旧列表不能绕过任何后端检查。

`UpstreamOidc::assurance_profile` 直接返回 `AssuranceProfile {fingerprint, supports_step_up}`；
两项由同一次部署批准判断派生，全部 adapter 与消费者同步替换，无旧返回类型包装。
持久 fingerprint 的计算与 schema 均不变。该内部描述不直接成为浏览器 wire 或授权证明。

UI 仅在安全页面需要时读取，绑定 session ID 和请求代际；续期、退出、页面切换使旧投影失效。
实际浏览器 T2 由 rss-web 的 `test:identity:joint` 驱动本仓 `make test-ui`，使用真实 PG、
公开 Router、HTTPS gateway 和固定 Keycloak fixture；不替代 #2366 产品 MFA T3。
