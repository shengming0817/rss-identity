# Instance-local HTTP v2

`rss-identity-http-axum` 提供可挂载 Router。宿主提供 canonical HTTPS origin、TLS 和可信代理/连接来源；不能直接信任浏览器转发头。仅 `/api/v2`，旧中央/internal/platform/CLI/v1 路由不存在。应用 JSON 字段使用 camelCase，旧 snake_case 字段拒绝；OIDC callback 标准参数 `error_description` / `error_uri` / `session_state` 保留上游协议拼写。DTO 留在 HTTP adapter 内，浏览器响应不能作为宿主 Rust 认证证明。

## 本地会话

以下路径以 `/api/v2/tenants/{tenant}` 为前缀。tenant、principal、session 标识为非 nil UUID。

| 方法 / 路径 | 请求 / 行为 |
| --- | --- |
| POST `/login` | `{login,password}`；完整验证、签发，已有有效 cookie 时需 CSRF 才能替换。 |
| GET `/session` | 当前身份/会话，不续期。 |
| POST `/session/reauthenticate` | `{password}`；绑定当前账户，不接受 login/角色字段，成功旋转会话。 |
| POST `/session/refresh` | 当前 cookie + CSRF；旋转，保留原 authTime/绝对期限。 |
| POST `/session/logout` | 撤销当前会话，清 cookie。 |
| POST `/sessions/logout-all` | 撤销账户全部会话，清 cookie。 |
| GET `/sessions` | 有界分页；`cursor`/`limit`。 |

成功登录/查询/refresh/重新认证响应：

```json
{"identity":{"principalId":"22222222-2222-4222-8222-222222222222","hasLocalPassword":true},"session":{"id":"33333333-3333-4333-8333-333333333333","authTime":1800000000,"idleExpiresAt":1800000900,"absoluteExpiresAt":1800014400},"csrfToken":"opaque"}
```

bearer 仅通过 `Set-Cookie: __Host-identity-session=...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=...` 传递。响应 no-store。写请求检查精确 Origin；登录、重新认证和管理写入要求 `x-identity-request: 1`，已认证修改须 `x-csrf-token`。拒绝重复/畸形凭据头。日志不得记录 Cookie、Set-Cookie、密码、CSRF 或回调参数。

## 账户管理

同一 tenant 前缀：GET/POST `/accounts`（分页 / `{login,password}`）；POST `/accounts/{principal}/enabled`、`/membership`（`{enabled}`）；POST `/accounts/{principal}/password`（`{password}`）；POST `/account/password`（`{currentPassword,password}`）。管理角色与防锁死由宿主 ManagementPolicy 提供，每次事务重查；没有 administrator 字段/路由。

## 可选 OIDC Router

仅合并 `federated_router` 后可用。同一 tenant 前缀：GET `/login-options`；POST `/oidc/{provider}/login`（`{returnTarget}`）、`/link`（重新认证与受控目标）、`/step-up`（受控目标）；GET `/session/security`。后者提供 `authentication:{authTime,acr,amr}` 和 `eligibleStepUpProviders:[{providerId,label}]`；普通 OIDC 未提供认证时间时 `authTime:null`，不回填 iat。它只提供认证事实，不返回管理角色。

唯一回调 GET `/api/v2/oidc/callback`：state/code/iss 与独立 HttpOnly browser cookie 绑定；拒绝重放、过期、不匹配和不确定结算，不释放 cookie。returnTarget 是宿主白名单键，不接受任意 URL；不再接受中央 clientId。

IdP 管理：GET/POST `/providers`、PUT `/providers/{provider}`、POST `/providers/{provider}/enabled`、`/test`。写入使用 expectedVersion 乐观并发；创建初始配置不需要该字段。凭据只写，加密存储，不返回明文。provider 设置为 `{issuer,clientId,redirectUri,scopes,claims:{email,groups,departmentSnapshot},jit}`；只写凭据字段为 `clientSecret` / `caPem`，与领域持久化形状分别由各自 owner 持有；资源授权仍归宿主。

部门配置 `departmentSnapshot` 为省略/null（禁用）或 `{claim,maxAgeSeconds}`，对象两字段均必填，期限为 1–300 秒；输出统一包含 `departmentSnapshot`。JSON 使用 `maxAgeSeconds`，拒绝旧 department 字段、snake_case、字符串简写及缺失期限。修改映射或期限使用同一完整 update/expectedVersion/credentials 流程，推进版本并撤销旧会话及在途认证。完整部门树快照只来自已验证 ID Token，不能通过登录/回调/会话 DTO 提交；浏览器会话响应不增加部门授权证明。

## 失败与可信边界

OIDC callback 的错误投影由统一转换函数保留进程内 `HttpFailure` 与其它 response extensions；浏览器只收到原有 303 和闭集 reason，不包含内部错误内容或凭据。

外部错误为 `{code}`：malformed_request、invalid_credential、csrf_rejected、rate_limited、configuration_changed、insufficient_privilege、reauthentication_required 等闭集；基础设施失败为 503 identity_unavailable。内部 `HttpFailure` response extension 保留安全 settlement 分类，不暴露 SQL/IdP 原文，也不代表写入可自动重试。

HTTP 宿主资源请求统一调用 `authenticate_request`：用户活动选择 `SessionActivity::Active`，组件先验证严格 cookie、同源、请求标记和 CSRF，再读取权威状态并延长 idle；被动查询选择 `Passive`，不续期。宿主获得 `AuthenticatedSession` 后才执行资源授权，组事实通过 `VerifiedGroups` 借用；详细来源、过期和授权边界见 [嵌入指南](../guides/embedding.md)。HTTP JSON 只是前端交互投影。

底层 `Authority::authenticate_session` / `Authority::inspect_session` 仅供已建立请求保护的可信服务端 adapter 调用。前者验证并延长 idle，不改变原 absolute deadline；HTTP 宿主使用上述统一入口及显式活动策略，不能让后台心跳无限续期。`inspect_session` 只读验证，用于登录替换前检查、浏览器 GET session 和不应续期的被动查询。HTTP POST refresh 显式续期并旋转凭据；两种验证入口都重新检查权威状态。

## 参考宿主资源

`GET /api/identity-host/v1/tenants/{tenant}/context` 由 app/identity 持有，通过 HTTP adapter 的公开 `authenticate_request` 选择 `SessionActivity::Passive`，严格读取同一 cookie 并权威验证，不续期。响应为 `{tenantId,principalId,sessionId,navigation:{manageAccounts,manageProviders}}`，no-store；导航由 BootstrapPolicy 派生，仅作展示。组件管理事务始终重新验证会话与宿主策略。UI 静态配置使用网关固定同源 `/api/identity-host/v1/config.json`，严格 `{canonicalOrigin,oidcEnabled}`；并非动态能力发现。


`GET /api/identity-host/v1/tenants/{tenant}/mfa-example` 复用同一被动请求认证，检查本次 `AuthenticatedSession::assurance()`。只接受 `acr=mfa`、非空认证时间及 `0 <= now-authTime < 300` 秒；未来时间、缺失或过期事实返回 403 `reauthentication_required`，无效会话为 401，权威存储不可用为 503。成功返回 `{tenantId,principalId,sessionId,authentication:{acr,authTime}}`；全部响应 no-store，无 Set-Cookie，不延长 idle。宿主服务端时钟必须正确。此固定示范策略不改变账户/IdP 管理授权，也不由浏览器提供 MFA 事实。
