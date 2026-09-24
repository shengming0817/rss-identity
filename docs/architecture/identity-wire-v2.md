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

请求/响应 DTO 以 [HTTP adapter](../../crates/identity-http-axum/src/lib.rs) 的类型与路由为准；[会话接入测试](../../crates/identity-http-axum/tests/session_http.rs) 提供实际请求示例。

bearer 仅通过 `Set-Cookie: __Host-identity-session=...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=...` 传递。响应 no-store。写请求检查精确 Origin；登录、重新认证和管理写入要求 `x-identity-request: 1`，已认证修改须 `x-csrf-token`。拒绝重复/畸形凭据头。日志不得记录 Cookie、Set-Cookie、密码、CSRF 或回调参数。

## 账户管理

同一 tenant 前缀：GET/POST `/accounts`（分页 / `{login,password}`）；POST `/accounts/{principal}/enabled`、`/membership`（`{enabled}`）；POST `/accounts/{principal}/password`（`{password}`）；POST `/account/password`（`{currentPassword,password}`）。管理角色与防锁死由宿主 ManagementPolicy 提供，每次事务重查；没有 administrator 字段/路由。

## 可选 OIDC Router

仅合并 `federated_router` 后可用。同一 tenant 前缀：GET `/login-options`；POST `/oidc/{provider}/login`（`{returnTarget}`）、`/link`（重新认证与受控目标）、`/step-up`（受控目标）；GET `/session/security`。后者提供 `authentication:{authTime,acr,amr}` 和 `eligibleStepUpProviders:[{providerId,label}]`；普通 OIDC 未提供认证时间时 `authTime:null`，不回填 iat。它只提供认证事实，不返回管理角色。

唯一回调 GET `/api/v2/oidc/callback`：state/code/iss 与独立 HttpOnly browser cookie 绑定；拒绝重放、过期、不匹配和不确定结算，不释放 cookie。returnTarget 是宿主白名单键，不接受任意 URL；不再接受中央 clientId。

IdP 管理：GET/POST `/providers`、PUT `/providers/{provider}`、POST `/providers/{provider}/enabled`、`/test`。写入使用 expectedVersion 乐观并发；创建初始配置不需要该字段。凭据只写，加密存储，不返回明文。provider 管理字段由 [provider 管理适配器](../../crates/identity-http-axum/src/provider_management.rs) 持有。部门映射须显式启用并给出有界期限，省略/null 表示禁用；旧标量字段拒绝。更新映射和期限经过同一并发版本与凭据更新流程，撤销旧会话及在途认证。完整快照只来自签名 ID Token，浏览器响应不成为部门授权证明。


## 失败与可信边界

OIDC callback 的错误投影由统一转换函数保留进程内 `HttpFailure` 与其它 response extensions；浏览器只收到原有 303 和闭集 reason，不包含内部错误内容或凭据。

外部错误为 `{code}`：malformed_request、invalid_credential、csrf_rejected、rate_limited、configuration_changed、insufficient_privilege、reauthentication_required 等闭集；基础设施失败为 503 identity_unavailable。内部 `HttpFailure` response extension 保留安全 settlement 分类，不暴露 SQL/IdP 原文，也不代表写入可自动重试。

HTTP 宿主资源请求统一调用 `authenticate_request`：用户活动选择 `SessionActivity::Active`，组件先验证严格 cookie、同源、请求标记和 CSRF，再读取权威状态并延长 idle；被动查询选择 `Passive`，不续期。宿主获得 `AuthenticatedSession` 后才执行资源授权，组事实通过 `VerifiedGroups` 借用；详细来源、过期和授权边界见 [嵌入指南](../guides/embedding.md)。HTTP JSON 只是前端交互投影。

底层 `Authority::authenticate_session` / `Authority::inspect_session` 仅供已建立请求保护的可信服务端 adapter 调用。前者验证并延长 idle，不改变原 absolute deadline；HTTP 宿主使用上述统一入口及显式活动策略，不能让后台心跳无限续期。`inspect_session` 只读验证，用于登录替换前检查、浏览器 GET session 和不应续期的被动查询。HTTP POST refresh 显式续期并旋转凭据；两种验证入口都重新检查权威状态。

## 参考宿主资源

参考宿主提供同源 UI 配置、当前上下文及 MFA 示范资源，由 [宿主 HTTP 模块](../../app/identity/src/context.rs) 持有。导航只是展示，管理事务仍重新授权。MFA 资源以当前请求的可信 assurance 判定，缺失/未来/过期事实要求重新认证，不接受浏览器提供的 MFA 结论。

这些只读资源不续期、不签发 cookie，并使用 no-store；实际策略通过宿主查询命令读取。前端接口与业务权限由对应产品维护，不能将示范资源扩展成通用授权协议。
