# Instance-local HTTP v2

`rss-identity-http-axum` 提供可挂载 Router。宿主提供 canonical HTTPS origin、TLS 和可信代理/连接来源；不能直接信任浏览器转发头。仅 `/api/v2`，旧中央/internal/platform/CLI/v1 路由不存在。DTO 留在 HTTP adapter 内，浏览器响应不能作为宿主 Rust 认证证明。

## 本地会话

以下路径以 `/api/v2/tenants/{tenant}` 为前缀。tenant、principal、session 标识为非 nil UUID。

| 方法 / 路径 | 请求 / 行为 |
| --- | --- |
| POST `/login` | `{login,password}`；完整验证、签发，已有有效 cookie 时需 CSRF 才能替换。 |
| GET `/session` | 当前身份/会话，不续期。 |
| POST `/session/reauthenticate` | `{password}`；绑定当前账户，不接受 login/角色字段，成功旋转会话。 |
| POST `/session/refresh` | 当前 cookie + CSRF；旋转，保留原 auth_time/绝对期限。 |
| POST `/session/logout` | 撤销当前会话，清 cookie。 |
| POST `/sessions/logout-all` | 撤销账户全部会话，清 cookie。 |
| GET `/sessions` | 有界分页；`cursor`/`limit`。 |

成功登录/查询/refresh/重新认证响应：

```json
{"identity":{"principal_id":"22222222-2222-4222-8222-222222222222","has_local_password":true},"session":{"id":"33333333-3333-4333-8333-333333333333","auth_time":1800000000,"idle_expires_at":1800000900,"absolute_expires_at":1800014400},"csrf_token":"opaque"}
```

bearer 仅通过 `Set-Cookie: __Host-identity-session=...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=...` 传递。响应 no-store。写请求检查精确 Origin；登录、重新认证和管理写入要求 `x-identity-request: 1`，已认证修改须 `x-csrf-token`。拒绝重复/畸形凭据头。日志不得记录 Cookie、Set-Cookie、密码、CSRF 或回调参数。

## 账户管理

同一 tenant 前缀：GET/POST `/accounts`（分页 / `{login,password}`）；POST `/accounts/{principal}/enabled`、`/membership`（`{enabled}`）；POST `/accounts/{principal}/password`（`{password}`）；POST `/account/password`（`{current_password,password}`）。管理角色与防锁死由宿主 ManagementPolicy 提供，每次事务重查；没有 administrator 字段/路由。

## 可选 OIDC Router

仅合并 `federated_router` 后可用。同一 tenant 前缀：GET `/login-options`；POST `/oidc/{provider}/login`（`{return_target}`）、`/link`（重新认证与受控目标）、`/step-up`（受控目标）；GET `/session/security`。后者只提供当前 auth_time/acr/amr 和可用 step-up provider，不返回管理角色。

唯一回调 GET `/api/v2/oidc/callback`：state/code/iss 与独立 HttpOnly browser cookie 绑定；拒绝重放、过期、不匹配和不确定结算，不释放 cookie。return_target 是宿主白名单键，不接受任意 URL；不再接受中央 client_id。

IdP 管理：GET/POST `/providers`、PUT `/providers/{provider}`、POST `/providers/{provider}/enabled`、`/test`。写入使用 expected_version 乐观并发；创建初始配置不需要该字段。凭据只写，加密存储，不返回明文。provider 设置与上游协议字段见 core 的 ProviderSettingsInput；资源授权仍归宿主。

## 失败与可信边界

外部错误为 `{code}`：malformed_request、invalid_credential、csrf_rejected、rate_limited、configuration_changed、insufficient_privilege、reauthentication_required 等闭集；基础设施失败为 503 identity_unavailable。内部 `HttpFailure` response extension 保留安全 settlement 分类，不暴露 SQL/IdP 原文，也不代表写入可自动重试。

宿主业务请求直接通过 `inspect_session` 生成可信认证结果，组事实通过 `VerifiedGroups` 借用；详细来源、过期和授权边界见 [嵌入指南](../guides/embedding.md)。HTTP JSON 只是前端交互投影。
