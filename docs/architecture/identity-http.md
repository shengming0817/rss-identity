# Instance-local HTTP v1

`rss-identity-http-axum` 提供可挂载 Router。宿主提供 canonical HTTPS origin、TLS 和可信代理/连接来源；不能直接信任浏览器转发头。仅 `/api/v1/identity`，旧中央/internal/platform/CLI、HTTP V2 及历史 V1 路由不存在。应用 JSON 字段使用 camelCase，旧 snake_case 字段拒绝；OIDC callback 标准参数 `error_description` / `error_uri` / `session_state` 保留上游协议拼写。DTO 留在 HTTP adapter 内，浏览器响应不能作为宿主 Rust 认证证明。

`router` 与 `federated_router` 保持现有公开签名，各自将相对路由挂载到固定 `/api/v1/identity`，宿主直接 merge；不得再次添加该前缀。请求边界通过 OriginalUri 检查完整路径及 8192 字节 URI 上限，callback 的 HEAD 返回 405。参考宿主资源独立使用 `/api/v1/identity-host/...`。

## 本地会话

以下路径以 `/api/v1/identity/tenants/{tenant}` 为前缀。tenant、principal、session 标识为非 nil UUID。

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

同一 tenant 前缀：GET/POST `/accounts`（目录查询 / `{login,password}`），GET `/accounts/{principal}` 读取完整账户；POST `/accounts/{principal}/enabled`、`/membership`（`{enabled}`）；POST `/accounts/{principal}/password`（`{password}`）；POST `/account/password`（`{currentPassword,password}`）。管理角色与防锁死由宿主 ManagementPolicy 提供，每次事务重查；没有 administrator 字段/路由。

账户目录接受 `filter/sort/fields/limit/cursor`；字段与操作符由 `identity-core::directory::AccountQuery` 定义。页大小默认 50、最多 100，排序追加主体 ID。投影行只含所选字段，编辑先读取完整详情。查询姓名、邮箱或资料状态必须显式指定 `source=local` 或确切 IdP UUID；不会混合不同来源。部门 exact/subtree 条件也使用指定 IdP，每个账户在自身完整部门树中匹配。资料与部门的筛选、排序和输出均单独调用宿主管理授权，账户目录权限不隐含资料读取权限。

部门目录取该来源最新成功接受的登录事实，再判定来源、代际和有效期；缺失、无效或过期不回退旧观察。登出不删除仍在期限内的目录观察，明确空成员与未知状态分别表达。这些目录数据不代替当前会话绑定的认证与授权事实。游标是不透明、会话及查询绑定的值，旧账户 UUID 游标已退出；`409 account_cursor_invalidated` 后由用户显式从首页重查。会话列表继续使用自身固定顺序的窗口合同。

## 可选 OIDC Router

仅合并 `federated_router` 后可用。同一 tenant 前缀：GET `/login-options`；POST `/oidc/{provider}/login`（`{returnTarget}`）、`/link`（重新认证与受控目标）、`/step-up`（`{returnTarget,operation}`）；GET `/session/security`。后者提供 `authentication:{authTime,acr,amr}` 和 `eligibleStepUpProviders:[{providerId,label}]`；普通 OIDC 未提供认证时间时 `authTime:null`，不回填 iat。它只提供认证事实，不返回管理角色。

唯一回调 GET `/api/v1/identity/oidc/callback`：state/code/iss 与独立 HttpOnly browser cookie 绑定；拒绝重放、过期、不匹配和不确定结算，不释放 cookie。returnTarget 是宿主白名单键，不接受任意 URL；不再接受中央 clientId。

IdP 管理：GET/POST `/providers`、PUT `/providers/{provider}`、POST `/providers/{provider}/enabled`、`/test`。写入使用 expectedVersion 乐观并发；创建初始配置不需要该字段。凭据只写，加密存储，不返回明文。provider 管理字段由 [provider 管理适配器](../../crates/identity-http-axum/src/provider_management.rs) 持有。部门映射须显式启用并给出有界期限，省略/null 表示禁用；旧标量字段拒绝。更新映射和期限经过同一并发版本与凭据更新流程，撤销旧会话及在途认证。完整快照只来自签名 ID Token，浏览器响应不成为部门授权证明。


## 失败与可信边界

OIDC callback 的错误投影由统一转换函数保留进程内 `HttpFailure` 与其它 response extensions；浏览器只收到原有 303 和闭集 reason，不包含内部错误内容或凭据。

外部错误为 `{code}`：malformed_request、invalid_credential、csrf_rejected、rate_limited、configuration_changed、insufficient_privilege、reauthentication_required 等闭集；基础设施失败为 503 identity_unavailable。内部 `HttpFailure` response extension 保留安全 settlement 分类，不暴露 SQL/IdP 原文，也不代表写入可自动重试。

所有 `429 / rate_limited` 必须携带 `Retry-After` 的正整数秒数，表示该响应时刻按数据库已生效限制计算的最早重试时间；向上取整，不区分账号是否存在或公开耗尽维度。继续竞争或新增失败可能改变后续结果，重试时间不保证登录成功。客户端须保留该时间供用户提示，不能自动重放密码或写请求。响应体仍只有 `{code}`。密码计数与来源策略见 [嵌入指南](../guides/embedding.md#密码防护与资源预算)。

HTTP 宿主资源请求统一调用 `authenticate_request`：用户活动选择 `SessionActivity::Active`，组件先验证严格 cookie、同源、请求标记和 CSRF，再读取权威状态并延长 idle；被动查询选择 `Passive`，不续期。宿主获得 `AuthenticatedSession` 后才执行资源授权，组事实通过 `VerifiedGroups` 借用；详细来源、过期和授权边界见 [嵌入指南](../guides/embedding.md)。HTTP JSON 只是前端交互投影。

底层 `Authority::authenticate_session` / `Authority::inspect_session` 仅供已建立请求保护的可信服务端 adapter 调用。前者验证并延长 idle，不改变原 absolute deadline；HTTP 宿主使用上述统一入口及显式活动策略，不能让后台心跳无限续期。`inspect_session` 只读验证，用于登录替换前检查、浏览器 GET session 和不应续期的被动查询。HTTP POST refresh 显式续期并旋转凭据；两种验证入口都重新检查权威状态。

## 参考宿主资源

参考宿主提供同源 UI 配置、当前上下文及 MFA 示范资源，由 [宿主 HTTP 模块](../../app/identity/src/context.rs) 持有。导航只是展示，管理事务仍重新授权。MFA 资源以当前请求的可信 assurance 判定，缺失/未来/过期事实要求重新认证，不接受浏览器提供的 MFA 结论。

这些只读资源不续期、不签发 cookie，并使用 no-store；实际策略通过宿主查询命令读取。前端接口与业务权限由对应产品维护，不能将示范资源扩展成通用授权协议。


## 登录资料接入

当前会话元数据的签发时间为 `issuedAt`；`authentication.authTime` 是独立的、可能未知的真实认证时间，
`authentication.source` 为 local_password、oidc 或 platform。客户端必须使用当前唯一结构。

`GET /api/v1/identity/tenants/{tenant}/profile` 返回本次会话绑定资料，观察被替换或不可用时不回退到其他来源。
账户资料 GET/PUT 和 operation receipt 入口及期限语义见[嵌入指南](../guides/embedding.md#登录资料与属性)。
资料请求体单独限制 96 KiB，普通身份请求保持原有边界；成功及失败响应沿用 no-store、Cookie／CSRF 与错误投影。
资料 CAS 与 operationId 冲突分别为 409 revision_conflict / operation_conflict；未知提交仍为既有不可判定结果，须查询回执。

## WebAuthn 与操作证明

显式挂载 `webauthn_router`；当前 tenant 前缀下提供 `/webauthn/credentials` 查询、`register/begin` 与 `register/finish`、`authenticate/begin` 与 `authenticate/finish`、`credentials/{id}/remove` 和 `{ceremony}/cancel`。写操作沿用 Origin、请求标记、CSRF 和当前 Cookie 检查；不接受 assurance 或 RP 配置。

`operation` 使用 `register`、`remove`（带 credential）、`recover` 或 `host` 的类型标记。前三项由服务端派生本人管理上下文；`host` 必须由可信宿主中间件注入 `StepUpContext`，不能从浏览器复制任意 context。OIDC step-up 和 WebAuthn 完成都设置短期 HttpOnly `__Host-identity-operation` Cookie，原会话保持不变。该 Cookie 不是身份凭据，消费必须匹配原会话和精确操作；产品业务使用同事务 `consume_step_up_on`，禁止验证后另起事务写业务。

注册 begin 接受 `{label,recover}`；finish 接受 `{id,response}`。首次开通使用近期主认证，后续注册/恢复消费操作证明；HTTP 不暴露无因子宿主恢复授权。服务端 ceremony state 从不发送到浏览器。取消与超时不生成成功证明；未知提交不自动重放。
