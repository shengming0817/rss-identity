# Identity v1 wire 草案

Owner：#2331；实现 owner：#2336。此文档不是已运行 HTTP API。标准 OIDC discovery/authorize/token/JWKS/logout 由 Hydra 提供，不在 Identity 复制同名端点。

## POST /internal/v1/identity/validate

调用方：已注册产品后端；TLS + 产品独立凭据认证，凭据与 Hydra client 身份严格绑定。浏览器不调用该接口。

请求：`credential`（不透明服务端协议凭据）、`tenant_id`、`audience`。client_id 来自认证凭据，不接受请求覆盖；issuer 来自服务端配置，不接受任意 URL。

成功 JSON 包含 `subject`、`tenant_id`、`session_id`、`client_id`、`audience`、`issuer`、`auth_time`、`amr`、`acr`、`expires_at`；可选 groups 包含 provider 来源和 mapping_version，不含 MDM roles/permissions 或 DeviceContext。Identity 不暴露内部跨产品 PrincipalId。该快照只用于本次请求，禁止跨请求复用为认证缓存。

流程：认证 client → 有界 Hydra introspection → 检查 tenant/client/audience/issuer 与精确 grant/session 关联 → 读取 Identity 当前状态/epoch/expiry → 输出事实。任何一步失败都不返回部分可信上下文。

错误：400 malformed_request；401 invalid_client/invalid_credential（外部不区分详细原因）；403 identity_not_active（不暴露账户存在性）；503 identity_unavailable（存储/上游不可用）；请求预算耗尽 503。响应 `Cache-Control: no-store`；error 仅 code 和不含敏感信息的 correlation_id。

## 产品浏览器回调

`GET /auth/callback?code=...&state=...`：产品验证自己保存的 state，服务端带原 redirect_uri 与 PKCE verifier 兑换；校验 issuer/audience/nonce 后调用上述复核入口，成功才创建/旋转产品 cookie。回调 URL 不保留 code，不记录 query 或把 code 发向第三方资源。

## 演进与来源

新可选字段仅在旧 consumer 可忽略时增加；身份字段含义、错误安全语义和隔离边界变化使用新 major。未知 auth strength 不提升 assurance，未知必要 identity enum 拒绝。I02 的 core 是绑定规则库，不提供反序列化即可构造的 VerifiedIdentityContext。
