# 下游身份接入

I06 提供可挂载 router 和最小在线验证 client，完整产品服务器/页面分别由 I08/I07 提供。

装配顺序：现有 Authority → 以具名 RegistrationInput/LifetimeLimits 构造的静态 Registration 集合与 Lifetimes → 注入 Hydra adapter 和共享 PrepareAdmission 的 Downstream → downstream_router，与原 central/federated router 合并。Hydra admin URL 必须是固定 HTTPS origin，注入允许地址范围、服务 gateway bearer 身份及可选私有 CA；不公开 admin、不接受浏览器 URL、不信任隐式环境代理或自动重定向。service gateway 必须实际验证此身份，Hydra 自身不替代 gateway 鉴权。

每个产品 client 注册一个 tenant、audience、精确 HTTPS callback 和单调 config_version。完整配置指纹存入 grant，配置漂移拒绝旧 grant。静态 secrets 集合必须与 client 集合完全相等，值至少32字节且各产品不同；由部署解析不可变 secret_ref，原始 secret 不进入数据库。validation secret 与 Hydra OIDC secret 分域，注册或轮转时由部署核对；缺配置拒绝构造。

Hydra 注册 authorization_code/code/openid/client_secret_basic 和精确 redirect，启用 oauth2.pkce.enforced=true、strategies.access_token=opaque；不注册 refresh/client_credentials/offline_access。Lifetimes 必须与实际 Hydra 有效配置匹配，并禁止部署扩大未登记的 client 自定义 token 期限。Identity/产品 origin 和 issuer 继续服从 I01 的版本化配置载体。

## 浏览器接口

所有下列入口均 POST JSON，要求精确 Origin、X-Identity-Request: 1，响应 no-store/no-referrer。前两步可在中央登录之前完成准备，身份接受必须有中央 cookie 和 X-CSRF-Token。

| 路径 | 输入 | 成功 |
|---|---|---|
| /api/v1/downstream/login | `{challenge}`，Hydra login challenge | `{tenant_id,grant_id}`；首次设置独立 browser cookie |
| /api/v1/downstream/login/accept | `{flow:{tenant_id,grant_id},challenge}` + 当前中央 cookie/CSRF | `{redirect_to}`，浏览器继续 Hydra |
| /api/v1/downstream/consent | `{challenge}`，Hydra consent challenge + browser cookie | 当前 `{tenant_id,grant_id}` |
| /api/v1/downstream/consent/accept | `{flow:{tenant_id,grant_id},challenge}` + 中央 cookie/CSRF | `{redirect_to}`，浏览器继续 Hydra |

`__Host-identity-downstream-browser` 使用 Secure/HttpOnly/SameSite=Lax/Path=/、无 Domain，Max-Age 3600 秒。凭据由 core downstream 的 BrowserBindingSecret 持有，私有零化字段、不可 Clone、独立域分离摘要，不与中央 SessionSecret 互换。已有 cookie 不覆盖；首次无 cookie 时先完成 begin，再并发其它 flow。flow 是定位符，不是认证证明；不能从 flow 字段提交身份、权限或任意回跳地址。I07 持有 Hydra 配置的 login/consent 页面以及登录后继续这些 API 的交互。

## 服务端验证

`IdentityClient::new(ClientConfig, Arc<dyn Clock>)` 固定 identity_origin、issuer、client_id、tenant_id、audience、validation_secret、非零有界 timeout 和可选 CA。`validate(credential)` 每次执行网络请求，返回 VerifiedIdentity；只在当前请求使用 getter 读取事实，不保存为下一请求的认证缓存。Clock 是必填位置参数，生产显式注入 SystemClock，测试注入固定或推进时钟；返回时重新取时，拒绝请求期间墙钟回拨及恰好到期的响应。该类型没有公开构造或反序列化入口，但 SDK 不能代替消费产品正确调用每请求验证。

产品保存自己的 state/nonce/PKCE verifier，使用标准 OIDC 库服务端兑换，检查 ID token 的签名/issuer/audience/nonce，并将其 subject 与 Identity 验证结果核对；成功后才创建/旋转自己的 host-only cookie。token/verifier 不进入浏览器持久化或日志。没有自动刷新或离线认证，协议凭据过期后重新授权。

验证错误：400 malformed_request；401 invalid_client/invalid_credential；403 identity_not_active；429 rate_limited；503 identity_unavailable。browser 接口另有403 csrf_rejected；状态与代码由 contracts 的 ValidationFailureCode 唯一映射，未知值或状态错配拒绝。body 为 code/correlation_id，不回显 provider 或 SQL 原文。宿主可读取 DownstreamDiagnostic response extension；client 的 Error::Server 保留contracts 的闭集 ValidationFailureCode 与 correlation UUID，is_unavailable 区分可用性失败。未知/畸形失败 body 一律 Unavailable。任何错误都不能沿用上次成功。

## 开发验证

运行 `make test-downstream`；首次准备独立 consumer 可执行 `cargo fetch --locked --manifest-path tests/consumer/Cargo.toml`。规范入口启动真实 PG/Hydra/TLS fixture、运行精确测试集合，并在 Axum 服务存活期间运行独立 consumer。consumer 只通过本仓公开 client/标准 OIDC 消费，锁与 target 独立；不声称固定 Git 发布包或真实 MDM 验收。

生产依赖图的 #2357 RSA 例外保持原有唯一路径。独立测试 consumer 另精确限定 identity-consumer-proof → openidconnect 4.0.1 → rsa 0.9.10，仅公钥验签、无私钥操作；由 check_consumer.py 和独立 cargo-deny 配置核查，不扩大生产例外。上游修复、私钥用途或进入 I08 生产接纳时必须重新评估。

准备入口先取得必填共享 PrepareAdmission 的并发许可和固定窗口预算，再执行任何 Hydra/DNS/TLS 工作；无效 challenge 也耗用预算，取消释放并发许可但不退还请求预算。构造时并发1–128、窗口内请求1–10000、窗口大于0且不超过60秒；同一 Hydra 服务的所有 coordinator 必须共享一个实例。该边界限制单进程资源，I08 仍持有多副本入口配额与可信来源配置。解析后按 tenant/client 独立限制每60秒60次与1000条容量，限速返回429 rate_limited，容量耗尽返回503。AwaitingLogin 的 request 窗口结束即可清理；进入 Accepting 后才保持完整 token 安全窗口。清理重试不重复发布安全状态事件。

故障证明：canonical downstream_atomic 覆盖清理领取回滚、并发唯一远程调用、远程失败后退避、窗口内结算未知后以同一 consent/sid 重试、最终删除提交未知及 cleaned 事件唯一性。Hydra resolver 单测覆盖空/混合/越界解析和 hostname 错配，真实 TLS fixture 使用 localhost DNS SAN 与精确 loopback allowlist。

MFA / 新鲜度使用在线 `VerifiedIdentity` 的 `acr/amr/auth_time`；Hydra 标准 ID Token 保持 `acr=unspecified`、不投影上游 AMR，其 Hydra 登录时间不能代表上游 MFA 时间。
