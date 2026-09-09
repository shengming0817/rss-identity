# #2336 下游身份交接与在线验证

状态：I06 实现决定；实际 SHA、lock、provider digest 和验证结果随实现 PR。UI、生产装配、真实 MDM 接入分别属于 #2337/#2338/#2343。

## 唯一 owner

Identity 持有账户、成员、中央 session 和 grant 关联；Hydra 只持有标准 OIDC 协议状态。`identity-contracts` 是 wire 数据，`identity-client` 是不含账户/KDF/PG/OIDC 的在线验证客户端，`identity-hydra` 是受控 admin transport。core 定义窄 port，Postgres coordinator 唯一持有结算并返回私有构造的 ValidatedIdentity，HTTP 唯一映射到 wire DTO；PG 不依赖 contracts。I02 的 SessionSnapshot 检查骨架和假 Hydra bridge 已被删除，不保留兼容别名或第二条认证入口。

新增 product_subjects 按 tenant/client/principal 稳定保存随机 subject，直接作为 Hydra login subject，不能用 force_subject_identifier 替代（它不改变 introspection sub）。downstream_grants 引用中央 session 和 subject，不复制 epoch 或认证事实。注册版本及完整配置指纹共同约束在途和已发授权，避免仅改 redirect 却复用版本导致旧授权存活。schema v5 仅显式重建开发库；所有新表 FORCE tenant RLS，runtime 精确权限，maintenance 无新表权限。新事件 identity.downstream.security V1 与状态同事务，不包含挑战、cookie、code、token 或 secret。

## 交接

首期每个静态 client 绑定一个 tenant/audience；多个租户使用分别注册的 client。只接纳 confidential Code、openid、PKCE S256、精确 HTTPS callback，无 refresh、offline access 或自动 consent。RegistrationInput/LifetimeLimits 使用具名字段；组合时核对 adapter 声明 issuer 与所有注册完全一致，远程 challenge 还检查授权 URL 的 issuer origin/path。Hydra 必须固定 opaque token 和 PKCE enforcement；部署注入匹配实际 Hydra 的有限 request/code/token 期限。request 最大 300 秒、code 最大 600 秒、token 最大 86400 秒、时钟余量最大 60 秒；无缺省无限窗口。这是配置验证边界，不是生产 SLO。

浏览器通过 login challenge 准备最长 request 期限的流程，PG 保存独立 BrowserBindingSecret 的域分离摘要和 browser cookie 绑定，公开类型不可与中央 SessionSecret 互换；登录界面由 I07 持有。接受操作必须有当前中央 cookie、Origin 和 CSRF。顺序为 AwaitingLogin → LoginAccepting → AwaitingConsent → ConsentAccepting → Active；每次 accept 前先确认提交唯一领取。失败、结果未知和撤销进入 Revoking，不重放 accept。

Hydra v26.2 consent 的 login_challenge 是内部 flow ID，与加密浏览器 challenge 不同；login accept 的 context 注入本地 grant ID，consent 通过该 context 定位，再精确复核 tenant/client/subject/Hydra sid/browser/session/config。consent accept 的 access_token extension 仅含 identity_grant_id 和 identity_version；它不携带内部 PrincipalId。confirmed accept + 最终 PG 状态复核/提交后才向浏览器释放 redirect_to。没有首次验证激活或成功验证写事件。未认证 prepare 在 Hydra/DNS/TLS 之前强制取得由 composition 共享注入的 PrepareAdmission（有界并发和固定窗口预算），无效 challenge 也计数；单进程实例在同一 Hydra 服务的 coordinator 之间共享，多副本入口配置由 I08 持有。远程解析后继续使用 tenant/client 独立60秒窗口（最多60次）和每 client 1000条容量；这些是实现保护上限，不是生产容量证据。从未接受的 AwaitingLogin 只保留 request 窗口，领取 LoginAccepting 时才扩展完整安全窗口。

## 验证和恢复

产品每个请求以独立 Basic 凭据调用单一 internal validate；不接受 cookie 代替服务凭据，验证 secret 与 Hydra client secret 分开。先 introspect，再校验 token_use、issuer/client/audience/sub/scope/expiry/ext，最后在租户 guard 下复用中央 session 的账户/member/session/source epoch 判定。validate 只读，不 touch idle、不缓存成功；cookie 旋转保持 session ID，因此不切断既有 grant。失效提交后开始的验证拒绝；已通过的在途业务不追溯取消。

本地来源 amr 为 pwd；当前联合来源没有足够 AMR/ACR 证据，返回空 amr 和 unspecified acr，不推断 MFA。首版省略可选 groups。expires_at 取 token、grant 安全窗口、中央 idle/absolute 的最小值，过期严格拒绝；iat/nbf 的未来时间允许显式 clock_skew。client 不用本机时钟重新裁定服务端 auth_time，只检查正值及其早于 expires_at，通过必填 Clock 位置参数读取消费方墙钟，严格拒绝已过期及请求期间时钟回拨的结果；生产显式注入 SystemClock，无默认时钟或成功缓存。

cleanup_once 按显式 tenant、limit（1–128）和 deadline 运行，由 I08 调度。扫描、租约领取及结算各自有界，远程调用不占 PG 事务；Accepting 租约到期后视作未知，不恢复为可重发。先保持本地拒绝，再按 consent_request_id 清理 token，按 sid 清理协议登录会话。204 可能发生在迟到 verifier 尚未消费前，故重复清理到 request+code+token+skew+60秒执行余量的窗口末端；最后确认清理并同事务写事件后删除流程行，subject 映射保留。revoking 只在首次转换时发一次，后续重试只更新调度元数据，最终发一次 cleaned；仍复用同一事务结算 owner。没有独立持久队列、永久 cleaned 状态或全局租户 SQL 旁路。

## 证据与限制

`make test-downstream` 使用真实 PG、固定 Hydra、一次性 TLS/admin gateway 和可挂载 Axum，另运行独立 workspace/lock/target 的标准 OIDC consumer。旧 test-oidc 只保留真实 Keycloak 上游测试。容器与秘密均为可丢弃 fixture；Hydra DSN=memory 不证明生产持久化/重启恢复，生产调度/密钥/域名仍归 I08。I06 重启证明针对 Identity 的持久记录及 coordinator 重建。

来源：Hydra 0b84568fffccf151dc5e6c7955fdfb738555bf4b 的 flow/flow.go:401–425、flow/consent_types.go、oauth2/handler.go、consent/handler.go；固定 RSS 的 local_tx/Outbox；reqwest 0.12.28 的 resolver、redirect 和 request timeout。均通过现有接口组合，不复制上游实现。

错误响应与宿主 DownstreamDiagnostic 扩展共享同一个 correlation ID，保留安全 HttpFailure 分类；contracts 的 ValidationFailureCode 唯一持有闭集 wire code 与 HTTP 状态；HTTP 和 client 直接消费，未知 code/状态错配拒绝；client 只解析该枚举和合法 UUID，不携带 SQL/provider 原文。fixture 子进程有独立执行/退出边界，超时回收整个进程组；不设置 make ci 总时限。
