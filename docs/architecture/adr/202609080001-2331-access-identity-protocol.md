# #2331 身份、租户与产品会话协议

状态：I01 冻结；实现与运行证据分别由 I02–I09 持有。消费者：MDM；关联 ACC-01/08、#2331/#2332/#2343。

## 决定与取舍

Identity 自有 AuthN、Principal、TenantMembership、联合身份、中央认证 session 和安全事件；Hydra 是独立 OIDC 协议引擎，拥有授权码、token、client 和协议 session。Keycloak 仅作为首个上游租户 IdP。openidconnect 是上游 client，不是服务端授权系统。

直接用 Rauthy 会转移账户/会话 owner，并不能直接满足现有租户关联与安全状态/Outbox 同事务；自建完整 OIDC OP 增加协议责任。因此采用自有 Identity + Hydra，接受额外服务、schema 和跨服务失败边界，不复制通用协议引擎。不保留内部 handoff 作为备用协议。

## 主体与信任

- Principal 是全局、不透明、非空 UUID；TenantMembership 明确关联 tenant/principal，带有效性和单调 epoch。认证 session 固定一个 tenant；切租户必须重新形成该租户的授权上下文。
- 联合身份键为 tenant/provider/issuer/subject；email 不是身份键，不自动合并。当前 groups v1 带经验证的来源、采集快照 ID、provider 配置版本和固定期限；MDM 自行持有授权映射及其版本，见[在线协议](../identity-wire-v1.md)。
- 产品凭据绑定 issuer/client/audience/tenant/session；subject 为按 tenant/client 隔离的稳定不透明映射，不向产品暴露可跨产品关联的内部 PrincipalId。该映射由 [I06](202609090513-2336-downstream-identity.md) 持久化实现。
- 客户端元数据不构成 DeviceContext，Identity 管理员不自动获得 MDM 权限。首期 MDM 单租户不接纳 MSP/M2M。

## 登录路径和 UI

产品后端创建并持有随机 state/nonce/PKCE verifier（S256），浏览器只传 state/code。Hydra 回调 Identity 的 login/consent 页面，Identity 完成本地或上游认证、确认成员与目标 client 后接受 challenge；不盲信浏览器传入的 subject、tenant 或重定向。

仅 confidential client、静态注册、精确 HTTPS redirect URI，client_secret_basic over TLS，client 单独 secret_ref。凭据轮转在服务端完成；不在浏览器存 Identity/IdP token。不启用隐式/密码/client_credentials/offline_access、动态 client 注册。交互登录请求 openid 必需 scope，额外 claims 按最小披露。

Identity 提供中央登录、账户/会话管理、IdP 管理 UI；MDM 提供产品 callback、产品会话与业务页面。Identity 不代理全部产品 API。

独立 origin：IDENTITY_PUBLIC_ORIGIN 与 PRODUCT_PUBLIC_ORIGIN（部署必填，不能从 forwarded host 推断）；开发示例为 https://identity.example.test 和 https://mdm.example.test。产品回调 /auth/callback，Identity 管理/login 路由属于 Identity 自己，Hydra 公共协议路径通过固定 public issuer 暴露。不得部署时重写 issuer identity。

首个 MDM 部署采用唯一权威配置载体：I08 的版本化部署配置中 `identity_origin` 记录，必填
`environment_id`、`config_version`、`IDENTITY_PUBLIC_ORIGIN`、`PRODUCT_PUBLIC_ORIGIN`，由部署 owner
审查后固定为 artifact 配置身份。当前未选定真实域名，以上 `.example.test` 仅为开发示例，不可用作生产默认。
I08 在启动/注册前验证 HTTPS、无 path/query/userinfo/fragment、两 origin 不同且与环境一致；缺失即拒绝启动。
Hydra issuer 固定为 IDENTITY_PUBLIC_ORIGIN + `/oidc`，MDM redirect/callback 固定为
PRODUCT_PUBLIC_ORIGIN + `/auth/callback`；Identity 登录/consent 路由同样从该记录派生，不接受独立覆盖值。
origin 变更是身份迁移：创建新 config_version，重新静态注册 client/redirect，拒绝旧版本在途登录并撤销旧关联会话；
禁止仅改代理 host、复用旧 issuer 的持久化身份或跨环境复用配置。I01 冻结此载体、派生和变更规则；I08 持有具体域名和装配验证。

Cookie 使用 __Host- 前缀、Path=/、Secure、HttpOnly、SameSite=Lax，不设 Domain；变更接口校验同源 Origin 与 session-bound CSRF。OIDC 回调校验单次浏览器事务，不用 SameSite 代替 state/nonce。Identity 首期普通 session idle 30min/absolute 8h，管理员 idle 15min/absolute 4h；产品 session 不得超过 Identity absolute expiry。这些是实现配置基准，不是性能/生产 SLO 证据。

## 本地应急与恢复

首期 Keycloak 不可用时，已预先建立且启用的 Identity 本地账户仍可经正常本地登录入口认证；
不把联合登录失败自动降级为本地登录，不按 email 自动匹配或创建账户，也不绕过账户、membership、epoch 和限流。
Identity/PG 或下游 Hydra 不可用时仍拒绝产品交接，本地应急不提供离线授权。

I03 使用单次、并发安全、受控初始化授权原子建立首个本地管理员及安全事件，不内置默认账户或密码。
既有管理员只能通过受认证的管理操作显式建立/启用指定租户应急本地管理员，保存凭据到部署 owner 的受控保管介质，
不接受浏览器自选应急身份或 IdP 故障信号作为启用授权。禁用账户不能因进入应急模式重新有效；最后管理员保护在 I03 实现。
完全失去管理登录时仅允许 I03 定义的受控管理员恢复流程，经独立恢复授权、原子凭据替换、epoch 提升、会话失效和安全事件闭合；
不得直接改库恢复或回退撤销状态。I03 交付上述基础机制及拒绝路径；I09 再交付 MFA/step-up assurance、
应急凭据保管/启用/使用后轮换规程、恢复演练与备份/密钥恢复证明。I09 未验收前不宣称商用恢复就绪。

验收映射：I03 覆盖未授权启用、并发初始化、禁用/最后管理员、恢复授权重放和事件原子性；I05 覆盖 IdP 故障不得 JIT/自动绑定；
I06 覆盖基础设施不可用时不发产品凭据；I09 覆盖应急使用后轮换与撤销不回退。

## 撤销和失败

产品每次受保护请求调用 Identity 验证入口，不缓存成功结果。Identity 先验证 client/credential（Hydra introspection），再读权威账户、membership/session 与 epoch；无可信关联、inactive、错 tenant/audience、过期、超时、存储错误均不形成 VerifiedIdentityContext。协议 token 独立校验成功不能跳过 Identity 状态。

Identity 失效事务提交后开始的复核必须拒绝；已通过复核的在途操作不追溯取消。密码变化、禁用、全会话退出提升对应身份 epoch；当前会话退出使该 session 失效。协议凭据清理/后通道通知加速下游退出；通知失败或 Hydra 旧凭据不恢复 Identity 状态。首期不提供离线认证模式，不承诺上游 IdP 禁用能被即时发现或全局退出。

Identity 的状态和安全事件同 PG 事务；Hydra challenge 接受/token 发放不与此事务原子。先提交 Identity 状态，提交未知不接受 challenge；远程接受结果未知不盲重试，不返回成功，I06 按精确关联及持续到窗口末端的失效补偿处理孤儿授权。异常/日志不得泄漏 code、token、cookie、verifier、client secret。

Hydra admin API 不公开，由 Identity 服务身份和受控网络独占；TLS/出站目标限制包含 discovery、JWKS、token，HTTP 自动重定向关闭。上游配置变更/停用使相应在途事务失败，不重取当前配置偷偷换 authority。

## 验证 owner

I02 证明独立 Git 消费、真实 PG 事务与标准 OIDC 接缝，不实现完整 authority。I03 账户并发和事件；I04 会话/epoch；I05 state/config/JIT；I06 实际 Hydra bridge、client/sid 映射、孤儿授权、单入口在线验证和撤销 T2；I07 UI；I08 生产装配；T31–T33 各自独立。未知状态拒绝必须有负向用例，不用短 JWT 推导即时撤销。

首次实现前无旧 wire/API 兼容承诺。v1 发布后以 URL major 与字段含义持有 wire identity；breaking 新版本，不能把“不向后兼容”作为原地破坏已消费协议的永久授权。
