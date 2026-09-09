# RSS Identity 产品需求

版本：v0.1 需求草案；日期：2026-09-07。用户已确定独立 Identity 产品方向；本文件的具体协议和验收目标尚待实施设计冻结。I01/I02 建立协议和工程接缝，完整认证产品尚未实现；实际验证结果由实施 PR 持有。

## 1. 定位与消费者

本地认证 + 租户联合身份接入 + 服务端会话 authority，服务私有化部署的 RSS 系产品。独立拥有用户与会话状态、配置、迁移、进程和生产验收。

首批消费者为 rss-mdm：其当前 PRD 的 WMD-A01（本地身份/会话）、WMD-A02（OIDC/JIT/映射）均为一级；WMD-A03 的设备权限仍归 MDM。WMD-A04 的 MFA 为二级，WMD-A05 的 M2M/多租户产品为三级。ZT 是预期消费者，尚未验证实际接入需求。来源见 [证据索引](../reference/sources.md)。

Identity 自身从第一版显式携带 TenantId，拒绝跨租户身份串用；首期 MDM 可仅配置一个租户。这不把 MDM 的 MSP、计费、设备数据隔离和多租户运营提前到一级。

## 2. 用户与关键旅程

| 用户 | 关键旅程与结果 |
| --- | --- |
| 部署管理员 | 一次性初始化首位管理员 → 初始化入口关闭 → 重启不可重新夺取 authority |
| 本地用户 | 登录 → 服务端会话 → 产品接入 → 刷新/重新认证 → 当前或全部会话退出 |
| 租户身份管理员 | 配置 IdP → 连接测试 → 激活策略 → SSO 登录 → 查看关联和失败原因 |
| 安全管理员 | 禁用账户/撤销会话 → 观察下游在承诺窗口内拒绝 → 查询无密钥泄漏的安全事件 |
| MDM 管理员 | 接收已验证身份 → 按 MDM 业务角色授权设备动作；Identity 管理权不自动扩散 |

## 3. 身份与会话边界

规范化主体包含 PrincipalId、TenantId、认证方式、认证时间、认证强度和 SessionId；groups/claims 标识来源与映射版本。设备信息只能说明客户端元数据，不能冒充已验证 DeviceContext。

Identity 中央登录会话与产品浏览器会话分开。首期使用 Hydra 提供标准 OIDC Authorization Code + PKCE S256；产品后端兑换凭据并建立 host-only cookie 会话。Identity 自有身份状态与协议凭据分离，产品每次通过 Identity 单一入口复核身份。禁止自制通用 OAuth 授权服务器。

不依赖跨产品宽域 cookie，不把浏览器可构造的 JSON 直接反序列化为可信上下文。产品后端校验或查询成功才形成 VerifiedIdentityContext。浏览器默认不接收上游 IdP token；若选 token-mediating 方案，必须显式修订浏览器 token 暴露范围。Identity 不自动代理所有 MDM/ZT API。

## 4. 需求与验收

一级补关键盲区并形成首个可用接入；二级补商用生产闭环；三级须明确消费者后接纳。下表全部为目标，历史“有实现”不表示 Identity 已实现。

| ID / 等级 | 需求 | 最低验收目标 |
| --- | --- | --- |
| ACC-01 / 一级 | 产品身份和接入契约 | 区分身份、租户成员资格和产品授权；错误 tenant/audience/client/session 不产生可信上下文；版本演进和失效窗口可说明 |
| ACC-02 / 一级 | 初始化与本地账户 | 无默认密码；独立维护身份的一次性初始化且并发安全，账户/初始管理权/安全事件原子成立；用户创建、禁用、密码变更、受控管理员恢复；最后管理员保护和应急访问有明确规则 |
| ACC-03 / 一级 | 本地认证安全 | 成熟密码哈希、有界 KDF 和并发；失败响应不枚举账户；尝试限流覆盖验证入口；账户状态/epoch 与发会话并发时不越权 |
| ACC-04 / 一级 | 服务端会话 | 不透明高熵 cookie，Secure/HttpOnly、明确 SameSite 和 CSRF 策略；登录/提权旋转，idle/absolute expiry，当前/全部会话撤销；密码变化和禁用按冻结规则失效；存储故障拒绝认证 |
| ACC-05 / 一级 | 租户 IdP 配置 | tenant/provider/config-version 绑定，issuer/client/secret_ref/redirect/scopes/claim mapping；配置管理授权与审计；可诊断连接测试，受控出站与 TLS；停用或版本变化不偷偷切换在途登录 authority |
| ACC-06 / 一级 | OIDC Code + PKCE | state/nonce/verifier 与浏览器、tenant/provider、目标 client/return target 绑定；过期、重放、存储不可用、issuer/audience/nonce 不匹配均拒绝；只允许受控回跳地址 |
| ACC-07 / 一级 | JIT 与身份关联 | 稳定关联键包含 tenant/provider/issuer/subject；JIT 可禁用，成员资格明确；不得仅因邮箱相同自动合并本地账户；显式关联须重新认证，冲突可诊断；groups 标准化交给产品授权 |
| ACC-08 / 一级 | 下游身份交接与撤销 | 服务端凭据与 client/audience 隔离；交接单次且有界；断网、缓存、离线 token 的失效语义明确；消费方承诺撤销最大延迟，不能以短 JWT 自动宣称立即撤销 |
| ACC-09 / 一级 | 安全事件原子性 | 成功登录/撤销/账户安全变更与必要事件同事务；CommitUnknown 不返回成功凭据；新旧 schema owner 不共享全局迁移序号；安全事件不包含口令、cookie、code、verifier 或上游 token |
| ACC-10 / 一级 | 最小交互与管理 | 登录/SSO 入口、失败与会话过期提示、退出和会话列表；用户禁用/恢复、IdP 配置测试与状态；前端和管理 API 均不能越权。只读页面不取代写 API 验证 |
| ACC-11 / 一级 | 可部署装配 | binary/config/secret/migration；启动失败回滚、readiness、bounded drain、重启；冻结必选 provider，故障时允许哪些操作有明确说明 |
| ACC-12 / 二级 | 商用管理员认证与恢复 | 选定 IdP 的 MFA/step-up assurance 验证；本地应急账户和恢复规程；账号、密钥、备份恢复及撤销状态不回退；冻结容量、IdP 矩阵、RPO/RTO 与密钥轮转策略后验证 |
| ACC-13 / 三级 | 可选产品化 | SAML/LDAP/SCIM、passkey、本地 MFA、M2M、自动化 SDK、自助注册/邮件恢复、通用代理按消费者另立项 |

ACC-12 是商用发布前必须评估的闭环，分到二级不表示可以跳过安全验收。一级的账户恢复先采用受控管理员路径，避免隐式引入邮件服务。邀请/自助注册 UI、品牌定制和邮件 OTP 不进入初始关键路径。

## 5. 故障与安全验收重点

- state store 不可用时不得跳过 state/nonce；PKCE 不随配置 feature 被关闭。
- callback 对旧配置、停用 provider、重复 code、浏览器事务不匹配做确定处置，未知结果不盲目再次兑换。
- 联合身份关联、JIT、会话创建和事件在数据库侧有明确原子边界；外部 IdP 兑换不能被描述成数据库可回滚操作。
- 同邮箱跨 IdP/跨租户、并发 linking、邮箱未验证、组撤销与陈旧映射均有测试。
- cookie 认证的变更接口防 CSRF；不信任任意 forwarded host、return URL 或 IdP discovery 跳转。
- 退出分为 Identity 会话、本产品会话及上游 IdP 会话；不支持的上游全局退出不得宣称完成。
- 产品组映射、设备危险动作和用户停用后的授权效果由 MDM 接入验收证明。

## 6. 实现取舍与发布边界

Rust 优先复用成熟 openidconnect/oauth2、密码学、SQLx、Axum 等上游。历史 RSS 提供认证事务不变量，WinMDM 提供产品工作流，Plane 提供页面和账户恢复流程参考；不是直接复制实现的许可或成熟度证明。

初始建议 `crates/identity-core`、必要的 `crates/identity-contracts`，`crates/identity-postgres`、`crates/identity-oidc`、`crates/identity-http-axum`，`app/identity-server`。contracts/client/testkit 仅在真实跨 crate 消费出现时建立；先用包内模块组织 domain/application。具体目录与 package 数在 I02 按闭包冻结。

产品有独立 lock/CI/发布。RSS 使用固定完整 Git commit 与独立 lock 消费，发布不是 I02 前置；不复制 RSS runtime 或 messaging。T3 在独立 Issue/PR 中证明装配独有风险，详见 [实施计划](../architecture/implementation-plan.md)。

## 7. 设计阶段必须闭合的决定

I01 冻结首个 MDM 部署域名与会话路径、内部交接/标准协议选择、client 认证方式、撤销策略和延迟、租户与 principal 模型、初期 UI owner、首个 IdP 及本地应急策略。冻结决定见 [I01 ADR](../architecture/adr/202609080001-2331-access-identity-protocol.md)；冻结不代表已验证运行，不建设通用授权服务器。

## I03 实施边界

账户 authority、PG 原子事件与本机初始化/恢复按 [I03 ADR](../architecture/adr/202609080509-2333-local-authority.md) 实施。I03 提供账户 Rust API 与 identity-admin；登录/session HTTP 归 #2334，账户管理 HTTP/UI 归 #2337。范围决定不代表测试或生产验收已通过。

## #2358 维护入口收敛

初始化和管理员密码恢复各由独立维护数据库身份执行一条本机命令；无授权票据、两阶段交付或临时授权文件。维护凭据只注入受控运维任务，不能被日常服务读取。日常数据库凭据直接改库、维护身份或宿主机失陷不在本项隔离保证内。

普通用户持当前口令改密；忘记密码由同租户可用管理员协助，自助邮件找回仍为 ACC-13。管理员无法登录时使用明确 tenant/principal 的维护恢复，仅替换密码并推进 epoch，不自动启用或扩大权限，也不声称覆盖 MFA/IdP/身份流程恢复。#2337 将日常管理原子切换至中央会话 HTTP/UI，并删除日常 CLI；维护命令只保留 initialize/recover。中央 UI 源码由 rss-web 独立 apps/identity 持有，后端仍由本仓拥有。

现有仅可丢弃开发库，#2358 直接重建 schema，无向后兼容要求。操作和重建步骤见 [开发指南](../guides/development.md#本机账户管理与维护)，设计见 [本地 authority ADR](../architecture/adr/202609080509-2333-local-authority.md)。

I04 会话实现决定见 [会话 ADR](../architecture/adr/202609080900-2334-central-session.md)。并发刷新只有一个成功，旧值拒绝但不自动撤销胜出值；全部退出推进统一认证 epoch。该决定不表示 Hydra 交接或产品 T3 已通过。


## I09 范围冻结（#2339）

首版只验证并传递选定 Keycloak password + TOTP assurance，提供显式同会话 step-up，不强制拦截 Identity 管理读写。没有旧部署，直接替换初始 schema 和受影响调用方。应急管理员启用、凭据独立封存，使用后立即维护改密，不新建应急激活权限。

ACC-12 恢复保证具体化为：原生备份精确恢复到所选切点；部署 owner 负责选择包含所需安全状态的备份/WAL，并在秘密/状态核验前保持隔离。不承诺从任意历史快照自动恢复故障前最新撤销，不引入库外安全状态服务；缺完整证据不开放。I09 组件 T1/T2、独立候选 T3 与生产 SLO/RPO/RTO 冻结分别提供证据，未闭合前本项保持未完成。入口见 [ADR](../architecture/adr/202609091607-2339-assurance-recovery.md)。
