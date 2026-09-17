# 实施路径与已登记 Issue

当前重构计划：[#2435 内嵌认证组件](adr/202609170001-2435-embedded-authentication.md)。2026-09-17 已批准并开始实施，按“彻底 / 不向后兼容 / 优雅简洁”复核；以下中央架构任务索引保留为历史来源，不代表当前组件运行模式。

状态：2026-09-07 已登记 1 个 Epic 和 13 个子项，并回读验证正文、类型、标签、父子关系与 Predecessor 依赖。INIT/I01 等保留为需求映射编号；实施状态以 Azure Boards 为准，本文不复制看板状态。

## Azure 工作项索引

| 本地编号 | 工作项 | Owner 仓库 | 前置工作项 |
| --- | --- | --- | --- |
| EPIC | [#2330 [ACCESS-R1/R2] 本地认证、租户 OIDC 与产品会话接入闭环](https://dev.azure.com/shengming0923/rss/_workitems/edit/2330) | rss-identity | — |
| I01 | [#2331 [ACCESS-I01] 冻结身份、租户与产品会话协议](https://dev.azure.com/shengming0923/rss/_workitems/edit/2331) | rss-identity | — |
| I02 | [#2332 [ACCESS-I02] 建立 Rust 工程、CI 和 RSS 版本消费](https://dev.azure.com/shengming0923/rss/_workitems/edit/2332) | rss-identity | [#2331](https://dev.azure.com/shengming0923/rss/_workitems/edit/2331) |
| I03 | [#2333 [ACCESS-I03] 本地 authority、账户安全与原子事件](https://dev.azure.com/shengming0923/rss/_workitems/edit/2333) | rss-identity | [#2332](https://dev.azure.com/shengming0923/rss/_workitems/edit/2332) |
| I04 | [#2334 [ACCESS-I04] 服务端会话、刷新与撤销](https://dev.azure.com/shengming0923/rss/_workitems/edit/2334) | rss-identity | [#2333](https://dev.azure.com/shengming0923/rss/_workitems/edit/2333) |
| I05 | [#2335 [ACCESS-I05] 租户 IdP 与 OIDC/JIT 闭环](https://dev.azure.com/shengming0923/rss/_workitems/edit/2335) | rss-identity | [#2332](https://dev.azure.com/shengming0923/rss/_workitems/edit/2332), [#2334](https://dev.azure.com/shengming0923/rss/_workitems/edit/2334) |
| I06 | [#2336 [ACCESS-I06] 下游登录交接与验证 client](https://dev.azure.com/shengming0923/rss/_workitems/edit/2336) | rss-identity | [#2334](https://dev.azure.com/shengming0923/rss/_workitems/edit/2334), [#2335](https://dev.azure.com/shengming0923/rss/_workitems/edit/2335) |
| I07 | [#2337 [ACCESS-I07] 登录与身份管理交互闭环](https://dev.azure.com/shengming0923/rss/_workitems/edit/2337) | rss-identity | [#2333](https://dev.azure.com/shengming0923/rss/_workitems/edit/2333), [#2334](https://dev.azure.com/shengming0923/rss/_workitems/edit/2334), [#2335](https://dev.azure.com/shengming0923/rss/_workitems/edit/2335), [#2336](https://dev.azure.com/shengming0923/rss/_workitems/edit/2336) |
| I08 | [#2338 [ACCESS-I08] 生产装配、迁移、发布与生命周期](https://dev.azure.com/shengming0923/rss/_workitems/edit/2338) | rss-identity | [#2333](https://dev.azure.com/shengming0923/rss/_workitems/edit/2333), [#2334](https://dev.azure.com/shengming0923/rss/_workitems/edit/2334), [#2335](https://dev.azure.com/shengming0923/rss/_workitems/edit/2335), [#2336](https://dev.azure.com/shengming0923/rss/_workitems/edit/2336), [#2337](https://dev.azure.com/shengming0923/rss/_workitems/edit/2337) |
| I09 | [#2339 [ACCESS-I09] 管理员 assurance 与生产恢复闭环（二级）](https://dev.azure.com/shengming0923/rss/_workitems/edit/2339) | rss-identity | [#2338](https://dev.azure.com/shengming0923/rss/_workitems/edit/2338) |
| T31 | [#2340 [ACCESS-T31] ACCESS-LIFECYCLE](https://dev.azure.com/shengming0923/rss/_workitems/edit/2340) | rss-identity | [#2338](https://dev.azure.com/shengming0923/rss/_workitems/edit/2338) |
| T32 | [#2341 [ACCESS-T32] ACCESS-LOCAL-AUTH](https://dev.azure.com/shengming0923/rss/_workitems/edit/2341) | rss-identity | [#2333](https://dev.azure.com/shengming0923/rss/_workitems/edit/2333), [#2334](https://dev.azure.com/shengming0923/rss/_workitems/edit/2334), [#2336](https://dev.azure.com/shengming0923/rss/_workitems/edit/2336), [#2337](https://dev.azure.com/shengming0923/rss/_workitems/edit/2337), [#2338](https://dev.azure.com/shengming0923/rss/_workitems/edit/2338) |
| T33 | [#2342 [ACCESS-T33] ACCESS-FEDERATED-SSO](https://dev.azure.com/shengming0923/rss/_workitems/edit/2342) | rss-identity | [#2335](https://dev.azure.com/shengming0923/rss/_workitems/edit/2335), [#2336](https://dev.azure.com/shengming0923/rss/_workitems/edit/2336), [#2337](https://dev.azure.com/shengming0923/rss/_workitems/edit/2337), [#2338](https://dev.azure.com/shengming0923/rss/_workitems/edit/2338) |
| M01 | [#2343 [MDM-ACCESS] 对齐 WMD-A01/A02 并消费 Identity 身份，保留资源授权 owner](https://dev.azure.com/shengming0923/rss/_workitems/edit/2343) | rss-mdm | [#2331](https://dev.azure.com/shengming0923/rss/_workitems/edit/2331), [#2336](https://dev.azure.com/shengming0923/rss/_workitems/edit/2336), [#2338](https://dev.azure.com/shengming0923/rss/_workitems/edit/2338) |

Azure Boards 工作项属于 rss 项目，通过 `repo-rss-identity` / `repo-rss-mdm` 标签与正文标明仓库 owner。13 个子项原生 Parent 均为 Epic #2330；Parent 表达目标归属，Predecessor 表达执行依赖。INIT 已由提交 b082a7e 完成，不重复登记为待办。

## 是否可以一个 Issue 完成

本次 INIT（独立仓、Git 配置、协作规则、PRD、来源与实施计划）可以一个 Issue/交付项完成。整个 Identity 使用一个 Epic 统筹，不能一个实现 Issue/PR 包含全部产品和 T3：协议、认证持久化、OIDC、跨产品信任及生产装配各有不同失败边界，且 T3 明确要求独立 Issue、独立 PR、独立必要性评估。

已登记一个 Epic、八个一级实施 Issue（I01–I08）、一个二级闭环 Issue（I09）、三个独立 Identity T3，以及一个由 MDM 拥有的接入 Issue。共 13 个子项；INIT 另作本次初始化记录。按实际复杂度可再拆，不能按数量目标合并安全边界。

Epic：`[ACCESS-R1/R2] 本地认证、租户 OIDC 与产品会话接入闭环`。
退出条件：I01–I09 及适用 T3、真实 MDM 接入有行为证据；版本和未支持矩阵明确。范围批准或文档合并不等于 Epic 完成。

## 一级主链

```text
I01 范围/协议 ADR
  → I02 工程、固定 Git 消费与事务接缝
    → I03 本地 authority → I04 会话
    → I05 租户 OIDC/JIT（会话闭环依赖 I04）
I04 + I05 → I06 下游交接
I03 + I04 + I05 + I06 → I07 最小 UI/管理闭环
I03–I07 → I08 装配与候选 artifact
I08 → T31 / T32 / T33（分别按必要依赖执行）
I06 + Identity 候选 artifact → M01 MDM 接入与业务授权
I08 → I09 二级商用认证/恢复闭环
```

I05 的配置与协议部分可在 I02 后推进，最终验收等待 I04。每项交付前置已闭合的 domain、schema、adapter、应用 API 与必要 T1/T2。I03 提供真实账户 Rust API 和本机管理工具；I04 首次建立登录/session HTTP 与认证提取；I07 复用真实 session 增加账户管理 HTTP/UI。不为提前挂载路由建立临时认证协议或占位认证器。

## 实施项范围

| ID / 标题 | 依赖与范围 | 验收 / 排除 |
| --- | --- | --- |
| INIT：建立独立仓与需求基线 | 本次；参考 MDM 组织文档和 Git 配置 | origin/develop、local exclude、来源、PRD/计划；不声称代码/CI 已存在 |
| I01：冻结身份、租户与产品会话协议 | ACC-01/08；MDM WMD-A01/02/03 对接；输出 ADR、wire 草案、威胁与失败路径 | 明确 BFF/中央 authority、租户成员、client 信任、cookie 域、撤销窗口、UI owner；登记 MDM 范围对齐，不导入 MDM domain |
| I02：建立 Rust 工程、CI 和 RSS 版本消费 | I01；独立 workspace/lock、必要 crate、依赖许可证、真实 PG/OIDC 测试入口、RSS 事务接缝验证 | 固定完整 Git commit、独立 lock 的 RSS 公共包可消费；业务写与 Outbox 同事务最小 T2；无浮动引用、双来源或旧内部包 |
| I03：本地 authority、账户安全与原子事件 | I02；ACC-02/03/09；初始化、管理账户、密码/禁用/恢复、预建本地应急管理员与受控启用基础机制；PG schema 与安全事件 | 并发初始化、账号状态/epoch 竞态、限流、KDF 有界、失败回滚、CommitUnknown 不发凭据；含必要 T1/T2，不含 T3 |
| I04：服务端会话、刷新与撤销 | I03；ACC-04/09；cookie/CSRF、期限、旋转、当前/全部撤销、会话查询 | 会话固定攻击、并发刷新、重放、存储不可用、密码/禁用导致失效、事件原子性；明确不等于上游 IdP 全局退出 |
| I05：租户 IdP 与 OIDC/JIT 闭环 | I02；完成依赖 I04；ACC-05/06/07/09 | 配置管理与连接测试；Code/PKCE/state/nonce；配置变化/失效事务；邮箱与 subject linking；真实 IdP T2；无校验降级、无自动邮箱合并 |
| I06：下游登录交接与验证 client | I04/I05；ACC-01/08；按 I01 冻结协议输出最小公共面 | 单次交接、client/audience/tenant 错配拒绝、认证服务端消费、撤销/缓存/故障；模拟 consumer 是 T2，真实 MDM 验收归 M01 |
| I07：登录与身份管理交互闭环 | I03/I04/I05/I06；ACC-10 | 最小登录/回调错误/退出/会话列表、账户恢复、IdP 测试与管理页面；UI 和管理 API 权限负向验证；不建全套通用管理门户 |
| I08：生产装配、迁移、发布与生命周期 | I03–I07；ACC-11 | config/secret/provider、迁移顺序、listener、readiness/drain、镜像与版本、运维手册、候选 artifact；装配验证不夹带 T3 |
| I09：管理员 assurance 与生产恢复闭环（二级） | I08；ACC-12 | 选定 IdP MFA/step-up、I03 本地应急账户的保管/使用后轮换与恢复演练、密钥轮转/备份恢复/容量与冻结 SLO；组件风险 T1/T2，新增产品 join hazard 另立 T3 Issue/PR，不能塞回此实现项 |

I03–I05 必须在各自实现时闭合安全事件，不能最后另加一个“补 Outbox”任务改变已验收的原子性。I02 只证明通用事务接缝，不能替代这些业务负向证明。

## 三个独立 Identity T3

| ID / 标题 | 必要性（装配后独有） | 依赖、验收及不重复项 |
| --- | --- | --- |
| T31：ACCESS-LIFECYCLE | binary + config + PG + 选定 IdP + messaging + listener 在启停/重启中的 join | I08；真实候选启动、部分启动失败、readiness、drain、重启与迁移版本匹配；不重跑完整 Outbox 故障矩阵 |
| T32：ACCESS-LOCAL-AUTH | 浏览器/cookie/路由 + 本地 authority + 持久化 + 产品交接 + 事件连通 | I03/04/06/07/08；真实登录→会话→消费→刷新→退出/禁用→拒绝→安全事件；不重复哈希算法或 PG repository conformance |
| T33：ACCESS-FEDERATED-SSO | tenant route + 外部 IdP + 浏览器事务 + callback + linking + session + downstream | I05/06/07/08；真实租户选择和 SSO、错误浏览器/租户/重放拒绝、产品接入与撤销；不重跑 JWT 算法矩阵 |

T31 的执行载体为 [identity-lifecycle](../../t3/identity-lifecycle/README.md)，按固定顺序覆盖首次安装、冷/热依赖故障、部分启动、真实在途请求排空、保留卷重启和 schema/config 身份错配。部署缺陷在独立 [#2419](https://dev.azure.com/shengming0923/rss/_workitems/edit/2419) / [PR #1008](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1008) 修复；换入修复候选后重新执行全矩阵，2026-09-12 的[实际记录](../deployment/202609120756-2340-lifecycle-acceptance.md)已完整通过。只消费候选自己的 renderer，不保留旧配置/schema 兼容分支；源码开发探针不能作为 T3 通过记录。

每个 T3 登记时须单独保留必要性、固定 artifact、provider/config 矩阵、实际输入输出、故障和排除项。可复用已发布测试设施，不能共享实现 PR 混交付。T31–T33 不自动证明 I09 后新增的 MFA/恢复行为。

T32 的独立执行载体见 [本地认证候选验收](../../t3/access-local-auth/README.md)，入口为
`make test-t3-local-auth`，消费已有固定候选。固定候选 `06d4e854...` 的 10 场景实跑通过，历史结果见[原则复核与运行记录](../reviews/202609120745-2341-local-auth-t3.md)，当前复验见[五组修复记录](../reviews/202609130014-2341-five-group-fix.md)；
该结论绑定记录中的 artifact/config/provider，不自动外推到其它版本。事件连通截止到持久 Outbox；测试消费者不持有 MDM 业务授权。

## M01：由 rss-mdm 拥有的独立接入项

标题：`[MDM-ACCESS] 对齐 WMD-A01/A02 并消费 Identity 身份，保留资源授权 owner`。

依赖 I01/I06 与可部署 Identity 候选。在 MDM PRD 明确 AuthN/session 交由 Identity，保留 WMD-A03 的业务角色、危险动作、组映射授权与授权失效责任。首期单租户接入不自动批准 MSP。

验收真实 MDM API 对可信身份、错误 tenant/audience、账户禁用/撤销、无权限设备动作的行为；按 MDM 规则判定是否需要独立产品 T3。禁止仅把 Identity client DTO 构造成功当作身份验证，不在 MDM 重跑整套 IdP 登录。

本次未修改 MDM PRD：该仓已有并行需求工作；通过 M01 对齐唯一 owner，避免两个仓各自宣称拥有账户 authority。

## 登记约定

每项 body 包含：问题/消费者、关联 ACC 与 WMD ID、范围及不含项、blocked-by、来源 revision/path、T1/T2 或独立 T3 必要性、验收、依赖版本、退出条件。Epic 是 Parent；执行阻塞另建依赖关系，不能只靠子项显示顺序。

全部工作项已登记，正文包含验收与来源，依赖通过原生 Predecessor 表达。I01 是首个无前置实施项；后续按依赖推进。I05 的 I04 依赖约束完整交付，配置准备可先行；二级 I09 与 T3 不因登记而自动宣称就绪或完成。

## I01/I02 合并交付决定（2026-09-08）

#2331 与 #2332 在同一个 PR 内按协议→core→PG→OIDC→CI 顺序实施，保留原有逻辑 Predecessor。当前基准为 RSS `bf5dd1350997d01aa834094a3347fce30247814e`，未来升级必须显式修改 rev/lock 并重新验证。未发布 registry 包不再构成阻塞。

[协议 ADR](adr/202609080001-2331-access-identity-protocol.md) 与 [wire 草案](identity-wire-v1.md) 为新设计入口；I03 自有账户和事件，I04 自有会话及撤销，I05 openidconnect/Keycloak 上游，I06 Hydra 下游和单一验证接缝，I07 自有登录/管理 UI，I08 包含 Hydra 装配。I09/T31–T33/M01 分别证明恢复、生产 join 和 MDM 权限，不能用本次接缝测试替代。

## I03 后续简化

[#2358](https://dev.azure.com/shengming0923/rss/_workitems/edit/2358) 收敛初始化/管理员恢复为独立维护身份的单条命令，删除授权票据与文件交付。日常 CLI 已由 #2337 的中央会话 API/UI 替代；#2338/#2339 分别持有生产注入与恢复治理，#2341 仍独立证明 T3。schema 2 仅按已确认的可丢弃开发库重建，实际测试与交付状态以 PR/看板为准。

## #2359 工程身份更名

[更名工作项 #2359](https://dev.azure.com/shengming0923/rss/_workitems/edit/2359) 将 `rss-access` 原地更名为 `rss-identity`；Azure repository ID 保持 `e1257122-3ec2-4a42-a134-67e73e574e61`。库统一位于 `crates/identity-*`，可执行入口位于 `app/identity`；不保留独立 `adapters/` 层。Cargo package 为 `rss-identity-*`，管理命令为 `identity-admin`。

仅有可重建测试数据且没有外部事件消费者：初始安装使用 `identity_authority`、`identity_account_runtime` / `identity_account_maintenance`，事件使用 `identity.security` / `identity.account.security`。没有旧入口别名、升级迁移、双读或旧事件桥接；已有开发库及 Outbox 须停用后重建，数据库角色属于集群对象，须单独核实依赖再清理。该一次性切换不进入产品启动逻辑。

该历史更名阶段使用 schema version 2，事件 V1 payload、账户/租户/authority/lineage/epoch 的业务语义不因名称改变；新测试安装自行生成身份，不将重建视为保留旧数据。历史 `ACCESS-*` / `ACC-*` 编号、工作项 ID、ADR 文件名与固定来源继续用于追溯。Hydra 架构不变，#2360 不属于本项。实际验证和本地切换证据由 #2359 PR 持有。

## I04 实施落点

#2334 的会话决定见 [中央会话 ADR](adr/202609080900-2334-central-session.md)：identity-core 会话策略、identity-postgres 单表/统一 auth_epoch 与事务事件、identity-http-axum Router。该历史阶段直接替换初始安装，不兼容旧开发库。仅 T1/T2，验证结果随实现 PR 记录，I05/I06/I07/I08 与独立 T3 的退出条件保持独立。

## I05 实施决定（#2335）

用户决定一个 PR 完成账户/本地凭据替换与全部联合身份闭环，不保留旧内存 LoginAttempt 或 schema 兼容。
实现模型与安全边界由 [I05 ADR](adr/202609082050-2335-federated-identity.md) 持有，管理与接入见[指南](../guides/federation.md)。实际版本/SHA/lock、provider digest 和验证结果记录于实现 PR，不以文档更新代替运行验收。

## I06 实施决定（#2336）

[下游 ADR](adr/202609090513-2336-downstream-identity.md) 持有真实 Hydra bridge、唯一 PG 关联、只读在线验证与有界清理；[接入指南](../guides/downstream.md) 持有公共消费面。该历史阶段直接替换 I05 初始安装，不保留兼容。实际验证结果和版本身份由实现 PR 持有。

## I07 当前决定

[单一管理入口 ADR](adr/202609090801-2337-central-management-ui.md) 固定无兼容替换、CLI 退出与 rss-web/apps/identity UI owner。双仓 PR 分别持有后端管理和前端；实际源码版本与验证结果以交付记录为准。


## I09 实施决定（#2339）

[Assurance 与恢复 ADR](adr/202609091607-2339-assurance-recovery.md) 固定 Keycloak password/TOTP 的可信事实、显式 step-up 和下游传播。该历史阶段直接替换 I08 初始安装，无旧部署兼容。应急沿用现有维护权限；恢复采用原生 PG 切点、真实 provider T2 和部署隔离规程，不增加 seal/激活业务状态机。

`make measure-capacity` 只提供组件测量，真实生产目标待测后冻结；#2339 不随实现 PR 自动关闭。已登记独立 PBI，Parent 均为 #2330，原生 Predecessor 为已完成的 #2338；额外执行前提是 #2339 实现 PR 合入后的精确候选/API，不以 #2339 Done 为启动条件：

| 项目 | 工作项 | Owner |
| --- | --- | --- |
| 候选 MFA/step-up T3 | [#2366](https://dev.azure.com/shengming0923/rss/_workitems/edit/2366) | rss-identity |
| 候选恢复/轮换 T3 与生产目标冻结 | [#2367](https://dev.azure.com/shengming0923/rss/_workitems/edit/2367) | rss-identity |
| 前端 step-up 入口与事实展示 | [#2368](https://dev.azure.com/shengming0923/rss/_workitems/edit/2368) | rss-web |

登记不表示已实施或运行通过；避免把实现项的完整验收条件反向变为 T3 的执行阻塞。

## #2427 + #2428 同 PR 实施

系统域、显式平台角色、动态租户开通/新增管理员、自助加密 OIDC、持久会话与 SSO CLI 按 [当前 ADR](adr/202609130900-2427-platform-onboarding.md) 交付。当前安装版本由 [SCHEMA_VERSION](../../crates/identity-postgres/src/lib.rs) 及其安装探测持有，上述阶段的版本说明只用于历史追溯。#2368 消费替换后的网页协议；#2342 绑定新的 CLI/API 候选做 T3。实施与验收状态以 PR 实际记录为准。
