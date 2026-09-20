# #2451：可信部门树快照

状态：实现契约；实际验证结果与固定 revision 由对应 PR 记录。替代 #2447 单部门代码方案，作为 MDM #2363 的硬前置。

## 决定

唯一配置为 claims.departmentSnapshot（claim 与明确 TTL），唯一输入为签名 ID Token 中的版本化 JSON 完整树与当前用户成员。领域 DepartmentSnapshot 统一验证上游输入和持久化结构，私有 TrustedDepartmentSnapshot 绑定权威会话来源并逐次检查期限。节点/成员/版本不能从浏览器或其它会话补齐，不把部门编码成安全组。

只支持 fresh schema v11、auth_facts v3；旧配置、标量访问器、旧格式/库直接拒绝，无别名、双读、转换或复活路径。HTTP 保持 v2，参考宿主配置保持 v4。宿主与 Web 管理客户端须更新新字段，并固定完整组件 revision。

完整树为 1–256 个节点、单根、最长 16 层，最多 16 个显式成员。稳定 ID、父 ID 与成员精确匹配；displayName 不提供身份。所有节点连通、无重复/环/缺父节点；memberships 空数组明确未分配。sourceRevision 是来源维护的不透明版本，不能替代 provider 配置版本、session epoch 或 snapshot_id。

已验签但缺失/非法的部门断言只产生部门不可用；auth_facts 总量超过 32 KiB 时关闭整个部门事实，再检查其余认证事实。签名、会话、存储格式/数据损坏或 PG 失败拒绝整个身份。持久化解码从不将腐败数据转成可用或不可用默认值。

## 来源与期限

实例、租户、主体、provider、issuer、配置版本来自同一权威会话，payload 不含这些字段。观察时间为 signed iat，截止为 min(iat + TTL, exp)，TTL 1–300 秒。最多 30 秒未来偏差仅允许认证，事实在 iat 前不可用；下一次权威读取才重新投影。

新认证重新观察；refresh、活动请求、重建组件不延寿。多个旧会话在各自原截止前可使用不同树，Identity 不维护全局最新目录。provider 更新/禁用、账户/成员/session 撤销沿用当前事务语义。link target 不替换 source 快照。

真实来源采用 Keycloak 26.7.3 内置 JSON UserAttributeMapper。管理员配置仅 admin 可查看/编辑的单个用户属性，关闭多值聚合，仅投影 ID Token。管理员负责完整树、稳定标识和各用户断言的同步；不新增 Java plugin、目录扫描或同步服务。此有界方案适合小型树；AAD/通用 OIDC 登录和组不意味着已具备部门能力。

## Owner 与验证

core 持有结构/映射，oidc 只在验签后解释输入，postgres 持有唯一持久化 codec、来源绑定和期限包装，http-axum 持有公开管理 DTO。复用现有时钟、会话和事务，不增加 crate、feature、目录表或通用 claims 框架。资源规则、子树授权及设备范围由 MDM 持有。

T1 验证树、输入与期限、旧契约拒绝、签名边界及不可伪造 wrapper。T2 验证真实 PG 的来源/撤销、大小上限与损坏拒绝，以及 Keycloak 管理员写入、普通用户不可改、移动/删除/转部门、多个会话与非法快照独立关闭。独立消费者固定同一完整 Git SHA 和自己的 lock/target。本仓 make ci 不替代 MDM 接入或产品 T3。

操作与 JSON 示例见[嵌入指南](../../guides/embedding.md#可选可信部门树快照)。上游对标见[来源索引](../../reference/sources.md#2451-部门树快照)。
