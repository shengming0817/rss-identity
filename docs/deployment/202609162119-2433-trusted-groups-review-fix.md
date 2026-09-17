# #2433 外部审查修复后的固定 SDK 与候选

本记录替代[首轮候选记录](202609162037-2433-trusted-groups.md)。交付 PR 为 [#1026](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1026)，审查来源为 [F1–F4](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1026?discussionId=14152)。本记录绑定实际完成的修复与 T1/T2、固定 Git consumer、Linux amd64 构建及运行冒烟；本轮最终 `make ci` 结果由 PR 验证评论追加。

## 修复与决定

- F1：保留用户批准的“来源和当前版本检查”，修正 I05 旧文档。provider 配置版本变化仍使旧联合身份拒绝；部署级 TTL 调整不改变 provider 版本，也不重算旧快照期限。#2427 已明确配置/凭据变化使旧流程和会话失效。
- F2：固定允许最多 30 秒未来签发偏差。偏差内认证可成功，但本地时间未到 `iat` 时只保留基础身份，组为 `unavailable/not_yet_valid` 且没有集合。超过偏差拒绝。期限仍是 `min(iat + TTL, exp)`，不按采集、刷新或偏差重新起算。PG 和 SDK 共用时间校验；`not_yet_valid` 与 `expired` 均是派生状态，不写入快照。
- F3：SDK 根导出 `GroupSource` 和 `UnavailableReason`；仅直接依赖 client 的 consumer 能命名来源并精确匹配 `ClaimMissing`、`LocalIdentity`。
- F4：contracts 唯一持有 Rust TTL 常量及窗口/偏差判定，core、PG、client 复用。Rust 配置测试把该 owner 的边界值传给 Python renderer 实际谓词，锁住跨语言一致性；没有新增生成框架、部署字段、crate 或数据库迁移。

F2/F4 已合并为一次具体批量处置请求；两分钟未回复后，按用户事先规定的“无响应按推荐选项继续”执行当前 PR 修复。不是把超时声称为明确答复。新鲜度窗口以签名 `iat` 为坐标，跨系统墙钟受 30 秒允许偏差约束，不声称零偏差 SLO。

## 固定来源与依赖

| 项目 | 固定值 |
|---|---|
| Git 仓库 | `https://dev.azure.com/shengming0923/rss/_git/rss-identity` |
| 实现 / SDK / 候选完整 SHA | `e747035c7e4834438d8249ef8d9578904d28227d` |
| package / groups 契约 / 内部快照 | `0.1.0` / `groups.version=1` / `auth_facts.format_version=1` |
| 安装 schema | v8，无迁移 |
| Identity Cargo.lock SHA-256 | `2f2664401565d1051ee8f254e06a32a89240ca8de987a940f8bc30912f38fe2f` |
| 独立 consumer Cargo.toml SHA-256 | `9bad4208a092a22c4d80a930e54a2c90addde85feffe6a9be583a380130c40cd` |
| 独立 consumer Cargo.lock SHA-256 | `312d87ad7e8ef026e3c752a08a1f84642fc654a4f165335f7a246b0c33e1643f` |

独立 consumer 的 Identity 依赖闭包只有 client/contracts，二者均来自该 Git revision，features 均为空；没有 core/PG/HTTP/server crate、本地 path、patch 或 source replacement。代码取此 revision 的 `tests/consumer`；沿用[独立消费复现方法](202609162037-2433-trusted-groups.md#独立消费复现)，将旧 revision、目录和摘要换为本记录值。consumer 的 Cargo.lock 仅给 client/contracts 两项增加精确 Git source，其他解析未变化。测试从 `/tmp` 运行以排除祖先 Cargo 配置，使用独立 workspace/lock/target 与系统 Git credential helper。

## 已完成的实际验证

| 命令/载体 | 结果 |
|---|---|
| core 时钟偏差最小用例 | 先因 1 秒未来 iat 返回 Claims 而 RED，实施后 GREEN |
| client 独立消费编译 | 先因缺少根导出而 RED，实施后 GREEN |
| core groups / client / PG codec / app 配置边界 | 通过；覆盖 1/30/31 秒、缺失/未配置/真实空组、不得提前使用、严格到期、派生状态拒绝持久化、Python/Rust 边界一致 |
| `make check` | fmt、clippy、locked check 全通过 |
| `make test-pg` | 完整通过，federated_atomic 由 14 增至 15 项；新用例在真实 PG 证明允许偏差保留 session，超限拒绝且不留下 JIT 身份 |
| 真实 PG + Keycloak + Hydra + 固定 Git consumer | 完整 downstream 10 PG + 3 HTTP 场景通过；consumer 四次调用均真实 `1 passed` |
| `make candidate` | 固定干净源码的 Linux amd64 构建、server/operator 运行冒烟及非 root gateway HTTP 冒烟通过 |

固定 Git consumer 的实际结果（不记录凭证、组全集或 provider 原文）：

```json
[
  {
    "passed": true,
    "scenario": "local_identity_logout",
    "timestamp": 1789593553
  },
  {
    "passed": true,
    "scenario": "available",
    "timestamp": 1789593558
  },
  {
    "passed": true,
    "scenario": "missing",
    "timestamp": 1789593559
  },
  {
    "passed": true,
    "scenario": "expired",
    "timestamp": 1789593588
  }
]
```

本轮保留登录、step-up、来源重认证、跨 provider 关联、CLI 延迟兑换、refresh、多个旧 session、同租户第二 client、撤组/重新登录、provider 配置/停用/恢复与依赖失败证明。Keycloak 26.7.3 零成员省略 claim，故真实撤组精确得到 `ClaimMissing`；实际签名空数组仍为可用空集合。新 SDK 的临界时间转换由确定性 Clock 用例验证。

## 候选摘要

输出：`rss-external-check/identity-2433/candidate-e747035`，包含 candidate.json、server/operator/gateway OCI archives、二进制与部署模板。固定 SDK 可再生目录为 `rss-external-check/identity-2433/sdk-e747035`；这些被忽略目录不持有唯一源码或唯一验收结论。实际构建命令：

```sh
make candidate CANDIDATE_OUTPUT=/absolute/new-candidate \
  IDENTITY_UI_SOURCE=/absolute/fixed-rss-web \
  IDENTITY_UI_DIST=/absolute/fixed-rss-web/apps/identity/dist
```

| 镜像 | OCI manifest digest | archive SHA-256 |
|---|---|---|
| server | `sha256:5cad77b9423a8ee6e012a675a32bfdd70ff563c72f1826d5c7b3c73f6f8441eb` | `063e2912afe1b6ac718d607a35c14e6f114252c4668b46508cfa4102547b8483` |
| operator | `sha256:7f018351747859bd65927e34e28ec63999bd20457fe95c760881cde197673f12` | `8083831822e95cab9dc1fa9e18df6a59b749335ce61517b2bd3e8842917dc543` |
| gateway | `sha256:b7e26fa6ff214099b73bfc4edf497a6f03bdb75618e7ea18bf7898a6bda7ee5e` | `9055b71d54baae272eaa1bee1a1bef41ef74a056159acbed2a084cf6ee9cea1d` |

全部归档实际内容 SHA-256 已重新核验。二进制摘要：

- `identity-admin`：`7453af5131b00d3e033f80e7a417916751d459d912b1c864ff1f1d5cce8cf611`
- `identity-clients`：`3d4bfb7b94c93217ba21a2ff965e09b74c70f170b7c3a20aa2259a9e8fc07997`
- `identity-platform`：`c0988deeb3c48f11c4fedbc6188458b31beb80bed1173b28c51049ef2b1243f5`
- `identity-server`：`903e7940bf7e4ab044ba0e34da294413d102736297f6f27b996df96920d52705`
- `identity-migrate`：`dd3aa6d77f12419859559e0c9d3505e1a4ea1f06c68b0725d327580c0a88d5e9`

UI 源码 `37b7fb356aa7e436cc708caa1593427e6d553d30`、UI lock `83740dc4c49b44d5298bece9ceb67536599facafa3f3c7837e227b7c008c06d3`、dist `074055e9978964d1fd38cf88b70cba6aa93797e6eaba20a5d8abe80e26654c15`，与首轮完全一致；没有 UI 改动。provider 镜像、Rust 1.96.0、RSS 固定来源及生产 features、迁移/schema 摘要与[首轮记录](202609162037-2433-trusted-groups.md#候选摘要)一致，并已对比两份 candidate.json 核验。候选在 ARM Linux build 容器交叉编译 linux/amd64，未推 registry。私有 Git 获取仍走一次性 BuildKit secret，凭据文件已移除。

公开部署/初始化沿用候选模板和[运维入口](operations.md)。本项不声明产品 T3、生产容量/RPO/RTO，也不等待 #2363；MDM 后续固定消费本记录 revision 并持有资源授权映射及接入 T2。
