# #2340 固定候选生命周期验收

## 必要性与范围

T31 验证 binary/config/secret/TLS、PG、Hydra、Keycloak、RSS producer 与 listener 的实际装配和启停行为。低层 T1/T2 不足以证明该 join；本载体和验收记录归独立 [PR #1009](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1009)，产品部署修复归 [#2419 / PR #1008](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1008)。执行矩阵、预算和排除项见[载体说明](../../t3/identity-lifecycle/README.md)。

## 固定输入与恢复

本次由本地干净 checkout 构建，没有 Azure pipeline run ID，也没有发布 registry/Pipeline Artifact。原件位于共享 RSS workspace 内的 `rss-identity/.local-ci-runs/2419-candidate/`，目录包含 `candidate.json`、三份 `*.oci.tar`、`binaries/`、`deploy.py` 和 `deployment/`。复制整个目录后用载体预检核对锁；不要复制 `*-probe-*` 开发目录。

| 身份 | 固定值 |
| --- | --- |
| Identity source | `06d4e85498281a874eff9898a3b77fc19705e8b1`，rss-identity PR #1008 |
| candidate.json SHA-256 | `01429fb94beed6e361749c1342f8f93389f18de47862a82a861c73a407ddd568` |
| 配置/schema | 当前配置格式，Identity schema v7，无旧格式适配 |
| UI source | rss-web `37b7fb356aa7e436cc708caa1593427e6d553d30` |
| UI dist SHA-256 | `074055e9978964d1fd38cf88b70cba6aa93797e6eaba20a5d8abe80e26654c15` |
| RSS source | `93ce6848b7c78753df9947bd08abfb37e5799838`，单一固定 Git 消费 |
| 编译 | Rust 1.96.0；原生构建器交叉编译 Linux amd64 |

[Identity 固定源码](https://dev.azure.com/shengming0923/rss/_git/rss-identity?version=GC06d4e85498281a874eff9898a3b77fc19705e8b1)、[UI 固定源码](https://github.com/shengming0817/rss-web/tree/37b7fb356aa7e436cc708caa1593427e6d553d30) 及各自 lock 是重建来源。按[候选构建](candidate.md)在两个干净固定 checkout 生成 UI，然后执行：

```sh
make candidate CANDIDATE_OUTPUT=/absolute/new-candidate IDENTITY_UI_SOURCE=/absolute/fixed-rss-web IDENTITY_UI_DIST=/absolute/fixed-rss-web/apps/identity/dist
```

重建可能生成不同 archive/manifest 字节；不能用同一 Git SHA 冒充原件摘要。原件丢失或需要新候选时，重新审查构建 manifest、原子更新 T31 锁和本记录，并重跑完整矩阵。候选是可再生构建产物；唯一测试代码和实际验收记录必须保留在 Git。没有将本地原件宣称为已持久发布的制品服务。

## 原候选与独立修复

原批准候选 `7e1e11dfcfad18af764f60a18671be536640573d`，manifest SHA-256 `f4549eebeb00f216c23e7df83078ba66609c88e5a20fd2fab8e75524b27c2888`，在真实 Compose 解析 volume-init shell 时失败。#2419 修复 Compose 字面量、动态 IP 抢占、内外 HTTPS 端口及公网网络/固定 provider upstream 接缝。开发源码探针只用于定位，未作为固定候选 T3 通过证明。

修复 HEAD 的 `make ci CI_BASE=origin/develop` 已通过，包含真实 PG/OIDC/装配/网关/恢复 T2；这些结果独立于下面的 T31 实测。

## T31 实际结果

最终固定候选完整运行正在执行；在经检查的结果提交前，本记录不表示 T31 已通过。
