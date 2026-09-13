# #2340 固定候选生命周期验收

## 必要性与范围

T31 验证 binary/config/secret/TLS、PG、Hydra、Keycloak、RSS producer 与 listener 的实际装配和启停行为。低层 T1/T2 不足以证明该 join；本载体和验收记录归独立 [PR #1009](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1009)，产品部署修复归 [#2419 / PR #1008](https://dev.azure.com/shengming0923/rss/_git/rss-identity/pullrequest/1008)。执行矩阵、预算和排除项见[载体说明](../../t3/identity-lifecycle/README.md)。

## 固定输入与恢复

本次由本地干净 checkout 构建，没有 Azure pipeline run ID，也没有发布 registry/Pipeline Artifact。原件位于共享 RSS workspace 内的 `rss-identity/.local-ci-runs/2419-candidate/`，目录包含 `candidate.json`、三份 `*.oci.tar`、`binaries/`、`deploy.py` 和 `deployment/`。复制整个目录后用载体预检核对锁；不要复制 `*-probe-*` 开发目录。

| 身份 | 固定值 |
| --- | --- |
| Identity source | `06d4e85498281a874eff9898a3b77fc19705e8b1`，rss-identity PR #1008 |
| candidate.json SHA-256 | `01429fb94beed6e361749c1342f8f93389f18de47862a82a861c73a407ddd568` |
| 配置/schema | 该固定候选的配置格式，Identity schema v7，无旧格式适配 |
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

本轮替换首次验收证据：PR #1009 review 揭示旧载体的进程组回收与两层认证断言不足，旧 passed 记录不作为关闭依据。下述结果来自修复后的完整重跑，候选与锁保持相同。

2026-09-12 UTC，以干净载体提交 `3ff0cb5ef93ee7e97acff20615d955a81fc6b8e8` 执行完整序列，命令退出 0；[原始结构化结果](../../t3/identity-lifecycle/evidence/20260912-result.json)记录 11 阶段全部 passed、`not_run=[]`、`cleanup=true`，容器/网络/卷剩余数量均为 0。清理前已完整采集本次仍存的 8 个容器 inspect 和 log tail，原件均为 0600 私密文件；公开 JSON 只保存采集安全摘要。记录提交只新增证据与文档，执行代码及锁文件逐项摘要与记录一致。

```sh
make test-lifecycle LIFECYCLE_CANDIDATE=/Users/shengming/Documents/code/rss/rss-identity/.local-ci-runs/2419-candidate LIFECYCLE_OUTPUT=/Users/shengming/Documents/code/rss/rss-identity/.local-ci-runs/2340-lifecycle-fix-1009-01
```

环境为 Python 3.14.6、Docker 29.7.2 / Compose 5.5.1；Engine `linux/arm64`，三份产品镜像仿真 `linux/amd64`，固定多架构 provider 使用原生 ARM64。具体解析后的镜像 ID/平台、原始与隔离后 Compose 摘要均在结果中。

| 实测场景 | 观察结果 |
| --- | --- |
| 候选与安装 | 只消费摘要匹配的只读快照；真实文件 UID/GID/权限；schema v7 与内嵌迁移身份匹配；首次管理员初始化成功 |
| 健康基线 | 公布的 HTTPS 端口返回固定 UI revision；本地登录 200；真实私网网关缺失/错误服务密钥均为 401 invalid_client；正确服务密钥配错误业务凭据为 401 invalid_credential；Keycloak provider test 通过 |
| 冷启动故障 | PG 停止时 server 退出 1；Hydra authenticated admin 停止时 live 200 / 不 ready，实际 Compose 网关启动被拒绝、端口未开放；Keycloak 停止不影响 readiness，provider test 失败 |
| 运行中故障 | PG 故障时会话 503；Hydra 故障时在线验证 identity_unavailable、本地登录可用；Keycloak 故障时 provider 失败、本地登录可用；三者恢复均无需重启 Identity |
| 部分启动 | 已接入 PG 后监听 bind 失败，退出 1，runtime PG 连接数归零 |
| 正常排空 | PG 锁确认已有请求入库；SIGTERM 后新请求未进入 SQL，原请求完成；退出 0，实测 0.610 秒；子进程组已回收 |
| 超时排空 | 保留 PG 锁，内部预算耗尽后退出 1，实测 19.735 秒；非 OOM，早于外部 40 秒强杀；子进程组已回收 |
| 保留卷重启 | 部署身份、storage lineage、已提交 Outbox 记录保留，原会话 200；重复 initialize 退出 1 |
| 错配拒绝与恢复 | schema 版本缺失、config identity 代际错误均拒绝 migrate/server；不自动修复；恢复正确输入后可启动 |

25 项载体单测及 3 项共用进程单测通过，覆盖摘要/快照替换、阶段/清理误报、dirty/changed harness、异常结果写入、二次中断、进程组回收与真实跨进程分配互斥。完整产品 `make ci` 结果由 PR 交接评论另行记录，不能以此替代本 T3 实测。

合成 CA、秘密和故障预算仅用于本次验收；原始私密诊断未提交。本记录不提供性能/容量、生产 DNS/证书/SLO、备份 RPO/RTO、多副本、完整本地账户/SSO/MFA/恢复矩阵、完整 Outbox/relay/Inbox 或真实 MDM 授权证明。
