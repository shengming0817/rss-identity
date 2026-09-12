# Identity 生命周期 T3（#2340）

本载体消费固定候选，验证 binary、配置/秘密、TLS、PG、Hydra、Keycloak、RSS producer 和监听器在启停中的组合边界。它不构建产品，也不从执行 checkout 读取部署模板：renderer、字段示例、镜像、二进制和迁移身份均来自候选。产品缺陷由独立实现项 #2419 / PR #1008 修复。

固定版本、原件位置和重建边界见[本次验收记录](../../docs/deployment/202609120756-2340-lifecycle-acceptance.md)。

## 执行

需要 Unix 主机、Python 3.11+、本地 Docker Engine、Compose 和足够的本地容器资源。候选三份 OCI 为 Linux amd64；ARM64 Engine 使用仿真运行产品镜像，固定 provider 多架构摘要按 Engine 原生架构解析。结果逐项记录实际镜像 ID/架构；该环境不提供性能或容量结论。

```sh
make test-lifecycle LIFECYCLE_CANDIDATE=/absolute/fixed-candidate LIFECYCLE_OUTPUT=/absolute/new-result
```

载体 checkout 必须是干净提交；输出目录必须不存在。`candidate.lock.json` 固定整个 manifest 与三个部署文件的 SHA-256；预检继续核对三份 OCI、四份二进制、镜像 revision/user/platform。已锁定文件复制到本次 0700 目录下的只读快照，重新校验后只从快照加载镜像和执行 renderer；结束时再次复核快照及载体代码/锁文件摘要。换候选必须审查并更新锁文件，重新执行完整序列，不支持跳过阶段、历史配置适配或旧 schema 自动修复。

```sh
python3 -m unittest discover -s t3/identity-lifecycle -p 'test_*.py'
```

上面的轻量测试只验证载体的 artifact 防替换、结果防误报和进程/清理边界，也随 `make test` 运行。它不能代替真实 T3。

## 顺序和判定

| 阶段 | 必须观察到的行为 |
| --- | --- |
| candidate / prepare | 完整摘要匹配；真实 daemon 文件系统保留 UID/GID/权限；独立 Compose 项目、网络和卷 |
| install / healthy | 新卷安装 schema v7；内嵌迁移摘要一致；管理员只初始化一次；公布的 HTTPS 端口提供对应 UI；本地登录、Hydra 验证拒绝无效凭据、Keycloak provider test 通过 |
| cold_dependencies | PG 不可用拒绝启动；Hydra 认证 admin 停止时 live 但不 ready，实际网关启动被 health 依赖拒绝；Keycloak 不可用仍 ready，provider test 失败；各自恢复 |
| running_dependencies | PG 故障拒绝业务；Hydra 故障拒绝在线验证而本地登录可用；Keycloak 故障只影响对应 provider；Identity 不重启即可恢复 |
| partial_start | 在 PG 已装配后制造监听 bind 失败，非零退出并释放 runtime PG 连接 |
| clean_drain / timeout_drain | PG 锁确认真实请求已进入数据库；SIGTERM 后新请求不能进入该 SQL；及时释放锁时已有请求完成并退出 0，保留锁时资源预算耗尽、非零退出且不是 OOM/外部强杀 |
| persistent_restart | 保留卷重启；部署身份、storage lineage、已提交 Outbox 记录及中央会话保留；重复初始化被拒绝 |
| mismatch | 缺失 schema 版本、配置身份代际错误均拒绝 migrate/server；不自动修复；恢复正确输入后可启动 |

排空观察允许前端返回 503（关闭的 admission）或 502（监听器已停止接受连接）；同时核对 SQL waiter 数量，不能只凭网关错误码宣称没有新工作。请求预算 20 秒、资源预算 8 秒、总排空 25 秒，Docker 外部 grace 40 秒；这些是合成故障输入，不是生产 SLO。

## 隔离和证据

随机租户、主体、存储身份、管理员口令及服务秘密仅属于一次运行。合成 CA/证书与秘密在专用 Docker 卷生成；root 准备器按产品要求交付 0600/指定 owner，不放宽产品权限验证。公网端口仅发布到主机 loopback，consumer 使用独立网络；不连接开发数据库，不读取用户产品秘密。

隔离变换仅设置项目名、镜像运行平台/禁止拉取和随机 loopback 主机端口。变换前必须确认 renderer 公网端口为 `443:443`，容器端口保持 443；原始及隔离后 Compose 摘要均入结果，不修正候选的产品拓扑。

同一主机用户按 Docker Engine ID 互斥分配子网，直到 Compose 实际创建网络再释放；锁等待上限 60 秒。系统临时目录保留无内容的 0600 锁文件，以免删文件造成不同 inode 的并发锁。排空故障的三个子进程组分别以 wait/TERM/KILL 回收，每次等待上限 2 秒；某组失败仍继续其余组，失败结果不能通过。

清理有独立 120 秒总预算（超时进程组另有最多两次 2 秒终止宽限），二次中断记录为状态并继续回收；超时/失败报告剩余资源数量与枚举是否完整。清理按本次唯一 Compose / fixture ownership label 枚举资源，即使 Compose 解析或 Docker 创建半途失败也执行。`result.json` 只有在全序列依次通过且清理成功时才标 passed；失败保留阶段、非秘密状态和未运行项。清理失败也必须失败。正常完成移除本次容器、网络及所有卷，不删除其它项目资源或共享镜像。

`result.json`、公开 CA 和 Compose 路径/摘要不含秘密值。`diagnostics.private.log` 可能包含工具错误原文，仅在本地 0700 输出目录中按 0600 保存，不提交或上传。不要发布整个输出目录；验收记录只接纳经检查的 `result.json`。固定候选本身和本地运行目录均为可再生产物，唯一代码/验收记录必须提交 Git。

未覆盖：完整本地账户矩阵（#2341）、完整 SSO/MFA/恢复矩阵（#2342/I09）、消息 relay/Inbox 或完整 Outbox 故障矩阵、真实 MDM 授权接入、生产 DNS/证书/容量/SLO、备份 RPO/RTO 与多副本。

参考源码：CPython v3.11.13 `Lib/subprocess.py`；docker/compose v5.5.1 `pkg/compose/stop.go`。复用本仓 `hack/bounded_process.py` 的进程组预算；最终拓扑由候选 renderer 持有。
