# 停机备份、恢复与密钥轮换

适用于新部署的同版本、同环境/origin 恢复到选定切点。部署 owner 负责恢复点、秘密保管与最后开放；工具不判断任意旧快照是否包含故障前全部撤销。缺少完整安全状态、当前配置或必需密钥时保持隔离，不通过改 epoch、初始化或直接改账户表重新开放。

## 备份

以下命令中的绝对路径由部署 owner 选定。使用已交付候选的 compose.json 和 providers.lock；备份目录应处于加密存储、权限 0700，禁止公开渲染目录、数据库备份或密钥。

1. 记录 candidate.json 摘要、Identity/RSS/UI SHA/lock、schema、配置身份及 provider digest。停止公私网入口，再排空 Identity 并停止 Hydra、Keycloak及其它写入者：

   ```sh
   docker compose -f /private/rendered/compose.json stop public-gateway private-gateway
   docker compose -f /private/rendered/compose.json stop identity hydra-admin hydra keycloak
   ```

2. PostgreSQL 保持运行，使用其原生工具备份整集群，包含 Identity、Hydra、Keycloak 数据库及角色。`/tmp/identity-backup` 必须不存在；不要覆盖已有备份：

   ```sh
   docker compose -f /private/rendered/compose.json exec -T postgres pg_basebackup -U postgres -D /tmp/identity-backup -Fp -X stream -c fast
   docker compose -f /private/rendered/compose.json exec -T postgres pg_verifybackup /tmp/identity-backup
   docker compose -f /private/rendered/compose.json cp postgres:/tmp/identity-backup /private/backups/cut-001
   ```

   此命令使用受控容器内数据库本机身份；不同 PG 部署按其认证配置使用专用备份身份，密码从受控文件读取。禁止降低数据库访问控制来运行备份。

3. 外部副本复制完成后，在同版本 PG 工具中再次校验，记录 manifest 摘要后才清理容器内这个临时目录。外部 cut-001 备份继续保留：

   ```sh
   PG_IMAGE=$(python3 -c 'import json; print(json.load(open("/artifacts/candidate.json"))["providers"]["postgres"])')
   docker run --rm --user 0:0 --entrypoint pg_verifybackup -v /private/backups/cut-001:/backup:ro "$PG_IMAGE" /backup
   shasum -a 256 /private/backups/cut-001/backup_manifest > /private/backups/cut-001.manifest.sha256
   # 仅在上述两步成功后执行；不删除外部副本。
   docker compose -f /private/rendered/compose.json exec -T postgres rm -rf -- /tmp/identity-backup
   ```

4. 记录并独立保管 backup_manifest 摘要、PG system identifier/WAL 范围和切点时间；配置、证书、所需 system/cookie key 集合和当前服务秘密另行保管。Keycloak realm export 不能代替数据库备份。源端恢复写入后，该备份不再证明之后的安全状态。

## 恢复与开放

1. 保持入口、Identity、Hydra、Keycloak 停止，停止源 PG，保留原卷。恢复到新的空目标卷，不覆盖唯一现存数据。
2. 使用与备份一致的 PG17 工具校验并复制到新卷；参考部署 PG UID/GID 为 10001:10001。下面 `PG_IMAGE` 从实际候选读取，不使用浮动镜像：

   ```sh
   PG_IMAGE=$(python3 -c 'import json; print(json.load(open("/artifacts/candidate.json"))["providers"]["postgres"])')
   docker volume create identity-restore-cut-001
   docker run --rm --user 0:0 --entrypoint sh \
     -v /private/backups/cut-001:/backup:ro \
     -v identity-restore-cut-001:/restore \
     "$PG_IMAGE" -ec 'pg_verifybackup /backup; test -z "$(ls -A /restore)"; cp -a /backup/. /restore/; chown -R 10001:10001 /restore; chmod 700 /restore'
   ```

   不能仅凭校验成功跳过启动后的实际核验。
3. 保留源卷，释放原参考拓扑的容器/网络，使用显式目标卷启动。`down` 不附加 `--volumes`；此处不会删除源数据。将以下内容保存为私有 `/private/restore-volume.json`：

   ```json
   {"volumes":{"pg":{"external":true,"name":"identity-restore-cut-001"}}}
   ```

   ```sh
   docker compose -f /private/rendered/compose.json down
   docker compose -p identity-restored -f /private/rendered/compose.json -f /private/restore-volume.json run --rm volume-init
   docker compose -p identity-restored -f /private/rendered/compose.json -f /private/restore-volume.json up -d postgres
   docker compose -p identity-restored -f /private/rendered/compose.json -f /private/restore-volume.json run --rm migrate
   docker compose -p identity-restored -f /private/rendered/compose.json -f /private/restore-volume.json up -d hydra hydra-admin keycloak
   docker compose -p identity-restored -f /private/rendered/compose.json -f /private/restore-volume.json run --rm hydra-clients
   ```

   固定 schema、环境/origin、storage identity、provider 版本和当前秘密。不得运行账户初始化、重新创建用户或自动 down migration。原站点与恢复站点不能同时接入同一产品流量。
4. 运行候选中的 `identity-migrate` 作同版本结构/身份/权限核验（已有安装分支不会修复或重新授权），再启动 Hydra/Keycloak，验证实际 client 凭据。保持网关未开放，核对账户禁用、member/provider 状态、维护改密结果、撤销会话、Outbox 及旧 Hydra 凭据的 Identity 拒绝结果。
5. 只有选定恢复点确实包含所需安全状态、provider/秘密核验和独立 T3 均通过，才由部署 owner 启动 Identity 并最后开放网关。任意步骤失败保留隔离；不自动回滚数据库或重发未知远程操作。

本次 T2 使用临时卷演练以上原生机制，覆盖备份损坏和两种真实恢复点。历史切点会恢复历史账户事实；本项目没有额外库外状态源，不能宣称自动阻止这种回退。生产 RPO/RTO 需在真实资源及可接受数据损失范围下另行冻结。

## 轮换矩阵

所有轮换先关闭入口并停止相关调用方，保留必要恢复材料，使用新私有渲染目录；应用重新启动读取文件，不假定热更新。原秘密文件不可覆盖仍在使用的候选配置身份。

| 材料 | 操作与验证 |
| --- | --- |
| 应急管理员口令 | 每次使用结束立即 `identity-admin recover`，确认 emergency/enabled/member 状态未被扩大；验证旧口令、中央 cookie 与下游凭据失效。受控保管和人工使用归属由部署入口记录。 |
| PG runtime/maintenance/owner、Hydra/Keycloak DB 密码 | 数据库 owner 用 PostgreSQL `ALTER ROLE` 在受控交互任务中更新，再同步私有文件；重启所有持有旧连接池的服务。必须以新连接证明旧密码拒绝、新密码成功，不能用缓存连接证明轮换。 |
| OIDC client secret | Keycloak 原生 client-secret 轮换；分配新 secret_ref，显式更新 provider 配置版本和部署允许绑定。取消在途流程，验证旧 secret 兑换失败、新配置重新登录成功。需要撤销已建立联合会话时显式停用/重新启用 provider。 |
| Identity state key | 生成独立新 32 字节 key 并更换 state_key_file，重启服务；全部旧 state 拒绝，用户重新开始登录。没有双钥窗口。 |
| 下游 OIDC client secret | 通过 Hydra 原生 admin API 在维护窗口替换，同步产品后端文件；`identity-clients` 仅核验最终配置，不自动覆盖漂移。旧 client secret 必须认证失败。 |
| Identity validation / Hydra gateway service secret | 同步调用双方文件和渲染配置，重启双方；旧 secret 拒绝、新 secret 成功。凭据轮换本身不替代账户/会话撤销。 |
| Hydra system / cookie keys | 使用必填有序 `hydra_system_secret_files`、`hydra_cookie_secret_files`，分别 1–8 个不重复密钥，两域不重用。新钥置首，旧钥仅在数据仍需解密时保留。实测旧签名 key 在新旧 keyring 中可读，提前移除旧 system key 后不可读；过期 token 不代表所有持久加密数据都已退出。 |
| TLS 证书/私钥/CA | 使用同一既定 hostname/SAN，先准备双方信任配置，再在窗口内更换并重启。逐接缝验证 VerifyFull/TLS 成功及错误/退出 CA 拒绝。变更 origin 是独立身份迁移，不作为证书轮换处理。 |

Hydra 旧数据不会自动重新加密。没有可靠旧钥退出证据时保留所需 key；不自写上游 SQL、不使用已退出的 migrate-secret 命令，也不以重建 Hydra 数据库冒充无损轮换。

## 可重复验证与测量

- `make test-recovery`：临时 PG 物理备份/恢复、真实持久 Hydra/Keycloak、选定切点拒绝旧凭据、旧快照反例、数据库新连接密码轮换。
- `make test-federated`：真实 TOTP 与 Keycloak client-secret 轮换。
- `make test-clients`：真实持久 Hydra client 凭据、重启及原生 keyring 保留/错误移除旧钥。
- `make measure-capacity`：单进程 consumer，1 tenant、16 accounts、8 grants；并发 1/4/16，每组 64 次请求。统计包含失败，登录限流/KDF 拒绝也如实计入；独立组前重置 fixture 尝试预算，组内不重置。清理只测 8 个 grant 的一次失效处理，不代表最终删除。

测量输出绑定当前源码/dirty 状态、lock、provider/架构；它没有性能门禁或生产 SLO。正式接受前在固定候选、实际资源配额和负载上重测，记录失败类型及未覆盖场景。

独立候选与生产验收：[MFA #2366](https://dev.azure.com/shengming0923/rss/_workitems/edit/2366)、[恢复/轮换与生产目标 #2367](https://dev.azure.com/shengming0923/rss/_workitems/edit/2367)。
