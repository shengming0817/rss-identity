# 安装与操作

在 Linux Docker 部署主机使用本仓 hack/deploy.py / hack/operate.py（部署只需脚本、deployment 配置及已准备的镜像）。复制 `deployment/deploy.example.json` 为私有输入，填写随机 instanceId、storage target/lineage、租户与唯一 bootstrap principal、固定 HTTPS origin 和秘密路径。`runtime.publicGateway` 必须等于 backendSubnet 的 .2；Identity .3、PostgreSQL .4，网段为不冲突的私有 /24。公开入口仅 HTTPS 443，租户登录入口 `/tenants/{tenant-uuid}/login`（例如 `https://identity.example.test/tenants/11111111-1111-4111-8111-111111111111/login`），API `/api/v2`，唯一 callback `/api/v2/oidc/callback`。

每个 `storage.tenants` 中的租户使用自己的登录 URL；将 origin 与该租户 UUID 组合后交给用户。根路径 `/` 不负责选择租户。

准备公共 TLS 证书及私钥，证书 SAN 覆盖 origin；PG 证书 SAN 含 postgres，database.caFile 信任其 CA。每个数据库角色用不同的私有 0600 密码文件，无尾部换行；口令长度和内容须满足宿主配置校验。OIDC 为空即本地模式。开启时配置 stateKeyFile、credentialKeyring、assuranceProfiles、groupFactsMaxAgeSeconds 及 `returnTargets: {"resume":"https://固定域名/auth/resume"}`，字段以 RuntimeConfig 为准。state/keyring 钥文件为非零 32 字节随机钥的 64 位十六进制，不能复用。

```sh
sudo python3 hack/deploy.py --input /private/deployment.json --output /private/rendered --identity-image rss-identity:my-version --web-image rss-identity-web:my-version
python3 hack/operate.py --deployment /private/rendered --project identity-main install
python3 hack/operate.py --deployment /private/rendered --project identity-main verify
python3 hack/operate.py --deployment /private/rendered --project identity-main initialize <tenant-uuid> <login> /private/new-password
python3 hack/operate.py --deployment /private/rendered --project identity-main open
```

输出目录必须不存在；root 渲染为服务 UID/GID 10001:10001，目录0700、文件0600。操作命令由有权读取此目录和使用 Docker 的部署 owner 执行；新口令文件也须归10001且0600。同一输入生成 runtime、maintenance、owner migration 和严格静态 UI JSON。渲染在同父目录的私有临时目录完成，使用同一后端镜像的三个程序 `--check-config FILE` 在无网络容器内复用 Rust 的配置、秘密与契约校验；同时以实际 Web 镜像、仅网关配置与 TLS 挂载离线运行 nginx -t，并核对静态 index.html 与 identity-build.json 存在。全部通过才原子发布，错误镜像角色或网关配置在开放前拒绝；失败清理临时输出并允许原路径重试。不要手改生成配置或二次 envsubst；Compose 字面量已转义。首次 install 只安装数据库结构与角色授权；不会创建账户或开放入口。

`initialize <tenant> <login> <password-file>` 的 principal 取自该租户唯一 bootstrapAccounts。组件一次性 guard 拒绝重复、并发输家及重启后重做；旧 principal 参数形式拒绝。新 tenant 必须显式交由宿主配置，不提供平台租户 API。维护恢复命令为 `recover <tenant> <principal> <password-file>`，仅更新既有本地密码和 epoch，保持 enabled/member 与管理策略不变。

`verify` 是只读安装核验，检查 schema、instance、目标角色及有效权限、storage identity 和完整 tenant fence；不补建、不修授权、不初始化。`close` 先停网关再排空 Identity，并核对容器身份、终态、退出码与 OOM 状态；重启中/暂停/未知状态不视为关闭。`open` 先核验、再等待 Identity 内部健康检查、最后开放网关。非零退出或中断均不确认成功，先检查实际状态；不自动重发写命令。

网关固定提供 `/api/identity-host/v1/config.json`（canonicalOrigin/oidcEnabled）；UI 缺失或畸形时拒绝启动。唯一动态宿主资源 `/api/identity-host/v1/tenants/{tenant}/context` 读取权威会话，展示与宿主策略一致的管理提示；管理请求仍由组件事务内授权。网关覆盖来源头、保留原 API 路径且关闭代理重试，PG 不向宿主发布端口。日常容器不挂载 owner/maintenance 秘密。

回退只允许已验证、同 schema 和同 instance/storage 配置的后端镜像。切换前 close，在新私有渲染目录绑定镜像，verify 后 open；不得回滚数据库撤销状态。未知提交不等于失败回滚。实际切换和故障恢复证据由 #2366 保存。

全部服务（含 postgres、volume-init）由 compose.json 固定 image ID 和 pull_policy=never，不写平台字段；操作前核对本地镜像存在，当前 Docker daemon 负责选择并运行其默认平台。所有操作按 Docker daemon ID 与 project 获取跨进程排他锁；restore 按排序同时锁源、目标，锁竞争立即拒绝。每个 Docker 主机使用唯一部署 owner 和共享的 `/var/tmp/rss-identity-operations`；直接 Docker 操作或另一个未共享锁目录的控制主机不受该锁约束，维护期间必须禁止这些旁路。锁文件保留，文件描述符关闭释放锁；不要手删活跃锁文件。

操作输出是脱敏 JSON：`operation`、`stage`、`reason`、`outcomeKnown`、`status`。前置拒绝与只读核验失败标识已知结果；写入进程超时/失败或排空未确认标识未知，先运行 `verify`、`verify-keys` 或只读 `docker inspect`，不可自动重试写入。原始 stderr、配置和秘密值不进入诊断。

OIDC 默认只连接公网单播目标。拒绝私网、loopback、link-local、metadata、保留地址、IPv4 映射及过渡 IPv6；DNS 的全部 A/AAAA 必须通过校验，reqwest 直接消费这组地址，禁止代理和重定向。私网 IdP 不在当前参考部署支持范围，测试 loopback 仅由 test-support 显式构造，不由生产配置开启。

仅更新前端时，保持 --identity-image 和宿主配置不变，以新 --web-image 渲染新目录。通过原部署 close 后在新目录 verify/open；后端不需重建，备份只绑定后端版本。前端管理导航请求的网络、超时或合法 503 暂不可用保留已接受会话，隐藏提示依赖的入口并提供手动重试；401、协议错误与身份不匹配继续拒绝。
