# 安装与操作

使用候选中的 deploy.py / operate.py。复制 `deployment/deploy.example.json` 为私有输入，填写随机 instanceId、storage target/lineage、租户与唯一 bootstrap principal、固定 HTTPS origin 和秘密路径。`runtime.publicGateway` 必须等于 backendSubnet 的 .2；Identity .3、PostgreSQL .4，网段为不冲突的私有 /24。公开入口仅 HTTPS 443，UI `/`，API `/api/v2`，唯一 callback `/api/v2/oidc/callback`。

准备公共 TLS 证书及私钥，证书 SAN 覆盖 origin；PG 证书 SAN 含 postgres，database.caFile 信任其 CA。每个数据库角色用不同的私有 0600 密码文件，无尾部换行；口令长度和内容须满足宿主配置校验。OIDC 为空即本地模式。开启时配置 stateKeyFile、credentialKeyring、assuranceProfiles、groupFactsMaxAgeSeconds 及 `returnTargets: {"resume":"https://固定域名/auth/resume"}`，字段以 RuntimeConfig 为准。state/keyring 钥文件为非零 32 字节随机钥的 64 位十六进制，不能复用。

```sh
sudo python3 /artifacts/deploy.py --input /private/deployment.json --output /private/rendered --candidate /artifacts/candidate.json
python3 /artifacts/operate.py --candidate /artifacts --deployment /private/rendered --project identity-main install
python3 /artifacts/operate.py --candidate /artifacts --deployment /private/rendered --project identity-main verify
python3 /artifacts/operate.py --candidate /artifacts --deployment /private/rendered --project identity-main initialize <tenant-uuid> <login> /private/new-password
python3 /artifacts/operate.py --candidate /artifacts --deployment /private/rendered --project identity-main open
```

输出目录必须不存在；root 渲染为服务 UID/GID 10001:10001，目录0700、文件0600。操作命令由有权读取此目录和使用 Docker 的部署 owner 执行；新口令文件也须归10001且0600。同一输入生成 runtime、maintenance、owner migration 和严格静态 UI JSON。不要手改生成配置或二次 envsubst；Compose 字面量已转义。首次 install 只安装数据库结构与角色授权；不会创建账户或开放入口。

`initialize <tenant> <login> <password-file>` 的 principal 取自该租户唯一 bootstrapAccounts。组件一次性 guard 拒绝重复、并发输家及重启后重做；旧 principal 参数形式拒绝。新 tenant 必须显式交由宿主配置，不提供平台租户 API。维护恢复命令为 `recover <tenant> <principal> <password-file>`，仅更新既有本地密码和 epoch，保持 enabled/member 与管理策略不变。

`verify` 是只读安装核验，检查 schema、instance、目标角色及有效权限、storage identity 和完整 tenant fence；不补建、不修授权、不初始化。`close` 先停网关再排空 Identity。`open` 先核验、再等待 Identity 内部健康检查、最后开放网关。非零退出或中断均不确认成功，先检查实际状态；不自动重发写命令。

网关固定提供 `/api/identity-host/v1/config.json`（canonicalOrigin/oidcEnabled）；UI 缺失或畸形时拒绝启动。唯一动态宿主资源 `/api/identity-host/v1/tenants/{tenant}/context` 读取权威会话，展示与宿主策略一致的管理提示；管理请求仍由组件事务内授权。网关覆盖来源头、保留原 API 路径且关闭代理重试，PG 不向宿主发布端口。日常容器不挂载 owner/maintenance 秘密。

回退只允许已验证、同 schema 和同 instance/storage 配置的候选。切换前 close，在新私有渲染目录绑定候选，verify 后 open；不得回滚数据库撤销状态。未知提交不等于失败回滚。实际切换和故障恢复证据由 #2366 保存。
