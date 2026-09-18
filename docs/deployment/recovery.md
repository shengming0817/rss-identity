# 备份、隔离恢复与轮换

部署 owner 决定恢复点及可接受数据损失，独立保管配置、证书、密码和所需钥集合。工具保持实例与 tenant fence，不判断历史快照是否包含最新撤销；未核对完整安全状态前保持关闭。每条命令都传私有部署目录和明确 project，以下以 `op` 表示这个固定前缀。

```sh
op() { python3 hack/operate.py --deployment /private/rendered --project identity-main "$@"; }
op close
op backup /private/backups/cut-001.dump
op check-backup /private/backups/cut-001.dump
op verify
op open
```

backup 在关闭 Identity/网关并只读核验后执行 PG custom dump，使用排他新文件与0600权限；同名 `.dump.json` 记录摘要、schema、instance、storage、source project 和后端版本 backendVersion（实际不可变后端 image ID，sha256:…）。check-backup 和 restore 复用严格的字段/类型校验，要求后端版本、instance、storage、source project 和摘要完整有效且匹配；check-backup 还以固定 PG 的 pg_restore --list 离线核验。失败不会生成成功记录；部分文件需由 owner 核对后另选输出路径。备份和收据共同置于加密私有存储，校验不代替完整恢复演练。

恢复时先再次关闭源 Identity/网关，保留原卷，禁止两份密码权威同时开放。用当前秘密和相同 instance/storage/tenants 生成另一个私有渲染目录，backendSubnet 和 publicGateway 改为不冲突的隔离网段；project 必须不同且不存在容器/卷。

```sh
python3 hack/operate.py --deployment /private/restored --project identity-restored restore /private/backups/cut-001.dump
python3 hack/operate.py --deployment /private/restored --project identity-restored verify
# owner 完成恢复点、撤销、账户/member/provider 状态和秘密核对后，才显式 open。
```

restore 拒绝仍运行的源 Identity/网关，目标 PG 空卷只建立容器所需角色；pg_restore 在单事务恢复后仅运行 `--verify`，不执行 Identity 安装或初始化。失败目标留在隔离状态供检查，不覆盖源卷、不自动擦除失败卷重试。校验后部署 owner 才决定 open，保持源端关闭；actual browser/recovery/capacity T3 归 #2366。

凭据加密钥轮换：关闭源服务，用新私有渲染目录保留所有旧钥并将新钥设为 activeKeyId；运行 `rekey`。owner 一个有界事务遍历全部配置租户，先验证 storage/fence；组件按现有 provider 上限持锁、认证每个密文/AAD 并重写。未知提交不报成功、不重试。随后再生成只含新钥的配置，运行 `verify-keys`，完整解密所有租户后 verify/open。未完成单新钥核验前禁止销毁旧钥；备份保留期内仍需受控保管其解密钥。日常角色无额外授权。

stateKeyFile 更换后重启，旧 OIDC state 拒绝，用户重新开始。上游 client secret 通过 IdP owner 轮换和当前 provider 管理提交，同步核对旧凭据拒绝；不自动重放未知管理提交。数据库密码由 owner 在受控事务修改对应角色，再生成新私有配置并以新连接核验；TLS证书更新同样重新渲染和启动。维护 recover 不自动启用禁用账户或成员，不授予权限。

旧 candidate 字段回执明确拒绝，无兼容读取或转换。新格式不记录前端镜像，前端独立升级不影响已有备份；schema、instance、storage lineage、source project 及 dump 摘要仍严格校验。数据库 dump 格式保持不变。

backendVersion 与 Compose 的 identity image ID 精确相等；镜像的源码 revision 标签仅用于追溯展示，不作为恢复兼容凭据。同源码重建得到不同 image ID 时也须保留备份所属后端镜像，不能凭标签宣称兼容。
