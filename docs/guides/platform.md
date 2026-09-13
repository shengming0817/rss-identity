# 平台开通与命令行

当前入口由 #2427/#2428 持有，采用 schema v8。系统域由部署显式指定；`identity-admin initialize` 只创建系统域和首位本地平台管理员。业务租户通过受认证平台 API 开通。已有 schema 不自动升级或清理。

平台角色可以开通租户，也可以给已有租户新增本地管理员并设置其口令，因此具备接管租户身份管理的能力。新增操作不会覆盖既有账户、口令、成员或管理员资格。平台无单独禁用/解禁、改旧密码或仿冒会话 API；新增账户后续由租户正常管理 API 管理。MDM 的资源授权仍由 MDM 决定。

## 准备

CLI 配置为非秘密 JSON，所有路径使用绝对路径：

```json
{
  "format_version": 1,
  "origin": "https://identity.example.test",
  "system_domain_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "session_dir": "/private/identity/cli-session",
  "ca_file": "/private/identity/public-ca.pem",
  "request_seconds": 30
}
```

配置及 CA 文件须由当前用户或 root 持有，group/other 不可写；内容不要求保密。使用系统信任根时 `ca_file` 为 null。CLI 只访问此 HTTPS origin，禁止重定向和隐式环境代理。`session_dir` 的父目录须已存在；CLI 创建当前用户的 0700 会话目录，文件为 0600。口令从当前用户拥有的 0600 普通文件读取，拒绝 symlink/FIFO，不把秘密值传入 argv 或环境变量。

```sh
identity-platform --config /private/identity/platform.json login --login platform --password-file /private/identity/platform-password
identity-platform --config /private/identity/platform.json login --sso --provider a1111111-1111-4111-8111-111111111111
```

SSO 使用系统域独立 IdP，先通过系统域本地账户的正常关联 API 建立关联；JIT、邮箱和 claims 不授予平台角色。浏览器认证后，只给本机临时 loopback 返回一分钟的单次 PKCE 登录码，CLI 经 HTTPS 兑换中央会话。登录总等待五分钟，可按 Ctrl-C 取消。重复 login 先明确撤销当前保存的会话。

## 开通与增加管理员

执行前保存 operation、tenant、principal UUID；命令超时后仍用原 operation 查询，不重新生成定位信息。口令文件自行准备，例中只有文件路径。

```sh
identity-platform --config /private/identity/platform.json tenant create --tenant 11111111-1111-4111-8111-111111111111 --name Tenant-A --principal 11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa --login admin --password-file /private/identity/tenant-admin-password --operation 11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb
identity-platform --config /private/identity/platform.json tenant admin add --tenant 11111111-1111-4111-8111-111111111111 --principal 11111111-cccc-4ccc-8ccc-cccccccccccc --login second-admin --password-file /private/identity/second-admin-password --operation 11111111-dddd-4ddd-8ddd-dddddddddddd
identity-platform --config /private/identity/platform.json tenant list --limit 50
identity-platform --config /private/identity/platform.json operation status --operation 11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb
identity-platform --config /private/identity/platform.json logout
```

201/退出码 0 表示开通提交且租户可立即使用本地登录；202/退出码 3 表示提交已确认，运行绑定待激活，使用 operation status 查询。租户不需预先写入配置或重启。重复 operation、principal 或登录名返回冲突，不能覆盖原有管理权。

CLI 闲置十五分钟、绝对四小时；用户命令串行刷新并原子保存新凭据，绝对期限不延长。会话文件不能复制到另一个 origin/system domain。刷新响应丢失或保存失败必须重新登录；随后业务写入不会发出。退出未知时保存 logout_pending，禁止继续业务操作，重新 logout 会先在线核实。

| 退出码 | 含义 |
| --- | --- |
| 0 / 3 | 确认成功 / 已提交待激活 |
| 2 | 输入、配置或私有文件错误 |
| 10 / 11 | 需要重新认证或权限不足 / 已知拒绝或冲突 |
| 12 | 服务不可用且本次业务操作未完成 |
| 20 | 写入结果未知，或回执暂未观察到；使用原 operation 核实 |
| 21 / 22 | 退出未确认 / 会话文件被另一个命令占用 |

断网、超时、未知服务响应不自动重放写入。查不到回执不能证明服务器原事务已经结束或未提交。跨租户增加管理员的审计与账户、凭据和成员在同一个 PG 事务中；只有确认提交才返回结果。

## 密钥与恢复

部署使用外部 storage target/lineage 和统一 generation；恢复前由部署 owner 更新外部身份并同步数据库执行代际，不能从恢复后的数据库读取 epoch 反填期望值。当前只支持 deployment-wide 恢复，不提供 tenant generation override。

IdP 凭据加密 keyring 位于数据库外，每把密钥是私有文件中的 64 位十六进制。先部署包含新 active key 与旧解密钥的配置并重启，再在独立 owner 任务中反复运行 `identity-migrate --rekey --config /run/config/migration.json`，直至 `rewritten=0`。每次最多重写 100 个凭据，同一事务结算；结果未知时重新核验/执行，已使用 active key 的行不会再次改写。只有确认当前数据全部可解密且无旧钥引用后才能退出旧钥；备份仍需保留其切点对应的钥。启动会逐条验证密文认证；旧钥缺失、同名密钥材料错误或密文损坏使启动核验或解密失败，不静默接受损坏数据。

`make test-platform` 验证真实 CLI、HTTPS、后端及 PG；`make test-pg` 包含平台角色、事务和 CLI SSO 码接缝。完整生产双租户 SSO 验收由 #2342 持有，此指南不代表 T3 已通过。
