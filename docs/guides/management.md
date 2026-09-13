# 中央登录与日常管理

前端源码属于 rss-web 的独立 `apps/identity`；Identity 提供 `federated_router`、`management_router` 和 `downstream_router`。前两者使用同一个 Federation/Authority，三个 Router 合并挂载于唯一 HTTPS origin，传入真实 ConnectInfo。生产 listener、TLS、provider 注入与静态资源装配由 #2338 实施。

入口为 `/tenants/{tenant UUID}/login`；Hydra 的 login/consent 页面分别注册 `/login`、`/consent`。Federation 的静态 targets 必须注册 `("identity-ui","resume") -> https://IDENTITY_ORIGIN/auth/resume`。IdP 唯一 callback 是 `https://IDENTITY_ORIGIN/api/v1/oidc/callback`。不提供任意 return URL 或跨源凭据/CORS 回退。

管理员在账户页面创建普通/管理员/应急本地账户，分别管理账户启用、成员资格和管理员资格，或协助重置他人口令。本人改密必须输入当前口令。密码操作只替换口令并推进认证 epoch；不会恢复其它状态。最后本地管理员不能被移除。所有写入都可能使目标旧会话失效，本人安全变更后须重新登录。

IdP API 接受自助配置、只写 client secret 和可选 CA；后端加密保存，网页 #2368 按新协议消费。每租户最多 100 个 provider，创建事务原子检查，超限返回 409 `provider_limit_reached`。新 provider 默认停用，更新和启停消费当前版本。冲突先重新读取再编辑；未知写入不能重复提交。连接测试报告仅证明 discovery/TLS/JWKS 与 RFC 9207，不能冒充实际用户登录或 secret 有效性。

`identity-admin` 仅保留独立维护身份的 initialize/recover。日常服务不可读取维护凭据；不可通过维护恢复自动启用账户或成员。

## 验证

后端：`make test-pg`、`make test-federated`、`make test-downstream`，收尾 `make ci`。前端按 rss-web 的 pnpm 检查和 `test:e2e:identity` 验证。

联合 T2 由消费者 rss-web 持有，在已提交的 rss-web checkout 安装 frozen lock 后运行：

```sh
IDENTITY_BACKEND_FIXTURE=/absolute/identity-checkout \
IDENTITY_JOINT_RECORD=/tmp/identity-joint.json \
pnpm test:identity:joint
```

rss-web 自行构建实际 UI、选择同一源码内的 runner，记录两仓 commit/lock、UI 产物及 runner 摘要；后端仅提供 `make test-ui` 测试 fixture，不获取或构建消费者源码。fixture 创建临时 PG、测试 TLS gateway、in-process Router 与固定 Keycloak，使用真实 OIDC adapter。浏览器验证账户与 IdP 管理、平台开通、租户隔离以及 [当前会话认证事实和 step-up](assurance.md#浏览器当前会话投影2368)。该证明不是生产 binary/image/config T3。

连接测试从剩余总预算中保留四分之一（最多一秒）用于权限/版本重检和审计结算，上游超时也须确认失败事件提交后才返回诊断；存储结算不确定仍返回不可用，不假定审计成功。重复本地登录名返回明确冲突，管理员会话不因此退出。

平台角色只在专用系统域生效。系统域账户使用 member 账户形态，再通过平台 role API 显式授撤平台资格，不复用租户 administrator 标志。租户开通/增加管理员见[平台指南](platform.md)。

联合入口通过受控进程组处理 SIGINT/SIGTERM；`make test-ui` 使用 ExitStack 删除自己的容器及匿名卷，
并核实具名资源已经消失。`IDENTITY_UI_FIXTURE_RECORD` 是可选的测试协议输出，容器创建前记录定位，
终止后原子写结果、浏览器失败分类与 cleanup。创建或清理未知不冒称成功；固定消费者入口会将
恢复目标并入最终记录。SIGKILL 不能承诺执行 finally，缺少 fixture 终态时必须保留恢复目录。
