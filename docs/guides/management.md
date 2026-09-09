# 中央登录与日常管理

前端源码属于 rss-web 的独立 `apps/identity`；Identity 提供 `federated_router`、`management_router` 和 `downstream_router`。前两者使用同一个 Federation/Authority，三个 Router 合并挂载于唯一 HTTPS origin，传入真实 ConnectInfo。生产 listener、TLS、provider 注入与静态资源装配由 #2338 实施。

入口为 `/tenants/{tenant UUID}/login`；Hydra 的 login/consent 页面分别注册 `/login`、`/consent`。Federation 的静态 targets 必须注册 `("identity-ui","resume") -> https://IDENTITY_ORIGIN/auth/resume`。IdP 唯一 callback 是 `https://IDENTITY_ORIGIN/api/v1/oidc/callback`。不提供任意 return URL 或跨源凭据/CORS 回退。

管理员在账户页面创建普通/管理员/应急本地账户，分别管理账户启用、成员资格和管理员资格，或协助重置他人口令。本人改密必须输入当前口令。密码操作只替换口令并推进认证 epoch；不会恢复其它状态。最后本地管理员不能被移除。所有写入都可能使目标旧会话失效，本人安全变更后须重新登录。

IdP 页面只配置部署已批准的绑定与不可变 secret_ref；不上传原始秘密、CA 或出站许可。新 provider 默认停用，更新和启停消费当前版本。冲突先重新读取再编辑；未知写入不能重复提交。连接测试报告仅证明 discovery/TLS/JWKS 与 RFC 9207，不能冒充实际用户登录或 secret 有效性。

`identity-admin` 仅保留独立维护身份的 initialize/recover。日常服务不可读取维护凭据；不可通过维护恢复自动启用账户或成员。

## 验证

后端：`make test-pg`、`make test-federated`、`make test-downstream`，收尾 `make ci`。前端按 rss-web 的 pnpm 检查和 `test:e2e:identity` 验证。

联合 T2 在 Identity checkout 运行：

```sh
IDENTITY_UI_DIST=/absolute/fixed-web-source/apps/identity/dist \
IDENTITY_UI_RUNNER=/absolute/fixed-web-source/e2e/identity/real.mjs \
make test-ui
```

前端目录由固定 revision 归档并安装 frozen lock 后构建，`RSS_IDENTITY_WEB_REVISION` 与归档 SHA 相同。runner 使用该归档的 Playwright 依赖。该命令创建临时 PG、测试 TLS gateway 与 in-process Router，实际浏览器运行登录、账户写入、退出和普通成员拒绝。它不是生产 binary/image/config T3；不存在生产数据库或上游产品写入。
