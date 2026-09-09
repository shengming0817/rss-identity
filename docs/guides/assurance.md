# MFA assurance 与显式 step-up

Identity 验证并传递可信认证事实；管理员权限与 MDM 动作授权继续由既有 owner 判定，本功能不增加管理门禁。

## 部署批准

新配置中每个 OIDC provider 显式填写 `keycloak_totp: false|true`。只有确认锁定 Keycloak 使用 `deployment/keycloak-totp.json` 的 password + TOTP / ACR 2 profile 才设为 true。部署渲染器给新 realm 安装该 flow；已有 realm 由 Keycloak 管理员核验配置、用户 OTP 注册及当前 client，重复 import 不修复漂移。配置不创建默认用户或 OTP seed。

## HTTP

`POST /api/v1/tenants/{tenant}/oidc/{provider}/step-up`

body 与正常联合登录相同：`{"client_id":"identity-ui","return_target":"resume"}`。两个值必须来自当前服务的允许回跳表。请求必须携带当前 `__Host-identity-session` cookie、同源 Origin、`X-Identity-Request: 1`、当前会话的 `X-CSRF-Token`。无会话、错误租户、未批准 profile 或无效回跳均拒绝。

返回 `{"authorization_url":"..."}` 后由浏览器跳转 Keycloak。服务端持有 state/nonce/PKCE，浏览器不得改写认证要求、构造认证事实或自行兑换 code。成功通过唯一 `/api/v1/oidc/callback` 设置轮换后的 cookie，再返回已有回跳目标；没有新的兼容 callback 或成功查询参数。失败沿用安全错误页，不重试 code 或未知结果。

仅支持同一主体已存在的 provider 关联。未关联的本地账户须先完成既有显式关联流程；step-up 不按邮箱绑定、不创建账户。刷新中的同一 session 按当前 cookie 重验；退出、禁用、provider 变化和跨主体切换不能被回调覆盖。

## 消费事实

`/internal/v1/identity/validate` 与 `VerifiedIdentity` 继续使用 `auth_time/amr/acr`：

- `acr=mfa`：批准 profile 的已验证认证；`auth_time` 来自上游真实认证时间。
- `acr=unspecified`：没有足够 MFA 证据；不表示认证失败。
- `amr`：实际可验证的已知方法；Keycloak 未提供时为空。不能用数组非空或本地口令恢复推断 MFA。

普通联合登录若未提供认证时间，低强度结果沿用中央会话建立时间；只有 MFA 或显式重新认证必须具有上游时间。会话续期不刷新认证时间。产品按动作判断允许强度和新鲜度，仍必须逐请求在线验证；旧 grant 不会自动升级为新 session 的 MFA。

首版交付后端 API/T2 和本指南，中央前端按钮与展示由 rss-web [#2368](https://dev.azure.com/shengming0923/rss/_workitems/edit/2368) 持有。

验证：`make test-federated` 包含真实 password/TOTP、浏览器降级和换用户拒绝；`make test-downstream` 检查实际 Hydra ID Token 及在线 client 的强度/认证时间；`make test-pg` 覆盖配置/撤销竞态、事件和未知提交。
