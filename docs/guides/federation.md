# IdP 配置与联合登录接入

I05/I07 提供 Federation 管理用例、管理 HTTP 和单一 callback；中央 UI 位于 rss-web apps/identity。生产 listener/反代由 I08 提供，本指南不构成生产 T3 证明。

## 配置管理

按[本机维护](local-maintenance.md)安装当前 schema 并初始化本地管理员，日常管理使用[管理 HTTP/UI](management.md)。

租户管理员通过 API 创建/更新 IdP 并提交只写 client secret、可选专用 CA。系统域由平台管理员管理；其 JIT 必须关闭，平台用户关联已建立的系统账户。配置、加密凭据及安全事件同事务，读接口不返回秘密、密文或 keyring。

部署不再批准 tenant/issuer/client/secret_ref/address 组合，也不限制 IdP 的 IP/CIDR 范围。HTTP adapter 保持 HTTPS、TLS 验证、协议目的地检查、无重定向、无隐式环境代理、5 秒请求/3 秒连接预算和 1 MiB 响应上限。callback 必须精确等于本部署的 /api/v1/oidc/callback。

凭据由数据库外 keyring 加密持久化，每次配置/凭据更新推进配置和凭据版本、撤销旧流程与相关会话。create/update 必须重新提交完整凭据；系统域与各业务租户不共享凭据。list/disable 不解密目标秘密。密钥和恢复步骤见[平台指南](platform.md)。StateSigner 密钥独立，轮换会终止在途上游登录。

下面是非秘密 settings；create body 为 `{settings, client_secret, ca_pem}`，update 另带 expected_version。client_secret 为只写字段，ca_pem 可为 null。

IdP settings JSON：

```json
{
  "issuer":"https://keycloak.example.test/realms/company",
  "client_id":"identity",
  "redirect_uri":"https://identity.example.test/api/v1/oidc/callback",
  "scopes":["openid","profile","email"],
  "claims":{"email":"email","groups":"groups"},
  "jit":false
}
```

只支持 confidential client Code + S256；openid 必需，offline_access 禁止。claim mapping 只选直接 claim 名，不执行表达式；subject/issuer/audience/nonce 等验证字段不能映射。groups mapper 由 Keycloak owner 配置为 `oidc-group-membership-mapper`、`full.path=true`、`id.token.claim=true`，使用 `/parent/child` 完整路径。Identity 精确保留这些标识，不展开父组或把组转为产品角色。

管理 API 路径与输入见 [wire I07](../architecture/identity-wire-v1.md#日常管理-httpi07)。

创建默认 disabled，输出 provider ID/version；更新与启停要求当前精确 version，冲突后重新读取，不盲重试不确定提交。issuer 不可修改，更换 issuer 新建 provider。连接测试输出 checks、tls_verified、authorization_response_issuer；要求 discovery 声明 RFC 9207 支持。失败用封闭 stage/reason 区分 binding、discovery、JWKS、exchange 及 TLS/网络/上游拒绝，审计包含同样的安全诊断，不返回原始响应。该测试覆盖 discovery/TLS/JWKS 范围，不证明用户登录或 client secret 有效；实际登录用真实 code 兑换证明。

## HTTP 消费

用部署参数构造 `HttpOidc`、`StateSigner` 和 `Federation`（首个参数为经过校验的 `GroupFactsMaxAge`），传给 `federated_router(federation, HttpConfig)`。该 router 包含原本地会话路由并使用同一个 Authority。传入真实 ConnectInfo；不信任客户端 forwarded headers。详见 [wire](../architecture/identity-wire-v1.md)。

共享回调必须带 RFC 9207 `iss`，在领取 attempt 和发送 code 前与精确 issuer 比较；不支持该参数的 IdP 不可接入。开始返回 authorization_url；浏览器跳转至该 URL。回调成功 303 到注册 return_target，关联结果附加 `identity_result=linked|already_linked`，不含归属信息；部署回跳不得预占 `identity_result`。中央 session cookie 与原 I04 一致；GET session 可获取 session/CSRF。link 复用当前 cookie+CSRF，本地账户另提交密码；纯联合账户先跳原 IdP 重新认证，再跳目标 IdP。

配置变化、错误浏览器、过期、重放、身份冲突或存储故障均须重新开始，不重试同一个 code。失败不设置或清除 session cookie；所有响应 no-store/no-referrer。生产访问日志必须省略 callback query，失败固定跳往同源 UI 错误页，history 清理由 I07 UI 处理，不记录 code/state。

## 验证

```sh
cargo test --locked -p rss-identity-core --test federation
cargo test --locked -p rss-identity-oidc --lib --test config
make test-pg
make test-oidc
make test-federated
make -k ci CI_BASE=origin/develop
```

`test-federated` 需要 Docker 与 openssl，自动创建短期测试 CA/Keycloak TLS fixture 与独立 PG，严格核对 canonical 测试集合；所有测试私钥和数据库随 fixture 清理。具体运行结果、镜像 digest、SHA 与 lock 在实现 PR 记录。

部署的 `oidc.group_facts_max_age_seconds` 必填，示例值 300，范围 1–300；不属于 provider 管理 API，也不需要前端配置。只有新的可信上游认证更新快照，普通会话续期不会延长组期限。已有快照不随配置变更重算，立即撤销使用 provider 或会话撤销。具体状态、时间与来源绑定见 [groups wire](../architecture/identity-wire-v1.md#可信组事实2433)。

Keycloak 26.7.3 的 `OIDCAttributeMapperHelper.mapAttributeValue` 在集合为空时不写 claim；因此该 mapper 的零成员登录会得到 `unavailable/claim_missing`，不是 `available` 的空数组。Identity 不推断缺失含义；上游实际发送已签名 `[]` 时才表示已验证空组。
