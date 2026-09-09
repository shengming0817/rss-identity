# IdP 配置与联合登录接入

I05 提供配置管理 CLI、Federation Rust 用例和可挂载 Axum Router。生产 listener、UI、反代及 Hydra/MDM 接入仍由后续 owner 提供；不要把本指南当作生产 T3 证明。

## 配置管理

先按[本机维护](local-maintenance.md)显式重建 schema 4、安装并初始化本地管理员。已有本地 CLI 操作保持其功能，内部凭据切换到独立表；不迁移旧开发库。

部署 policy JSON：

```json
{
  "bindings": [{
    "tenant_id": "11111111-1111-4111-8111-111111111111",
    "issuer": "https://keycloak.example.test/realms/company",
    "client_id": "identity",
    "redirect_uri": "https://identity.example.test/api/v1/oidc/callback",
    "secret_ref": "keycloak@1",
    "addresses": ["192.0.2.0/24"]
  }],
  "secret_files": {"keycloak@1":"/private/keycloak-client-secret"},
  "ca_file": "/private/organization-ca.pem"
}
```

上述域名、地址和路径均为示例，必须替换为部署批准的实际值。tenant/issuer/client/callback/secret_ref/address 是部署批准的完整绑定；其它租户、issuer 或 client 不能借用同一个 secret_ref。租户管理员不能通过 IdP settings 重组这些许可。HTTP adapter 固定 HTTPS、TLS 验证、DNS 解析结果地址许可、无重定向、无隐式环境代理、5 秒请求/3 秒连接预算和 1 MiB 响应上限。私有 Keycloak 需显式批准其地址范围及 CA。

管理 policy 不含登录 state key 或回跳注册。list/enable/disable 只需 PG 和管理员认证；create/update 仅检查静态绑定；test 在验证管理员和精确配置后只读取目标 secret 与 CA。其它 IdP 的秘密文件缺失不妨碍管理当前 IdP。

秘密文件必须为当前本机私有普通文件，禁止最终 symlink/FIFO/组与其它用户权限。密钥不得放命令参数、环境变量或日志。已有 `name@version` 绑定不可偷偷换值；secret 轮换创建新 ref 并更新 IdP config_version。HTTP 装配另行注入独立随机 32 字节 StateSigner 密钥和受控回跳集合；state key 轮换取消在途登录，中央会话仍按自身撤销规则处理。

IdP settings JSON：

```json
{
  "issuer":"https://keycloak.example.test/realms/company",
  "client_id":"identity",
  "secret_ref":"keycloak@1",
  "redirect_uri":"https://identity.example.test/api/v1/oidc/callback",
  "scopes":["openid","profile","email"],
  "claims":{"email":"email","groups":"groups"},
  "jit":false
}
```

只支持 confidential client Code + S256；openid 必需，offline_access 禁止。claim mapping 只选直接 claim 名，不执行表达式；subject/issuer/audience/nonce 等验证字段不能映射。groups mapper 由 Keycloak owner 配置；Identity 不把 groups 转为产品角色。

```text
identity-admin PG_CONFIG idp-create POLICY ACTOR ACTOR_PASSWORD_FILE SETTINGS
identity-admin PG_CONFIG idp-list ACTOR ACTOR_PASSWORD_FILE
identity-admin PG_CONFIG idp-update POLICY ACTOR ACTOR_PASSWORD_FILE PROVIDER_UUID EXPECTED_VERSION SETTINGS
identity-admin PG_CONFIG idp-enable ACTOR ACTOR_PASSWORD_FILE PROVIDER_UUID EXPECTED_VERSION
identity-admin PG_CONFIG idp-disable ACTOR ACTOR_PASSWORD_FILE PROVIDER_UUID EXPECTED_VERSION
identity-admin PG_CONFIG idp-test POLICY ACTOR ACTOR_PASSWORD_FILE PROVIDER_UUID
```

创建默认 disabled，输出 provider ID/version；更新与启停要求当前精确 version，冲突后重新读取，不盲重试不确定提交。issuer 不可修改，更换 issuer 新建 provider。连接测试输出 checks、tls_verified、authorization_response_issuer；要求 discovery 声明 RFC 9207 支持。失败用封闭 stage/reason 区分 binding、discovery、JWKS、exchange 及 TLS/网络/上游拒绝，审计包含同样的安全诊断，不返回原始响应。该测试覆盖 discovery/TLS/JWKS 范围，不证明用户登录或 client secret 有效；实际登录用真实 code 兑换证明。

## HTTP 消费

用部署参数构造 `HttpOidc`、`StateSigner` 和 `Federation`，传给 `federated_router(federation, HttpConfig)`。该 router 包含原本地会话路由并使用同一个 Authority。传入真实 ConnectInfo；不信任客户端 forwarded headers。详见 [wire](../architecture/identity-wire-v1.md)。

共享回调必须带 RFC 9207 `iss`，在领取 attempt 和发送 code 前与精确 issuer 比较；不支持该参数的 IdP 不可接入。开始返回 authorization_url；浏览器跳转至该 URL。回调成功 303 到注册 return_target，关联结果附加 `identity_result=linked|already_linked`，不含归属信息；部署回跳不得预占 `identity_result`。中央 session cookie 与原 I04 一致；GET session 可获取 session/CSRF。link 复用当前 cookie+CSRF，本地账户另提交密码；纯联合账户先跳原 IdP 重新认证，再跳目标 IdP。

配置变化、错误浏览器、过期、重放、身份冲突或存储故障均须重新开始，不重试同一个 code。失败不设置或清除 session cookie；所有响应 no-store/no-referrer。生产访问日志必须省略 callback query，UI 的失败页/history 清理由 I07/I08 处理，不记录 code/state。

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
