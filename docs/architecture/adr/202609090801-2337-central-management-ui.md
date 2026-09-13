# I07：单一日常管理入口与独立 Identity 前端

状态：#2337 已确认实施决定。后端基线 `9e7c645f53ac2171e88738656b85976c1126f873`，前端 rss-web 基线 `dc2863c5ceeedcd364ed6243e2342a63130ccea5`。实际测试、最终 SHA/lock 和双 PR 由交付记录绑定；不代表生产装配验收。

## Owner 与不兼容替换

Identity 持有认证有效性、租户管理权限、PG 和协议 callback；rss-web 的独立 `apps/identity` 持有中央登录、账户、会话和 IdP UI。前端静态产物挂载于 Identity HTTPS origin，旧 `apps/web` 的产品迁移不属于本项；新入口不加载其 bearer 或业务代码。

按维护者确认，以下面原地替换，不保留旧签名、alias、兼容分支或备用日常 CLI：

| 旧入口 | 当前唯一入口 | 验证与退出 |
| --- | --- | --- |
| create_account / change_account 接受密码候选 | session-only create_local_account / 明确账户操作 | 迁移账户矩阵、竞态与结算测试；删除旧签名 |
| Authority 公共 provider CRUD / 任意测试 closure | Federation 管理门面；Authority 包内持久化 | 自助凭据、CAS、前后权限重验；删除公共旁路 |
| identity-admin 日常账户及 IdP 命令 | 管理 HTTP/UI | 完整覆盖 member/admin/emergency、成员/账户/管理权及 IdP；删除命令、依赖与使用说明 |
| callback 错误 JSON / 空 code 兑换 | 同一个 callback 的安全 303 失败跳转 | 绑定、取消、重放与故障；不新增第二 callback |
| session-only HTTP 成功载荷 | session + identity + csrf_token | 严格前端解码与真实 HTTP 测试；不建 profile 认证链 |

`AuthenticationCandidate` 仍服务于密码登录发会话及本地关联再认证；不是日常管理授权。Maintenance initialize/recover 是不同权限与恢复职责，不是旧管理兼容入口。

## 日常账户与 IdP

每次事务内重验 AuthenticatedSession，包括存储 authority、cookie digest、tenant、期限、账户/成员 epoch 与当前管理资格。早期管理员快照检查仅用于拒绝不必要的 KDF/静态配置工作，不授予操作权限。常规账户/IdP 管理的目标和 actor 必须同域；#2427 的两个平台增加操作使用独立受认证入口和窄范围跨域事务，不扩张这些常规 API。

创建角色闭集为 member/administrator/emergency。启用账户、启用成员、授予管理权分别执行。管理员重置仅针对他人，本人改密需当前口令再认证并在提交中重验 session 和凭据代际；秘密替换不自动启用或扩权。最后本地管理员规则保持唯一 core owner。相关成功操作与安全事件同事务，未知结算不冒充成功。

#2427 原地替换 IdP create/update 输入为 settings、只写 client secret、可选 CA；凭据加密存入 PG，配置/凭据/事件同事务。系统域 IdP 由平台角色管理，业务租户只管理本域 IdP。退出 approve_configuration 和静态出站批准；保留纯协议校验、可信 assurance 解释及有界网络工作。测试前后复核权限/版本，审计确认后才返回安全报告；不新增 last-test 表。

## 浏览器边界

唯一 OIDC callback 保持 `/api/v1/oidc/callback`。上游拒绝验证 state MAC、browser、iss、provider/version 和源会话后消费 attempt，绝不发送空 code。失败固定到 `/auth/error?reason=cancelled|failed|unavailable`，不反射 query、不设置/清除中央 session cookie。GET query 必须从访问日志排除；HEAD 不消费。

UI 只允许标签页内五分钟的 challenge/flow 定位信息，完成/失败/过期清除，发送 accept 前先移除可重放暂存。它不是权限；服务器继续验证绑定和单次领取。Cookie 为 host-only/HttpOnly；密码、csrf、上游 token、PKCE verifier 不持久化。刷新集中串行、仅由用户活动触发，写入不自动重放。

## 证明与装配

T1 覆盖纯规则、wire、前端状态和组件；T2 使用真实 PG/Keycloak/Hydra 及测试专用 HTTPS/Axum 宿主消费独立前端构建。联合验收由 rss-web 自行构建、运行并记录两仓 commit/lock 与产物/runner 摘要；后端仅提供测试 fixture，不审查或构建消费者源码。每租户 provider 上限 100，与有界读取一致，创建事务超限返回明确 409，保持会话有效。I08 仍持有生产 listener/config/镜像，T31–T33 和 MDM 接入保持独立。

参考：Axum `axum/src/extract/state.rs` @ `c59208c86fded335cd85e388030ad59347b0e5ae`；Vue Router `packages/router/src/navigationGuards.ts` @ v4.5.0；已有 I03/I04/I05/I06 事务和协议 owner。

#2428 新增 HTTP-only identity-platform CLI，复用同一会话与 API；identity-admin 仍只维护 initialize/recover。旧日常数据库 CLI 没有恢复。平台 UI 的替换协议由 #2368 消费。
