# 产品范围

rss-identity 拥有可嵌入的本地认证、租户成员身份、联合 IdP 登录/关联、实例内服务端会话和原子安全事件。core、postgres、oidc、http-axum 为公开能力包；app/identity 是参考宿主，不成为消费方的运行依赖。宿主接入见[嵌入指南](../guides/embedding.md)。

宿主持有管理角色、防锁死、资源授权、配置、实例标识、租户 admission、数据库角色与 fenced PgRuntime；组件强制实例/租户/主体/epoch/会话绑定并在事务内调用宿主策略。组、可选部门树快照和 assurance 仅提供可信认证事实，不生成资源权限。MDM/ZT 持有设备 authority、attestation、posture 和业务授权。

仅支持当前配置、HTTP v1 和全新 schema 安装，无旧配置、旧库升级、旧 API alias、legacy feature 或中央 downstream/client/Hydra 模式。重新部署及真实产品迁移须由其独立任务闭合。

RSS 公共 runtime、事务消息及必要基础库使用同一 Git URL/完整 SHA，独立 Cargo.lock 与实际 feature 闭包。禁止消费方跨仓 path、源码副本、浮动 branch/tag 或 Git/registry 双来源。固定 Git checkout 内的包间 path 属于同一源码闭包。源码消费不等于 registry 发布。

宿主注入既有连接池，业务变更与 Outbox 使用同一 PG 事务。组件不重建、替换或关闭宿主池；各 schema owner 导出 migration，宿主决定顺序、角色与 tenant fence。OIDC 配置可选，不引入统一 provider 总线。

不建设通用 IAM、OAuth 授权服务器、API proxy、中央 ABAC 或设备 authority。账号密码签发的实例内 Bearer 呈现已由 #2795 接纳，复用现有会话 owner；API Key 与程序化来源准入归消费产品。新增 SAML/LDAP/SCIM、机器身份平台、自助注册、passkey 按独立需求接纳。参考宿主持有部署运维；MDM 和 Web 持有各自的产品接入。工作项记录具体交付及验证结果。

Identity 拥有账户、会话和联合身份事件到 Audit 的解释、脱敏与 Outbox 投影。Audit 公共包从 rss-audit 独立固定 Git revision 消费；其 RSS 基础库与 Identity 统一来源和 revision。宿主显式启用同库 worker，持有独立角色及生命周期。


登录资料由 Identity 持有：固定常用资料、批准根内的有界动态 JSON、本地资料管理及每账户／来源的最新登录观察。
current 只读取会话绑定的观察；latest 是单独授权的最近观察展示。资料不是认证或授权事实，MDM 拥有业务字段定义、可见性与资源授权。
平台接缝仅接收宿主安装的 verifier，经一次性挑战和同事务资格复核签发既有 Cookie 会话；设备、平台密码学与绑定 authority 属于 MDM。
不提供通用 IdP、平台 Bearer 签发或硬件密钥自动 MFA。身份签发时间与真实认证时间分别持有。
