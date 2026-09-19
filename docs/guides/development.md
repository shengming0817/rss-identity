# 开发与验证

需要 Rust 1.96.0（rustfmt/clippy）、Python 3.11+、Docker、cargo-deny 0.19.9 和 RSS Git 读取权限。使用系统 `/usr/bin/git`。

```sh
make ci
```

`make ci` 执行 fmt、locked clippy/编译、Rust/Python 测试、固定依赖与 feature 闭包检查、许可证/公告检查及真实 PostgreSQL、OIDC、Keycloak HTTPS + Axum 测试。普通 cargo test 中 ignored 的 provider 用例必须由 runner 实际执行；runner 验证测试名称和全部计数，零测试/部分执行失败。容器是临时 loopback fixture，故障时只输出安全诊断并清理。

PostgreSQL 17.6、Keycloak 26.7.3 的镜像摘要由 [providers.lock.json](../../deployment/providers.lock.json) 固定。没有 Hydra 测试或中央客户端。数据库单元层的竞态测试可访问 crate 私有接口，公开消费者只能使用完整 facade。

固定 Git 消费单独运行：

```sh
make test-consumers IDENTITY_CONSUMER_REVISION=<完整已提交并推送的SHA> IDENTITY_CONSUMER_OUTPUT=/tmp/identity-proof-<唯一编号>
```

每个消费者拥有独立 workspace/Cargo.lock/target，无仓库祖先 Cargo 配置；组件与 RSS 均为固定 Git 来源，不能用路径样例代替此证明。先固定生产提交，再运行消费者，验证前后有效源码与配置必须一致。report 记录生产文件摘要、精确依赖版本/features、Cargo.lock 摘要和实际运行计数，生成文件保留在仓外输出目录；结果记录与持久归档遵循[文档规则](../rules/documentation.md)。可执行消费者源码见 [embedding](embedding.md)。

本仓 worktree 常规检查共用 Identity 主 checkout 的 target；外部消费者使用自己的 target，不能套用该缓存配置。`make dependencies` 对测试 metadata 和实际生产 compiler artifacts 分别检查 RSS features、统一来源、无 patch/跨仓 path。schema 变更通过 `python3 hack/schema_signature.py` 从全新临时 PG 计算签名，不接受现有业务库漂移。

Azure CI 的 job token 只供 fetch，随后移除凭据并离线运行相同门禁。配置文件不等于托管流水线已执行。唯一公告例外 [#2357](https://dev.azure.com/shengming0923/rss/_workitems/edit/2357) 仅为 identity-oidc → openidconnect 4.0.1 → rsa 0.9.10 公钥验证路径，版本或调用路径变化即撤销例外；不用于 RSA 私钥操作。

参考宿主配置见 [deployment/example.json](../../deployment/example.json)。完整 binary/image/UI 装配与操作入口见 [参考部署](../deployment/README.md)。联合 T2 从固定 Web checkout 运行 `IDENTITY_BACKEND_FIXTURE=/absolute/fixed-identity IDENTITY_JOINT_RECORD=/absolute/new-record.json pnpm test:identity:joint`；使用 Vitest/jsdom 的生产 transport，经 TLS 消费真实组件宿主。实际候选浏览器、恢复和容量 T3 属于 #2366；MDM 接入属于 #2437。
