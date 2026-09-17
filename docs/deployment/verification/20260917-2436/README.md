# #2436 / #2368 固定候选记录

这是实现级候选与接缝验证，未标记 #2366 独立产品 T3 完成。证据提交只增加本文和 JSON，不改变候选生产树。

- Identity 固定源码：`b8b175fb86a9a45469c48934567d243e3373b869`。
- Web 固定源码：`4129f60de216c7803d3e6d6e23d30db30cdb6709`。
- schema 9 / config 3，RSS revision、locks、生产 features、三 binary 和三镜像摘要见 [candidate.json](candidate.json)。
- candidate.json SHA256：`a59a479230e4b0d7eb05f71a6fe3e47135234d13b23bf80498f346fac28a64d1`。
- 本地可再生候选目录：`rss-external-check/identity-2436-b8b175f`；重新构建用候选源码 SHA 的 `make candidate` 和固定 Web build，命令见 [构建指南](../../candidate.md)。JSON 已进入源码证据，不依赖本地目录保留。

[joint.json](joint.json) 记录干净双方 SHA、locks、产物/runner 摘要、真实 TLS 组件宿主 + Vitest/jsdom 生产 transport 的成功和清理结果。运行命令：

```sh
IDENTITY_BACKEND_FIXTURE=/absolute/fixed-identity IDENTITY_JOINT_RECORD=/absolute/joint.json pnpm test:identity:joint
```

[reference-seams.json](reference-seams.json) 是旧候选的手工历史清单，缺少仓内 runner 生成链，不作为当前修复的 passed 证明。新候选通过打包 `reference_seams.py` 与 `make test-reference` 生成并校验机器记录，见[候选构建](../../candidate.md)。旧清单记录固定候选上的 Compose 解析、TLS/来源头覆盖/API路径、严格静态JSON、旧入口拒绝、三个 binary `--version`，以及打包工具的 install/verify/open/close/backup/check-backup/restore/再次核验和开放。源端关闭后才恢复到新project/空卷，恢复中未运行Identity安装或初始化；恢复后的账户登录成功。全部专属容器、卷和网络已移除。参考目标是 Linux Docker；本次在 Docker Desktop 的 root Linux container 渲染，初始化通过同一 maintenance Compose入口验证（宿主文件 UID 映射与原生 Linux 不同）。命令接口和步骤见 [操作](../../operations.md)、[恢复](../../recovery.md)。

原生 dump/restore 回归曾因两条复合 CHECK 的 BETWEEN 重解析改变结构摘要而失败；等价展平比较后通过，未削弱 schema attestation。宿主双租户轮换验证后一租户失败会回滚前一租户更新，再验证仅新钥可完整解密。测试入口 `make test-assembly`；完整工程门为 `make ci`，最终门禁结果和六维审查处置保存在 PR #1030 / #1031 的 pm:ship 交接。

Web 已执行全仓 typecheck/lint/format check、124 文件 1156 测试与build，Identity UI 46 个组件/会话用例包含本地零OIDC、旧DTO拒绝、提示绑定、排队重新认证取消和纯SSO关联入口。生产transport联合用例单独执行。此记录不提供真实浏览器、RPO/RTO或容量指标；它们仍由 #2366 在实际目标环境独立验收。
