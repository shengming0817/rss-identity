# PR #1030 修复候选接缝记录

固定 Identity 源码 `89b8769fd489d95faded6e411941d5003215a09e`，Web `4129f60de216c7803d3e6d6e23d30db30cdb6709`；[candidate.json](candidate.json) 摘要 `20ad2786a4894a3c102cb8d70ed431d4ce2f90047f843e0b359392865656e2c4`。本证据提交只修改文档，未改变候选生产代码。

[reference-seams.json](reference-seams.json) 由该候选打包的 `reference_seams.py` 实际生成并在成功返回前校验，25 步全部通过，两个测试 project 的容器、卷和网络清理已核实。包含真实 encrypted provider 的轮换前仅新钥拒绝、rekey、仅新钥核验、重新开放/登录、backup/check-backup、空目标隔离恢复、恢复后新钥核验和登录。没有把原手工清单或 mock 结果替代这些操作。

执行环境：Docker Desktop 29.7.2 Linux daemon；server/operator/gateway 为固定 linux/amd64 候选，PG 为 providers.lock 中的 17.6。runner 在 Linux 容器内以 root 运行，Python 3.11.2、Docker CLI 28.5.2、Compose 2.40.3。私有工作目录使用 Linux Docker named volume 的实际 mountpoint，以保留 UID 10001；macOS bind mount 的 UID 映射不满足维护口令属主检查，未放宽该检查。运行工具镜像由固定 Rust image 与 Docker CLI image `docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d` 组合，仅提供 Python、openssl、Docker 和 Compose，不进入候选。

可再生入口和要求见[候选构建](../../candidate.md)：在隔离 Linux Docker 主机运行 `make test-reference`；验证既有记录使用同一候选的 `reference_seams.py --candidate ... --record ... --verify-record`。本地可再生候选目录为 `rss-external-check/identity-1030-89b8769`，唯一源码和证据均已提交，不依赖该目录保存。

本轮先验证了特殊地址/混合 DNS 拒绝与 TCP 未连接、三个 binary 无网络配置预检、跨进程锁、严格 receipt、原子渲染清理、普通成员 context 负向提示，以及真实 PG/Keycloak T2。最终 `make ci` 结果由 PR #1030 的 fix 交接记录持有。

这些是候选与 operator 的实现接缝证明；独立实际浏览器、生产恢复点、RPO/RTO 和容量验收仍归 #2366。
