# 固定候选构建

双方使用干净且固定的完整 Git SHA。Web 执行 frozen install、typecheck、lint、format check、tests 和 build；Identity 执行 `make ci`，再由 Web 的 `pnpm test:identity:joint` 消费真实组件宿主。候选只装入 `apps/identity/dist`，不装入 apps/web。

```sh
make candidate CANDIDATE_OUTPUT=/absolute/new-candidate IDENTITY_UI_SOURCE=/absolute/fixed-rss-web IDENTITY_UI_DIST=/absolute/fixed-rss-web/apps/identity/dist
python3 /absolute/new-candidate/operate.py --candidate /absolute/new-candidate candidate
```

构建需要 Python 3.11+、Node、Docker Buildx 和 RSS 固定 Git 源码的读取凭据。`IDENTITY_GIT_AUTH_HEADER_FILE` 是私有 0600 文件，或 CI 提供 `SYSTEM_ACCESSTOKEN`；仅作为 BuildKit secret 传给 fetch，编译离线且没有凭据。禁止把秘密值写到 CLI。Web origin 必须是激活 Azure 仓库。

候选目录包含 `candidate.json`、server/operator/gateway 的 OCI archives、identity-server / identity-admin / identity-migrate 三个 binary、deploy.py、operate.py 与部署材料。candidate.json 绑定双方 SHA、Cargo/pnpm locks、RSS Git revision 与实际生产 features、工具链、schema 9/config 3、迁移、UI、binary、操作工具、部署树和 OCI 摘要。构建会运行 binary `--version`、迁移 `--describe`，并读取非 root 网关内的 UI revision；工具校验归档及其 blob 摘要，不把本地候选宣称为已发布 registry 镜像。

用 `docker load --input /absolute/new-candidate/server.oci.tar` 分别加载三份归档。渲染配置仅引用 candidate.json 中的固定镜像摘要。部署前独立保存 candidate.json 摘要及可信来源；摘要校验不能替代候选来源认证。

构建、网关和清理机制参考本仓 `fa7019922162158704cc47c6ac7ad36a67c8ae5a` 的 hack/release.py、hack/ui.py 和 deployment/Dockerfile，按当前三 binary 与组件边界重建。代理行为核对 [NGINX release-1.30.0 源码](https://github.com/nginx/nginx/blob/release-1.30.0/src/http/modules/ngx_http_proxy_module.c)；未引入其代码。

参考候选接缝使用打包的 `reference_seams.py`（摘要在 candidate.tools 中），在隔离 Linux Docker 主机以 root 部署 owner 执行：

```sh
make test-reference CANDIDATE_OUTPUT=/absolute/candidate REFERENCE_RECORD=/private/reference-seams.json REFERENCE_WORK=/private/new-fixture
python3 /absolute/candidate/reference_seams.py --candidate /absolute/candidate --record /private/reference-seams.json --verify-record
```

需要 Docker Compose v2、Python 3.11+、openssl，使用候选锁定的 Rust image 作为一次性 HTTP fixture。runner 只创建唯一前缀的测试 project，使用 172.29.241.0/24、172.29.242.0/24 和 443 端口；在空闲隔离主机运行。源码、候选、记录与工作目录须可由 Docker 使用相同绝对路径挂载。记录逐步原子保存，绑定候选 JSON 摘要、双方源码 SHA 和 runner 摘要，含真实凭据负向核验、rekey、新钥核验、重新开放、备份与隔离恢复，以及清理失败。成功必须经过记录契约和 subject 校验；旧静态 passed 清单不进入当前验证。保留失败 fixture 秘密的私有工作目录，使用后由 owner 清理；所有测试容器、卷、网络由 runner 清理并核实。该入口证明候选/operator 接缝，实际浏览器、生产恢复目标和容量仍归 #2366。
