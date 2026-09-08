# 本地参考材料

历史材料仅用于需求分析和行为溯源，不作为产品源码提交。全部本地参考排除项放 `.git/info/exclude`，不用 `.gitignore`。

## WinMDM

本机来源：`/Users/shengming/Documents/code/rss/rss-mdm/reference/winmdm20260220-develop`。
Identity 可用本地软链接 `reference/winmdm20260220-develop` 查阅同一快照，不复制整个目录。该链接不入 Git，不是 Git submodule，也不是 Cargo 依赖。

同级布局下，在 Identity 根目录恢复：

```sh
printf '\n/reference/winmdm20260220-develop\n' >> .git/info/exclude
ln -s ../../rss-mdm/reference/winmdm20260220-develop reference/winmdm20260220-develop
/usr/bin/git check-ignore -v reference/winmdm20260220-develop
```

链接已存在时无需重复创建。也可自行恢复原 ZIP 到该路径。MDM 来源说明记录 ZIP SHA-256 为 `bb08749e671080dd96a3d61dd31c662730604cd288303fa67e7917aaf9778e67`；本次没有取得 ZIP 重新验证该摘要，不能当作本次完整性证明。具体已读文件另见证据索引及 SHA-256。

## RSS

历史 tag：`baseline/pre-community-core-20260902`；固定 commit：`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`。
在 RSS checkout 通过系统 Git 读取，例如：

```sh
/usr/bin/git -C /path/to/rss show 5b63e10a1b396b0ff70b7d1e6e55db296cd7a891:crates/identity/src/application/mod.rs
```

RSS 与 WinMDM 内部规则和历史运行配置不成为 Identity 规则。历史源码未在本次运行，缺陷分析不等于生产事故结论。

## 本地 Git 排除

初始化已在父 RSS `.git/info/exclude` 添加 `/rss-identity/`；Identity 自己的 exclude 持有 `/reference/winmdm20260220-develop`、`/worktrees/`、构建产物、IDE 与本地环境文件规则。exclude 不随 Git 分发，新机器需显式配置；任何密钥均不得提交。

上游与行为来源见 [证据索引](../docs/reference/sources.md)。
