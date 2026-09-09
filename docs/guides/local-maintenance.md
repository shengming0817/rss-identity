# 本机维护：开发库安装与不确定结果核实

适用 #2358/#2334/#2335 的可丢弃专属开发库（当前初始安装为 schema version 5）；不用于已有生产数据升级。本工具不自动执行下列管理 SQL。维护密码恢复始终通过 `identity-admin recover`，下列账户/事件查询只有只读用途。

## 连接与凭据前置条件

准备已配置 VerifyFull TLS 的 PostgreSQL、CA 和 `psql`。在私有 `~/.pg_service.conf` 定义 `identity_owner_cluster`（连 postgres）与 `identity_owner_dev`（连 rss_identity_dev）的 owner 服务，密码由私有 `.pgpass` 或交互提示提供，勿写到 DSN 参数、环境或历史记录。两个服务须指向同一已核实实例；owner 须具备创建数据库/角色及迁移中转移函数所有权所需权限。下文名称固定为专属开发示例，实际采用其它名称时整套替换。

先只读核实目标，停止其旧工具/服务；确认该库数据可丢弃且这些 Identity 角色不属于其它部署：

```sh
psql 'service=identity_owner_cluster' -X -v ON_ERROR_STOP=1 -c 'SELECT current_database(), inet_server_addr(), inet_server_port();'
psql 'service=identity_owner_dev' -X -v ON_ERROR_STOP=1 -c 'SELECT version FROM identity_authority.schema_version;'
```

## 重建与安装

仅在上述归属与丢弃条件成立时执行。DROP DATABASE 不在事务内；角色仍被其它数据库依赖时会失败，应核实归属，不添加 CASCADE、DROP OWNED 或强制断开连接。

```sh
psql 'service=identity_owner_cluster' -X -v ON_ERROR_STOP=1 <<'SQL'
DROP DATABASE rss_identity_dev;
DROP ROLE IF EXISTS identity_maintenance;
DROP ROLE IF EXISTS identity_account_maintenance;
DROP ROLE IF EXISTS identity_runtime;
DROP ROLE IF EXISTS identity_account_runtime;
CREATE DATABASE rss_identity_dev;
SQL
```

全新环境没有旧数据库时，从 `CREATE DATABASE rss_identity_dev` 开始。`rss_tmsg_relay` 是 RSS 必要 NOLOGIN 角色，不能随意删除；下列安装在缺少时创建，存在时拒绝不安全属性和任何父角色成员关系（不依赖 ADMIN/SET/INHERIT 选项）。Identity 两个组角色必须由新的初始安装 SQL 创建，碰到同名角色即失败。

在 Identity checkout 根目录执行，`RSS_CHECKOUT` 指向可读取固定 Git revision 的 RSS checkout；不要求该 checkout 的当前分支与固定 revision 相同。固定源码、八个有序迁移及 Identity 安装 SQL 合成一个非秘密临时文件后，在同一事务执行；任何失败中止整批安装。

```sh
set -e
RSS_CHECKOUT=/absolute/path/to/rss
RSS_REV=bf5dd1350997d01aa834094a3347fce30247814e
IDENTITY_INSTALL=$(mktemp)
trap 'rm -f "$IDENTITY_INSTALL"' EXIT
cat > "$IDENTITY_INSTALL" <<'SQL'
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='rss_tmsg_relay') THEN
  CREATE ROLE rss_tmsg_relay NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
 ELSIF EXISTS (SELECT FROM pg_roles WHERE rolname='rss_tmsg_relay' AND
   (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication))
 OR EXISTS (SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
   WHERE r.rolname='rss_tmsg_relay') THEN
  RAISE EXCEPTION 'unsafe existing RSS relay role';
 END IF;
END $$;
SQL
for migration in \
  0001_create_transactional_messaging.sql \
  0002_add_message_recovery.sql \
  0003_enforce_replay_identity.sql \
  0004_add_consumer_archive.sql \
  0005_enforce_archive_settlement.sql \
  0006_secure_archive_search_path.sql \
  0007_add_message_dr.sql \
  0008_apply_message_dr.sql
do
  /usr/bin/git -C "$RSS_CHECKOUT" show "$RSS_REV:crates/transactional-messaging-postgres/migrations/$migration" >> "$IDENTITY_INSTALL"
  printf '\n' >> "$IDENTITY_INSTALL"
done
cat crates/identity-postgres/migrations/0001_authority.sql >> "$IDENTITY_INSTALL"
psql 'service=identity_owner_dev' -X -v ON_ERROR_STOP=1 --single-transaction -f "$IDENTITY_INSTALL"
```

配置两个独立登录身份及固定 RSS PgRuntime 要求的事务权限。不给登录身份继承 `rss_tmsg_relay`，不授予 Identity owner 或表外额外权限。以下身份值只用于这个隔离开发库：target 为 16 个字节 1，lineage 为 16 个字节 2，tenant epoch 为 1；它们不是生产身份默认值。

```sh
psql 'service=identity_owner_dev' -X -v ON_ERROR_STOP=1 --single-transaction <<'SQL'
CREATE ROLE identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
CREATE ROLE identity_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
GRANT identity_account_runtime TO identity_runtime;
GRANT identity_account_maintenance TO identity_maintenance;
GRANT USAGE ON SCHEMA rss_transactional_messaging TO identity_runtime,identity_maintenance;
GRANT SELECT ON rss_transactional_messaging.policy TO identity_runtime,identity_maintenance;
GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO identity_runtime,identity_maintenance;
GRANT SELECT,INSERT ON rss_transactional_messaging.outbox TO identity_runtime,identity_maintenance;
GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO identity_runtime,identity_maintenance;
GRANT EXECUTE ON FUNCTION
 rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),
 rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),
 rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid),
 rss_transactional_messaging.check_execution()
 TO identity_runtime,identity_maintenance;
INSERT INTO rss_transactional_messaging.storage_lineage VALUES
 (true,decode(repeat('01',16),'hex'),decode(repeat('02',16),'hex'));
INSERT INTO rss_transactional_messaging.tenant_epoch VALUES
 ('11111111-1111-4111-8111-111111111111',1);
SQL
```

在交互 `psql 'service=identity_owner_dev' -X` 中分别执行 `\password identity_runtime` 和 `\password identity_maintenance`，交互设置数据库口令；由受控 secret 工具将相应口令注入各自普通 `0600` 文件，不把口令写进上述脚本。维护密码文件不得由日常服务读取。

Owner 只读核实非秘密安装身份：

```sql
SELECT version FROM identity_authority.schema_version; -- 恰好一行，5
SELECT authority_id,bootstrap_tenant FROM identity_authority.deployment; -- 恰好一行，记录 authority_id；tenant 为 NULL
SELECT encode(target,'hex'),encode(lineage,'hex') FROM rss_transactional_messaging.storage_lineage;
SELECT tenant_id,epoch FROM rss_transactional_messaging.tenant_epoch;
SELECT rolname,rolcanlogin,rolsuper,rolbypassrls FROM pg_roles
WHERE rolname IN ('identity_runtime','identity_maintenance','identity_account_runtime','identity_account_maintenance');
SELECT NOT EXISTS(SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
 WHERE r.rolname='rss_tmsg_relay') AS relay_has_no_parent_roles; -- 必须为 true
```

维护 CLI 配置使用独立 identity_maintenance 用户；runtime 凭据由服务装配持有。配置示例（替换主机、端口和文件路径；省略号不能放入实际 JSON）：

```json
{
  "host": "pg.dev.example.test", "port": 5432, "database": "rss_identity_dev",
  "user": "identity_maintenance", "password_file": "/private/identity/maintenance-db-password",
  "ca_file": "/private/identity/ca.pem",
  "tenant_id": "11111111-1111-4111-8111-111111111111",
  "storage_target": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
  "storage_lineage": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
  "storage_tenant_epoch": 1
}
```

准备符合密码规则的私有新密码文件后，在 Identity checkout 中初始化维护账户。这里只说明操作，不将文档或低层测试冒充 T3 运行证明：

```sh
cargo build --locked -p rss-identity-admin
PRINCIPAL_UUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
./target/debug/identity-admin /private/identity/maintenance.json initialize "$PRINCIPAL_UUID" admin /private/identity/admin-password
```

每个命令连接时都会执行 RSS 与 Identity 权限/存储探测。错误分类分别指示 schema 版本、角色不匹配、权限漂移或 schema/RLS 契约漂移；provider 失败仍保留其 settlement 分类，不回显连接值。

## 不确定提交：只读核实

CommitUnknown/RollbackFailed 表示结果未知，退出码不能证明未提交。先等待原命令退出并停止同目标的其它维护/管理写入；核实连接到原始数据库和 lineage，不能在落后的副本或恢复点上据缺失记录判未提交。使用 owner 的只读事务；不把 owner 凭据注入日常服务，也不通过 UPDATE 密码恢复。

使用执行前记录的 authority_id、配置中的 storage target/lineage 和已知 tenant/principal（初始化前生成的 UUID，不依赖成功 stdout）查询。缺少数据库身份基线时停止，不用查询当前值反填为“预期值”。`operation` 只能为 initialize 或 recover。事件过滤只解码账户安全事件，并只输出 action、tenant、principal、epoch、时间和事件 ID，不展示密码哈希、完整 envelope 或其它业务 payload：

```sh
psql 'service=identity_owner_dev' -X -v ON_ERROR_STOP=1 \
  -v tenant='11111111-1111-4111-8111-111111111111' \
  -v principal='REPLACE_WITH_ORIGINAL_PRINCIPAL_UUID' \
  -v authority='REPLACE_WITH_RECORDED_AUTHORITY_UUID' \
  -v target_hex='01010101010101010101010101010101' \
  -v lineage_hex='02020202020202020202020202020202' \
  -v operation='recover' <<'SQL'
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT set_config('rss.tenant_id', (:'tenant'::uuid)::text, true),
       set_config('identity.verify_principal', (:'principal'::uuid)::text, true),
       set_config('identity.verify_authority', (:'authority'::uuid)::text, true),
       set_config('identity.verify_target', :'target_hex', true),
       set_config('identity.verify_lineage', :'lineage_hex', true),
       set_config('identity.verify_operation', :'operation', true);
DO $$
DECLARE
 t uuid := current_setting('rss.tenant_id')::uuid;
 p uuid := current_setting('identity.verify_principal')::uuid;
 operation text := current_setting('identity.verify_operation');
 bootstrap uuid; accounts_count bigint; members_count bigint;
 account record; evidence record; event_epoch bigint; evidence_count integer := 0;
 initialized_evidence boolean := false;
BEGIN
 IF operation NOT IN ('initialize','recover') THEN
  RAISE EXCEPTION 'unknown maintenance verification operation';
 END IF;
 IF (SELECT count(*) FROM identity_authority.deployment)<>1
 OR NOT EXISTS(SELECT FROM identity_authority.deployment
   WHERE authority_id=current_setting('identity.verify_authority')::uuid)
 OR (SELECT count(*) FROM rss_transactional_messaging.storage_lineage)<>1
 OR NOT EXISTS(SELECT FROM rss_transactional_messaging.storage_lineage
   WHERE target=decode(current_setting('identity.verify_target'),'hex')
     AND lineage=decode(current_setting('identity.verify_lineage'),'hex')) THEN
  RAISE EXCEPTION 'database identity mismatch; stop maintenance';
 END IF;
 SELECT bootstrap_tenant INTO bootstrap FROM identity_authority.deployment;
 SELECT count(*) INTO accounts_count FROM identity_authority.accounts WHERE tenant_id=t AND principal_id=p;
 SELECT count(*) INTO members_count FROM identity_authority.memberships WHERE tenant_id=t AND principal_id=p;
 IF accounts_count>1 OR members_count<>accounts_count
 OR (operation='recover' AND (bootstrap IS NULL OR accounts_count<>1))
 OR (operation='initialize' AND
   ((bootstrap IS NULL AND accounts_count<>0) OR
    (bootstrap IS NOT NULL AND (bootstrap<>t OR accounts_count<>1)))) THEN
  RAISE EXCEPTION 'inconsistent deployment/account/membership evidence; stop maintenance';
 END IF;
 SELECT a.enabled,a.administrator,a.emergency,a.auth_epoch,
        m.active,m.epoch AS membership_epoch INTO account
 FROM identity_authority.accounts a JOIN identity_authority.memberships m USING(tenant_id,principal_id)
 WHERE a.tenant_id=t AND a.principal_id=p;
 FOR evidence IN
  WITH relevant AS MATERIALIZED (
   SELECT seq,envelope FROM rss_transactional_messaging.outbox
   WHERE tenant_id=t AND domain='identity.security'
   AND envelope->>'contract'='identity.account.security'
  ), decoded AS (
   SELECT seq,envelope,convert_from(decode((
    SELECT string_agg(lpad(to_hex(value::int),2,'0'),'' ORDER BY ord)
    FROM jsonb_array_elements_text(envelope->'payload') WITH ORDINALITY AS b(value,ord)
   ),'hex'),'UTF8')::jsonb AS payload FROM relevant
  )
  SELECT * FROM decoded WHERE payload->>'principal'=p::text AND payload->>'tenant'=t::text
  AND payload->>'action' IN ('initialized','administrator_recovered') ORDER BY seq DESC LIMIT 20
 LOOP
  event_epoch := (evidence.payload->>'epoch')::bigint;
  IF accounts_count=0 OR event_epoch IS NULL OR event_epoch<1 OR event_epoch>account.auth_epoch
  OR (event_epoch=account.auth_epoch AND evidence.payload->'state' IS DISTINCT FROM
   jsonb_build_object('enabled',account.enabled,'administrator',account.administrator,
    'emergency',account.emergency,'member_active',account.active,
    'membership_epoch',account.membership_epoch)) THEN
   RAISE EXCEPTION 'account and event evidence disagree; stop maintenance';
  END IF;
  evidence_count := evidence_count+1;
  initialized_evidence := initialized_evidence OR evidence.payload->>'action'='initialized';
  RAISE NOTICE 'event id=% action=% tenant=% principal=% epoch=% time=%',
    evidence.envelope->>'id',evidence.payload->>'action',t,p,event_epoch,evidence.envelope->>'occurred_at';
 END LOOP;
 IF operation='initialize' AND bootstrap IS NOT NULL AND NOT initialized_evidence THEN
  RAISE EXCEPTION 'initialization evidence unavailable; stop maintenance';
 END IF;
 RAISE NOTICE 'maintenance events found=%; events alone do not identify an invocation',evidence_count;
EXCEPTION WHEN data_exception THEN
 RAISE EXCEPTION 'invalid maintenance evidence; stop maintenance';
END $$;
SELECT authority_id,bootstrap_tenant FROM identity_authority.deployment;
SELECT a.tenant_id,a.principal_id,a.enabled,a.administrator,a.emergency,
       a.auth_epoch,m.active,m.epoch AS membership_epoch
FROM identity_authority.accounts a JOIN identity_authority.memberships m USING(tenant_id,principal_id)
WHERE a.tenant_id=:'tenant'::uuid AND a.principal_id=:'principal'::uuid;
COMMIT;
SQL
```

| 观察 | 判定与下一步 |
| --- | --- |
| 初始化：bootstrap tenant/账户和 initialized 事件一致 | 初始化已提交，不再次 initialize；按原输入密码继续正常操作。 |
| 初始化：bootstrap tenant 为空、目标账户和事件均缺失，已确认原事务结束且记录完整 | 可明确发起一次新的 initialize；并发保护仍在。 |
| 初始化：bootstrap 已指向其它 tenant、仅部分对象存在或记录冲突 | 不继续接管；由 owner 排查数据库身份、并发操作、迁移或数据损坏。 |
| 恢复：当前 epoch 与对应 administrator_recovered 事件一致，且有独占操作时间窗/先前 epoch 记录 | 可确认该恢复提交；保留停用/成员状态，按受控正常入口验证账户可用性。 |
| 恢复：epoch/事件没有变化，原事务已结束且已有完整操作前基线 | 可以明确发起新的恢复，不能将此前命令显示为成功。 |
| 恢复：没有操作前基线、期间有其它写入、Outbox 已清理或记录不完整 | 不能唯一关联此前调用。停止并发写入，明确发起一次新的恢复并取得确认提交；不回读或“释放”不确定凭据。 |
| 任意：查询报错、行数不符、状态与事件矛盾、数据库/lineage 不符 | 停止操作，先调查，不直接改账户表或自动重试。 |

上述 SQL 会对数据库身份、行数和同 epoch 的状态/事件矛盾报错；`ON_ERROR_STOP` 阻止将错误当作成功或空结果继续。事务级 tenant context 同样约束受 FORCE RLS 保护的普通表 owner，不要求 superuser/BYPASSRLS。

事件不含密码证明，也没有新加操作幂等键，因此“最新一条恢复事件”在存在其它写入时不能证明是本次调用。只读核实用于运维决策，不自动驱动重试。MFA/IdP、备份、密钥和身份流程恢复仍不由密码恢复覆盖。

参考：[PostgreSQL 17 FORCE ROW LEVEL SECURITY](https://www.postgresql.org/docs/17/ddl-rowsecurity.html)、[事务级 set_config](https://www.postgresql.org/docs/17/functions-admin.html#FUNCTIONS-ADMIN-SET)。`maintenance_runbook_respects_forced_rls` 直接读取本页 SQL，在无 superuser/BYPASSRLS 的表 owner 下验证租户可见性、错误数据库身份、缺成员及事件/epoch 矛盾。
