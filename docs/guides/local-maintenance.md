# 本机维护：开发库安装与不确定结果核实

适用 #2358/#2334/#2335 的可丢弃专属开发库（当前初始安装为 schema version 8）；不用于已有生产数据升级。本工具不自动执行下列管理 SQL。维护密码恢复始终通过 `identity-admin CONFIG recover <tenant> <principal> <password-file>`，下列账户/事件查询只有只读用途。

## 安装与凭据

旧checkout拼接SQL的安装步骤已退出。使用 [I08安装入口](../deployment/operations.md) 的 identity-migrate，凭据与schema/grants一次闭合；维护只消费独立的maintenance配置。当前初始schema为v8，所有旧开发库（含 v7）不得原地升级或自动清理。

Owner 只读核实非秘密安装身份：

```sql
SELECT version FROM identity_authority.schema_version; -- 恰好一行，8
SELECT authority_id,system_domain FROM identity_authority.deployment; -- 恰好一行，记录 authority_id；尚未初始化时 system_domain 为 NULL
SELECT encode(target,'hex'),encode(lineage,'hex') FROM rss_transactional_messaging.storage_lineage;
SELECT tenant_id,epoch FROM rss_transactional_messaging.tenant_epoch;
SELECT rolname,rolcanlogin,rolsuper,rolbypassrls FROM pg_roles
WHERE rolname IN ('identity_runtime','identity_maintenance','identity_account_runtime','identity_account_maintenance');
SELECT NOT EXISTS(SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member OR r.oid=m.roleid
 WHERE r.rolname='rss_tmsg_relay') AS relay_has_no_parent_roles; -- 必须为 true
```

维护 CLI 配置使用独立 identity_maintenance 用户；runtime 凭据由服务装配持有。配置示例（替换主机、端口和文件路径；省略号不能放入实际 JSON）：

```json
{
  "identity_origin": {"environment_id":"development","config_version":1,"identity_public_origin":"https://identity.example.test","product_public_origin":"https://mdm.example.test"},
  "host": "pg.dev.example.test", "port": 5432, "database": "rss_identity_dev",
  "user": "identity_maintenance", "password_file": "/private/identity/maintenance-db-password",
  "ca_file": "/private/identity/ca.pem",
  "system_domain_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "storage_target": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
  "storage_lineage": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
  "storage_generation": 1
}
```

准备符合密码规则的私有新密码文件后，在 Identity checkout 中初始化系统域平台账户。这里只说明操作，不将文档或低层测试冒充 T3 运行证明：

```sh
cargo build --locked -p rss-identity-app
PRINCIPAL_UUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
./target/debug/identity-admin /private/identity/maintenance.json initialize "$PRINCIPAL_UUID" platform /private/identity/admin-password
```

每个命令连接时都会执行 RSS 与 Identity 权限/存储探测。错误分类分别指示 schema 版本、角色不匹配、权限漂移或 schema/RLS 契约漂移；provider 失败仍保留其 settlement 分类，不回显连接值。

## 不确定提交：只读核实

CommitUnknown/RollbackFailed 表示结果未知，退出码不能证明未提交。先等待原命令退出并停止同目标的其它维护/管理写入；核实连接到原始数据库和 lineage，不能在落后的副本或恢复点上据缺失记录判未提交。使用 owner 的只读事务；不把 owner 凭据注入日常服务，也不通过 UPDATE 密码恢复。

使用执行前记录的 authority_id、配置中的 storage target/lineage 和已知 tenant/principal（初始化前生成的 UUID，不依赖成功 stdout）查询。缺少数据库身份基线时停止，不用查询当前值反填为“预期值”。下列完整 SQL 仅核实业务租户 recover；operation 必须为 recover。系统域初始化以不可变 system_domain、平台角色、账户/成员及 identity.platform.security 事件核实，不能按业务租户 initialized 事件推断。事件过滤只解码账户安全事件，并只输出 action、tenant、principal、epoch、时间和事件 ID，不展示密码哈希、完整 envelope 或其它业务 payload：

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
BEGIN
 IF operation <> 'recover' THEN
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
 SELECT system_domain INTO bootstrap FROM identity_authority.deployment;
 SELECT count(*) INTO accounts_count FROM identity_authority.accounts WHERE tenant_id=t AND principal_id=p;
 SELECT count(*) INTO members_count FROM identity_authority.memberships WHERE tenant_id=t AND principal_id=p;
 IF bootstrap IS NULL OR accounts_count<>1 OR members_count<>1 THEN
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
  AND payload->>'action' IN ('administrator_recovered') ORDER BY seq DESC LIMIT 20
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
  RAISE NOTICE 'event id=% action=% tenant=% principal=% epoch=% time=%',
    evidence.envelope->>'id',evidence.payload->>'action',t,p,event_epoch,evidence.envelope->>'occurred_at';
 END LOOP;

 RAISE NOTICE 'maintenance events found=%; events alone do not identify an invocation',evidence_count;
EXCEPTION WHEN data_exception THEN
 RAISE EXCEPTION 'invalid maintenance evidence; stop maintenance';
END $$;
SELECT authority_id,system_domain FROM identity_authority.deployment;
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

系统域初始化后，业务租户必须通过[平台 CLI/API](platform.md)开通，不能再次 initialize。系统域恢复还要求目标当前仍为平台管理员；只换密码，不恢复平台资格。
