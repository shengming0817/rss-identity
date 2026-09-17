//! Owner-side rotation; component owns encrypted values and SQL. No retry after unknown commit.
//! Derived from app/identity/src/rekey.rs at b8159ad^; ref: sqlx transaction.rs (0.9.0).
use crate::{
    AppError,
    config::{CredentialKeyringConfig, MigrationConfig},
    migration,
};
use sqlx::{Connection, PgConnection};
use std::time::Duration;

pub async fn run(
    config: MigrationConfig,
    keyring: CredentialKeyringConfig,
    verify_only: bool,
) -> Result<(), AppError> {
    let instance = migration::validate(&config)?;
    if verify_only && keyring.keys.len() != 1 {
        return Err(AppError::Configuration);
    }
    let keys = keyring.load()?;
    let options = config.database.sqlx()?;
    let mut c = tokio::time::timeout(
        Duration::from_secs(10),
        PgConnection::connect_with(&options),
    )
    .await
    .map_err(|_| AppError::Connection)?
    .map_err(|_| AppError::Connection)?;
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        let mut tx = c.begin().await.map_err(|_| AppError::Migration)?;
        sqlx::raw_sql("SET LOCAL lock_timeout='10s'; SET LOCAL statement_timeout='30s'").execute(&mut *tx).await.map_err(|_| AppError::Migration)?;
        migration::verify_storage(&mut tx, &config.storage).await.map_err(|_| AppError::Migration)?;
        let signature: Option<String> = sqlx::query_scalar(rss_identity_postgres::SCHEMA_SIGNATURE_SQL).fetch_one(&mut *tx).await.map_err(|_| AppError::Migration)?;
        if signature.as_deref() != Some(rss_identity_postgres::SCHEMA_SIGNATURE.trim()) { return Err(AppError::Migration); }
        for tenant in config.storage.tenants()? {
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true)")
                .bind(tenant.to_string()).bind(hex::encode(config.storage.target)).bind(hex::encode(config.storage.lineage)).bind(config.storage.generation.to_string()).execute(&mut *tx).await.map_err(|_| AppError::Migration)?;
            sqlx::query("SELECT rss_transactional_messaging.check_execution()").execute(&mut *tx).await.map_err(|_| AppError::Migration)?;
            keys.reencrypt_tenant(&mut tx, instance, tenant).await?;
        }
        if verify_only { tx.rollback().await } else { tx.commit().await }.map_err(|_| AppError::Migration)
    }).await.map_err(|_| AppError::Migration).and_then(|v| v);
    // Owned connection is discarded after uncertain settlement; never returned to a runtime pool.
    if !matches!(
        tokio::time::timeout(Duration::from_secs(5), c.close()).await,
        Ok(Ok(()))
    ) {
        eprintln!("component=credential-rekey cleanup=unconfirmed");
    }
    result
}
