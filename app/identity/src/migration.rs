//! Fresh reference-host installation; existing schemas are rejected without mutation.
use crate::{AppError, config::MigrationConfig};
use rss_identity_core::InstanceId;
use rss_identity_postgres::{AuthorityProfile, grant_profile};
use sqlx::{Connection, PgConnection};
pub async fn install(config: MigrationConfig) -> Result<(), AppError> {
    if config.format_version != 3
        || config.runtime_role == config.maintenance_role
        || config.runtime_role == config.database.user
        || config.maintenance_role == config.database.user
    {
        return Err(AppError::Configuration);
    }
    let instance = InstanceId::parse(&config.instance_id).map_err(|_| AppError::Configuration)?;
    let tenants = config.storage.tenants()?;
    config.storage.binding()?;
    let mut c = PgConnection::connect_with(&config.database.sqlx()?)
        .await
        .map_err(|_| AppError::Connection)?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut tx = c.begin().await?;
        sqlx::raw_sql("SET LOCAL lock_timeout='10s'; SET LOCAL statement_timeout='30s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(2435,9)")
            .execute(&mut *tx)
            .await?;
        // RSS's migration owns its relay role contract. Roles/logins are provisioned by the host operator.
        sqlx::raw_sql(rss_transactional_messaging_postgres::MIGRATION_SQL)
            .execute(&mut *tx)
            .await?;
        rss_identity_postgres::install(&mut tx, instance).await?;
        grant_profile(&mut tx, &config.runtime_role, AuthorityProfile::Runtime).await?;
        grant_profile(
            &mut tx,
            &config.maintenance_role,
            AuthorityProfile::Maintenance,
        )
        .await?;
        sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
            .bind(config.storage.target.as_slice())
            .bind(config.storage.lineage.as_slice())
            .execute(&mut *tx)
            .await?;
        for tenant in tenants {
            sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,$2)")
                .bind(tenant.to_string())
                .bind(config.storage.generation)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    })
    .await;
    let closed = c.close().await;
    result
        .map_err(|_| AppError::Migration)?
        .map_err(|_| AppError::Migration)?;
    closed.map_err(|_| AppError::Migration)
}
