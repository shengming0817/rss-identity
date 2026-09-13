//! Bounded owner-side credential re-encryption under the external restore generation.
//! ref: tokio 1.53.1 time/timeout.rs; sqlx 0.8.6 connection/mod.rs and transaction.rs.
use crate::{AppError, config::MigrationConfig};
use rss_identity_postgres::CredentialKeys;
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
use tokio::time::{Instant, timeout_at};

const BATCH_SIZE: u64 = 100;
pub async fn run(c: MigrationConfig) -> Result<u64, AppError> {
    let cutoff = Instant::now() + std::time::Duration::from_secs(60);
    c.storage.binding()?;
    if c.format_version != 2
        || matches!(
            c.database.user.as_str(),
            "identity_runtime" | "identity_maintenance"
        )
    {
        return Err(AppError::Configuration);
    }
    let keys = c.credential_keyring.load()?;
    let options = c.database.sqlx()?;
    run_connected(&c, &keys, options, cutoff).await
}
async fn run_connected(
    config: &MigrationConfig,
    keys: &CredentialKeys,
    options: PgConnectOptions,
    cutoff: Instant,
) -> Result<u64, AppError> {
    if Instant::now() >= cutoff {
        return Err(AppError::Migration);
    }
    let mut connection = timeout_at(cutoff, PgConnection::connect_with(&options))
        .await
        .map_err(|_| AppError::Migration)?
        .map_err(|_| AppError::Migration)?;
    let result = timeout_at(cutoff, batch(&mut connection, config, keys))
        .await
        .map_err(|_| AppError::Migration)
        .and_then(|v| v);
    // This is an owned connection, never returned to a pool after an uncertain transaction.
    if Instant::now() >= cutoff {
        drop(connection);
    } else if !matches!(timeout_at(cutoff, connection.close()).await, Ok(Ok(()))) {
        eprintln!("component=credential_rekey_connection result=close_unconfirmed");
    }
    // A close failure cannot erase a commit acknowledgement already received by batch.
    result
}
async fn batch(
    connection: &mut PgConnection,
    config: &MigrationConfig,
    keys: &CredentialKeys,
) -> Result<u64, AppError> {
    let mut tx = connection.begin().await.map_err(|_| AppError::Migration)?;
    bind(&mut tx, config, &config.storage.system_domain_id).await?;
    let authority: uuid::Uuid = sqlx::query_scalar(
        "SELECT authority_id FROM identity_authority.deployment WHERE system_domain=$1::uuid
         AND environment_id=$2 AND identity_config_version=$3
         AND identity_public_origin=$4 AND product_public_origin=$5",
    )
    .bind(&config.storage.system_domain_id)
    .bind(config.identity_origin.environment())
    .bind(config.identity_origin.version())
    .bind(config.identity_origin.identity_origin())
    .bind(config.identity_origin.product_origin())
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AppError::Migration)?;
    let versions: Vec<i32> =
        sqlx::query_scalar("SELECT version FROM identity_authority.schema_version")
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| AppError::Migration)?;
    if versions != [rss_identity_postgres::SCHEMA_VERSION] {
        return Err(AppError::Migration);
    }
    let mut tenants: Vec<String> = sqlx::query_scalar(
        "SELECT business_tenant::text FROM identity_authority.tenant_registry
         WHERE tenant_id=$1::uuid ORDER BY business_tenant LIMIT 128",
    )
    .bind(&config.storage.system_domain_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| AppError::Migration)?;
    if tenants.len() > 127 {
        return Err(AppError::Migration);
    }
    tenants.push(config.storage.system_domain_id.clone());
    tenants.sort();
    let mut rewritten = 0;
    for tenant in tenants {
        bind(&mut tx, config, &tenant).await?;
        // Completed rows leave the candidate set, so each invocation progresses without
        // a persisted cursor and never locks already-active credentials.
        let rows: Vec<(uuid::Uuid, i64, serde_json::Value)> = sqlx::query_as(
            "SELECT provider_id,credential_version,sealed FROM identity_authority.provider_credentials
             WHERE tenant_id=$1::uuid AND sealed->>'key_id' IS DISTINCT FROM $2
             ORDER BY provider_id LIMIT $3 FOR UPDATE",
        )
        .bind(&tenant)
        .bind(keys.active_key_id())
        .bind((BATCH_SIZE - rewritten) as i64)
        .fetch_all(&mut *tx).await.map_err(|_| AppError::Migration)?;
        for (provider, version, sealed) in rows {
            let new = keys.reencrypt_value(
                authority,
                rss_request_context::TenantId::parse(&tenant).map_err(|_| AppError::Migration)?,
                rss_identity_core::federation::ProviderId::parse(&provider.to_string())
                    .map_err(|_| AppError::Migration)?,
                version,
                sealed,
            )?;
            sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2")
                .bind(&tenant).bind(provider).bind(new).execute(&mut *tx).await.map_err(|_| AppError::Migration)?;
            rewritten += 1;
        }
        if rewritten == BATCH_SIZE {
            break;
        }
    }
    tx.commit().await.map_err(|_| AppError::Migration)?;
    Ok(rewritten)
}
async fn bind(
    c: &mut PgConnection,
    config: &MigrationConfig,
    tenant: &str,
) -> Result<(), AppError> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true),set_config('lock_timeout','10s',true),set_config('statement_timeout','30s',true)")
        .bind(tenant).bind(hex::encode(config.storage.target)).bind(hex::encode(config.storage.lineage)).bind(config.storage.generation.to_string()).execute(&mut *c).await.map_err(|_|AppError::Migration)?;
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(c)
        .await
        .map_err(|_| AppError::Migration)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_connection_is_bounded_and_discarded() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.unwrap();
            assert!(!bytes.is_empty());
        });
        let config:MigrationConfig=serde_json::from_value(serde_json::json!({"format_version":2,"identity_origin":{"environment_id":"deadline-test","config_version":1,"identity_public_origin":"https://identity.test","product_public_origin":"https://product.test"},"database":{"host":"127.0.0.1","port":port,"database":"fixture","user":"owner","password_file":"unused","ca_file":"unused"},"storage":{"target":vec![1;16],"lineage":vec![2;16],"system_domain_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","generation":1},"runtime_password_file":"unused","maintenance_password_file":"unused","credential_keyring":{"active_key_id":"test","keys":[]}})).unwrap();
        let keys = CredentialKeys::new("test".into(), vec![("test".into(), [8; 32])]).unwrap();
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(port)
            .username("owner")
            .database("fixture")
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_connected(
                &config,
                &keys,
                options,
                Instant::now() + std::time::Duration::from_millis(100),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(result, Err(AppError::Migration)));
        tokio::time::timeout(std::time::Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
    }
}
