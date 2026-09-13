//! Bounded owner-side credential re-encryption under the externally configured restore generation.
use crate::{AppError, config::MigrationConfig};
use sqlx::{Connection, Row};
pub async fn run(c: MigrationConfig) -> Result<u64, AppError> {
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
    let mut connection = sqlx::PgConnection::connect_with(&c.database.sqlx()?)
        .await
        .map_err(|_| AppError::Migration)?;
    let result=tokio::time::timeout(std::time::Duration::from_secs(60),async{
        let mut tx=connection.begin().await.map_err(|_|AppError::Migration)?;
        bind(&mut tx,&c,&c.storage.system_domain_id).await?;
        let authority:uuid::Uuid=sqlx::query_scalar("SELECT authority_id FROM identity_authority.deployment WHERE system_domain=$1::uuid AND environment_id=$2 AND identity_config_version=$3 AND identity_public_origin=$4 AND product_public_origin=$5").bind(&c.storage.system_domain_id).bind(c.identity_origin.environment()).bind(c.identity_origin.version()).bind(c.identity_origin.identity_origin()).bind(c.identity_origin.product_origin()).fetch_one(&mut *tx).await.map_err(|_|AppError::Migration)?;
        let versions:Vec<i32>=sqlx::query_scalar("SELECT version FROM identity_authority.schema_version").fetch_all(&mut *tx).await.map_err(|_|AppError::Migration)?;
        if versions!=[rss_identity_postgres::SCHEMA_VERSION]{return Err(AppError::Migration);}
        let mut tenants:Vec<String>=sqlx::query_scalar("SELECT business_tenant::text FROM identity_authority.tenant_registry WHERE tenant_id=$1::uuid ORDER BY business_tenant LIMIT 128").bind(&c.storage.system_domain_id).fetch_all(&mut *tx).await.map_err(|_|AppError::Migration)?;
        if tenants.len()>127{return Err(AppError::Migration);}tenants.push(c.storage.system_domain_id.clone());
        let mut rewritten=0;
        for tenant in tenants {
            bind(&mut tx,&c,&tenant).await?;
            let rows=sqlx::query("SELECT provider_id::text,credential_version,sealed FROM identity_authority.provider_credentials WHERE tenant_id=$1::uuid ORDER BY provider_id LIMIT 101 FOR UPDATE").bind(&tenant).fetch_all(&mut *tx).await.map_err(|_|AppError::Migration)?;
            if rows.len()>100{return Err(AppError::Migration);}
            for row in rows {
                let provider:String=row.try_get("provider_id").map_err(|_|AppError::Migration)?;
                let version:i64=row.try_get("credential_version").map_err(|_|AppError::Migration)?;
                let old:serde_json::Value=row.try_get("sealed").map_err(|_|AppError::Migration)?;
                let new=keys.reencrypt_value(authority,rss_request_context::TenantId::parse(&tenant).map_err(|_|AppError::Migration)?,rss_identity_core::federation::ProviderId::parse(&provider).map_err(|_|AppError::Migration)?,version,old.clone())?;
                if old!=new {
                    sqlx::query("UPDATE identity_authority.provider_credentials SET sealed=$3 WHERE tenant_id=$1::uuid AND provider_id=$2::uuid").bind(&tenant).bind(&provider).bind(new).execute(&mut *tx).await.map_err(|_|AppError::Migration)?;rewritten+=1;
                    if rewritten==100 {tx.commit().await.map_err(|_|AppError::Migration)?;return Ok(rewritten);}
                }
            }
        }
        tx.commit().await.map_err(|_|AppError::Migration)?;Ok(rewritten)
    }).await.map_err(|_|AppError::Migration).and_then(|v|v);
    let closed = connection.close().await;
    result.and_then(|v| closed.map(|_| v).map_err(|_| AppError::Migration))
}
async fn bind(
    c: &mut sqlx::PgConnection,
    config: &MigrationConfig,
    tenant: &str,
) -> Result<(), AppError> {
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true),set_config('lock_timeout','10s',true),set_config('statement_timeout','30s',true)").bind(tenant).bind(hex::encode(config.storage.target)).bind(hex::encode(config.storage.lineage)).bind(config.storage.generation.to_string()).execute(&mut *c).await.map_err(|_|AppError::Migration)?;
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(c)
        .await
        .map_err(|_| AppError::Migration)?;
    Ok(())
}
