//! Fresh-install transaction. Never upgrades, repairs, or destroys an existing installation.
use crate::{AppError, assembly, config::MigrationConfig, read_secret};
use sqlx::{Connection, Executor, PgConnection};
use std::path::Path;
const RELAY: &str = "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='rss_tmsg_relay') THEN CREATE ROLE rss_tmsg_relay NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION; ELSIF EXISTS(SELECT FROM pg_roles WHERE rolname='rss_tmsg_relay' AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR rolreplication)) OR EXISTS(SELECT FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='rss_tmsg_relay') THEN RAISE EXCEPTION 'unsafe relay role'; END IF; END $$;";
const GRANTS: &str = include_str!("grants.sql");
fn literal(value: &str) -> Result<String, AppError> {
    if value.is_empty() || value.len() > 4096 || value.contains(['\0', '\n', '\r']) {
        return Err(AppError::Configuration);
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}
pub async fn install(c: MigrationConfig) -> Result<(), AppError> {
    if c.format_version != 1
        || c.database.user == "identity_runtime"
        || c.database.user == "identity_maintenance"
    {
        return Err(AppError::Configuration);
    }
    c.storage.binding()?;
    let runtime_secret = read_secret(Path::new(&c.runtime_password_file))?;
    let maintenance_secret = read_secret(Path::new(&c.maintenance_password_file))?;
    if runtime_secret.len() < 32
        || maintenance_secret.len() < 32
        || *runtime_secret == *maintenance_secret
    {
        return Err(AppError::Configuration);
    }
    let mut connection = PgConnection::connect_with(&c.database.sqlx()?)
        .await
        .map_err(|_| AppError::Connection)?;
    // A session lock serializes commit verification as well as installation. Close always releases it.
    let result=tokio::time::timeout(std::time::Duration::from_secs(60),async{
        sqlx::query("SELECT pg_advisory_lock(2338,1)").execute(&mut connection).await.map_err(|_|AppError::Migration)?;
        let mut tx=connection.begin().await.map_err(|_|AppError::Migration)?;
        sqlx::raw_sql("SET LOCAL lock_timeout='10s'; SET LOCAL statement_timeout='30s'; SET LOCAL standard_conforming_strings=on").execute(&mut *tx).await.map_err(|_|AppError::Migration)?;
        let exists:bool=sqlx::query_scalar("SELECT to_regnamespace('identity_authority') IS NOT NULL OR to_regnamespace('rss_transactional_messaging') IS NOT NULL").fetch_one(&mut *tx).await.map_err(|_|AppError::Migration)?;
        if !exists {
            tx.execute(RELAY).await.map_err(|_|AppError::Migration)?;
            tx.execute(rss_transactional_messaging_postgres::MIGRATION_SQL).await.map_err(|_|AppError::Migration)?;
            tx.execute(rss_identity_postgres::MIGRATION_SQL).await.map_err(|_|AppError::Migration)?;
            for (role,password) in [("identity_runtime",&runtime_secret),("identity_maintenance",&maintenance_secret)] {
                let sql=zeroize::Zeroizing::new(format!("CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION PASSWORD {}",literal(password)?));
                sqlx::raw_sql(sqlx::AssertSqlSafe(sql.as_str())).execute(&mut *tx).await.map_err(|_|AppError::Migration)?;
            }
            tx.execute(GRANTS).await.map_err(|_|AppError::Migration)?;
            sqlx::query("UPDATE identity_authority.deployment SET environment_id=$1,identity_config_version=$2,identity_public_origin=$3,product_public_origin=$4")
                .bind(c.identity_origin.environment()).bind(c.identity_origin.version()).bind(c.identity_origin.identity_origin()).bind(c.identity_origin.product_origin()).execute(&mut *tx).await.map_err(|_|AppError::Migration)?;
            sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)").bind(c.storage.target.as_slice()).bind(c.storage.lineage.as_slice()).execute(&mut *tx).await.map_err(|_|AppError::Migration)?;
            for tenant in &c.storage.tenants {sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,$2)").bind(&tenant.tenant_id).bind(tenant.epoch).execute(&mut *tx).await.map_err(|_|AppError::Migration)?;}
        }
        // Existing installations never take a mutation/repair branch.
        let version:Vec<i32>=sqlx::query_scalar("SELECT version FROM identity_authority.schema_version").fetch_all(&mut *tx).await.map_err(|_|AppError::Migration)?;
        if version!=[6]{return Err(AppError::Migration);}
        let matches:bool=sqlx::query_scalar("SELECT count(*)=1 AND coalesce(bool_and(environment_id=$1 AND identity_config_version=$2 AND identity_public_origin=$3 AND product_public_origin=$4),false) FROM identity_authority.deployment")
            .bind(c.identity_origin.environment()).bind(c.identity_origin.version()).bind(c.identity_origin.identity_origin()).bind(c.identity_origin.product_origin()).fetch_one(&mut *tx).await.map_err(|_|AppError::Migration)?;
        if !matches{return Err(AppError::Migration);}
        let signature:String=sqlx::query_scalar(rss_identity_postgres::SCHEMA_SIGNATURE_SQL).fetch_one(&mut *tx).await.map_err(|_|AppError::Migration)?;
        if signature!=rss_identity_postgres::SCHEMA_SIGNATURE.trim(){return Err(AppError::Migration);}
        tx.commit().await.map_err(|_|AppError::Migration)?;
        // Verify real runtime/maintenance logins after commit, still holding the installation lock.
        for (user,path,profile) in [("identity_runtime",&c.runtime_password_file,rss_identity_postgres::AuthorityProfile::Runtime),("identity_maintenance",&c.maintenance_password_file,rss_identity_postgres::AuthorityProfile::Maintenance)]{
            let mut db=c.database.clone();db.user=user.into();db.password_file=path.clone();
            let pool=std::sync::Arc::new(rss_transactional_messaging_postgres::PgRuntime::connect(db.pg()?,assembly::Timer,c.storage.binding()?).await.map_err(|_|AppError::Migration)?);
            let kdf=std::sync::Arc::new(rss_identity_core::account::PasswordKdf::new());
            let result=async{for tenant in c.storage.tenants()? {rss_identity_postgres::Authority::connect(pool.clone(),kdf.clone(),c.identity_origin.clone(),assembly::delivery_budget()?,tenant,profile,assembly::deadline()).await?;}Ok::<_,AppError>(())}.await;
            pool.close().await;
            result?;
        }
        Ok(())
    }).await.map_err(|_|AppError::Migration).and_then(|r|r);
    let closed = connection.close().await;
    result?;
    closed.map_err(|_| AppError::Migration)?;
    Ok(())
}
