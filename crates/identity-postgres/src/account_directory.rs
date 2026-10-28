//! Account queries execute before LIMIT under the authenticated tenant transaction.
//! ref: launchbadge/sqlx v0.9.0 sqlx-core/src/query_builder.rs.
use crate::{
    transaction::{MutationError, corrupt, reject},
    types::Budget,
    *,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use rss_identity_core::directory::{AccountQuery, Expression, Field};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, QueryBuilder};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDirectoryRow {
    pub principal_id: String,
    pub login: Option<String>,
    pub enabled: bool,
    pub member_active: bool,
    pub has_local_password: bool,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub profile_status: String,
    pub department_status: String,
    pub department_snapshot: Option<rss_identity_core::department::DepartmentSnapshot>,
}
pub struct AccountPage {
    pub accounts: Vec<AccountDirectoryRow>,
    pub fields: Vec<Field>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    binding: Vec<u8>,
    expires: i64,
    position: Vec<Value>,
}

fn column(field: Field) -> &'static str {
    match field {
        Field::PrincipalId => "\"principalId\" COLLATE \"C\"",
        Field::Login => "login COLLATE \"C\"",
        Field::Enabled => "enabled",
        Field::MemberActive => "\"memberActive\"",
        Field::HasLocalPassword => "\"hasLocalPassword\"",
        Field::DisplayName => "\"displayName\" COLLATE \"C\"",
        Field::Email => "email COLLATE \"C\"",
        Field::ProfileStatus => "\"profileStatus\" COLLATE \"C\"",
        Field::DepartmentStatus => "\"departmentStatus\" COLLATE \"C\"",
        _ => unreachable!("checked scalar field"),
    }
}
fn operand(sql: &mut QueryBuilder<Postgres>, field: Field, value: &str) {
    if field.boolean() {
        sql.push_bind(value == "true");
    } else {
        sql.push_bind(value.to_owned());
    }
}
fn filter(sql: &mut QueryBuilder<Postgres>, expression: &Expression) {
    sql.push("(");
    match expression {
        Expression::And(items) | Expression::Or(items) => {
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    sql.push(if matches!(expression, Expression::And(_)) {
                        " AND "
                    } else {
                        " OR "
                    });
                }
                filter(sql, item);
            }
        }
        Expression::Compare {
            field,
            operator,
            values,
        } => {
            if matches!(field, Field::Department | Field::DepartmentSubtree) {
                sql.push("\"departmentStatus\"='available' AND EXISTS(WITH RECURSIVE ancestors(id) AS (SELECT jsonb_array_elements_text(\"departmentSnapshot\"->'memberships') UNION SELECT n->>'parentId' FROM ancestors x CROSS JOIN LATERAL jsonb_array_elements(\"departmentSnapshot\"->'nodes') n WHERE n->>'id'=x.id AND ");
                sql.push(if *field == Field::DepartmentSubtree {
                    "true"
                } else {
                    "false"
                });
                sql.push(" AND n->>'parentId' IS NOT NULL) SELECT FROM ancestors WHERE id=")
                    .push_bind(values[0].clone())
                    .push(")");
            } else if matches!(operator.as_str(), "=isnull=" | "=isnotnull=") {
                sql.push(column(*field)).push(if operator == "=isnull=" {
                    " IS NULL"
                } else {
                    " IS NOT NULL"
                });
            } else if operator == "=icontains=" {
                sql.push("strpos(lower(")
                    .push(column(*field))
                    .push("),lower(")
                    .push_bind(values[0].clone())
                    .push("))>0");
            } else {
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        sql.push(if operator == "=out=" { " AND " } else { " OR " });
                    }
                    sql.push(column(*field)).push(match operator.as_str() {
                        "==" | "=in=" => " = ",
                        "!=" | "=out=" => " <> ",
                        "=lt=" => " < ",
                        "=le=" => " <= ",
                        "=gt=" => " > ",
                        "=ge=" => " >= ",
                        _ => unreachable!("checked operator"),
                    });
                    operand(sql, *field, value);
                }
            }
        }
    }
    sql.push(")");
}
fn position(sql: &mut QueryBuilder<Postgres>, field: Field, value: &Value) {
    if value.is_null() {
        sql.push(if field.boolean() {
            "NULL::boolean"
        } else {
            "NULL::text"
        });
    } else if field.boolean() {
        sql.push_bind(value.as_bool().expect("checked boolean cursor"));
    } else {
        sql.push_bind(value.as_str().expect("checked text cursor").to_owned());
    }
}
fn after(sql: &mut QueryBuilder<Postgres>, query: &AccountQuery, values: &[Value]) {
    sql.push(" AND (");
    for (index, sort) in query.sort().iter().enumerate() {
        if index > 0 {
            sql.push(" OR ");
        }
        sql.push("(");
        for (prefix, value) in values.iter().enumerate().take(index) {
            sql.push(column(query.sort()[prefix].field))
                .push(" IS NOT DISTINCT FROM ");
            position(sql, query.sort()[prefix].field, value);
            sql.push(" AND ");
        }
        if values[index].is_null() {
            sql.push("false");
        } else {
            sql.push("(")
                .push(column(sort.field))
                .push(if sort.descending { " < " } else { " > " });
            position(sql, sort.field, &values[index]);
            sql.push(" OR ").push(column(sort.field)).push(" IS NULL)");
        }
        sql.push(")");
    }
    sql.push(")");
}
fn encode(key: &[u8], cursor: &Cursor) -> Result<String, MutationError> {
    let plain = serde_json::to_vec(cursor).map_err(|_| corrupt())?;
    let mut signed = b"identity.accounts.cursor.v1\0".to_vec();
    signed.extend(&plain);
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &signed);
    let mut bytes = tag.as_ref().to_vec();
    bytes.extend(plain);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn decode(key: &[u8], raw: &str) -> Result<Cursor, MutationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| MutationError::InvalidInput)?;
    if bytes.len() <= 32 || bytes.len() > 4096 {
        return Err(MutationError::InvalidInput);
    }
    let mut signed = b"identity.accounts.cursor.v1\0".to_vec();
    signed.extend(&bytes[32..]);
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &signed,
        &bytes[..32],
    )
    .map_err(|_| MutationError::CursorInvalidated)?;
    serde_json::from_slice(&bytes[32..]).map_err(|_| MutationError::InvalidInput)
}

impl Authority {
    pub async fn read_account(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        deadline: OperationDeadline,
    ) -> Result<AccountView, AuthorityError> {
        self.require_runtime()?;
        if target.tenant != actor.key.tenant {
            return Err(AuthorityError::Rejected);
        }
        let budget = Budget::new(deadline)?;
        let policy = self.policy.clone();
        let instance = self.instance;
        self.read_sql(target.tenant,budget.remaining(),move |c|Box::pin(async move {
            let loaded=crate::session_storage::recheck(c,&actor).await?;
            crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::ReadAccount,Some(target),c).await?;
            let expires=crate::sessions::checked_expiry(&loaded,budget.0)?;
            let state=crate::storage::load(c,target).await?.state;
            let login=sqlx::query_scalar("SELECT login_key FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND principal_id=$2").bind(target.tenant.to_string()).bind(target.principal.as_uuid()).fetch_optional(c).await?;
            if std::time::Instant::now()>=expires { return Err(reject().into()); }
            Ok(AccountView::new(state,login))
        })).await
    }
    pub async fn list_accounts(
        &self,
        actor: AuthenticatedSession,
        query: AccountQuery,
        cursor: Option<String>,
        deadline: OperationDeadline,
    ) -> Result<AccountPage, AuthorityError> {
        self.require_runtime()?;
        if cursor
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 4096)
        {
            return Err(AuthorityError::InvalidInput);
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.min(actor.expires);
        let policy = self.policy.clone();
        let instance = self.instance;
        let max_age = self.profile_limits.max_age_seconds();
        self.read_sql(actor.key.tenant, budget.remaining(), move |c| {
            Box::pin(async move {
                let loaded = crate::session_storage::recheck(c, &actor).await?;
                for op in [
                    Some(ManagementOperation::ListAccounts),
                    query
                        .needs_profiles()
                        .then_some(ManagementOperation::ReadLatestProfile),
                    query
                        .needs_departments()
                        .then_some(ManagementOperation::ReadLatestDepartments),
                ]
                .into_iter()
                .flatten()
                {
                    crate::management::authorize(policy.as_ref(), instance, &loaded, op, None, c)
                        .await?;
                }
                let window = crate::personnel::read_window(
                    c,
                    actor.key.tenant,
                    query.needs_profiles().then_some(max_age),
                    query.needs_departments().then(|| query.source()).flatten(),
                    budget.0,
                    Some(
                        loaded
                            .view
                            .idle_expires_at
                            .min(loaded.view.absolute_expires_at),
                    ),
                )
                .await?;
                let key = actor.digest;
                let binding = Sha256::digest(
                    serde_json::to_vec(&(
                        instance.to_string(),
                        actor.key.tenant.to_string(),
                        actor.key.principal.as_uuid().to_string(),
                        loaded.view.id.to_string(),
                        window.generation,
                        &query,
                    ))
                    .map_err(|_| corrupt())?,
                )
                .to_vec();
                let seek = cursor.as_ref().map(|raw| decode(&key, raw)).transpose()?;
                if let Some(seek) = &seek {
                    if seek.binding != binding || seek.expires <= window.now {
                        return Err(MutationError::CursorInvalidated);
                    }
                    if seek.position.len() != query.sort().len()
                        || query
                            .sort()
                            .iter()
                            .zip(&seek.position)
                            .any(|(sort, value)| {
                                !value.is_null()
                                    && if sort.field.boolean() {
                                        !value.is_boolean()
                                    } else {
                                        !value.is_string()
                                    }
                            })
                    {
                        return Err(MutationError::InvalidInput);
                    }
                }

                // The six prefix parameters are bound explicitly; only owner-controlled columns enter SQL.
                let mut sql = QueryBuilder::<Postgres>::with_arguments(
                    include_str!("account-directory.sql"),
                    {
                        use sqlx::Arguments;
                        let mut args = sqlx::postgres::PgArguments::default();
                        args.add(actor.key.tenant.to_string())
                            .map_err(|_| corrupt())?;
                        args.add(query.source().map(str::to_owned))
                            .map_err(|_| corrupt())?;
                        args.add(window.now).map_err(|_| corrupt())?;
                        args.add(query.needs_profiles()).map_err(|_| corrupt())?;
                        args.add(query.needs_departments()).map_err(|_| corrupt())?;
                        args.add(i64::from(max_age)).map_err(|_| corrupt())?;
                        args
                    },
                );
                sql.push("SELECT to_jsonb(r) FROM account_rows r WHERE ");
                if let Some(expression) = query.filter() {
                    filter(&mut sql, expression);
                } else {
                    sql.push("true");
                }
                if let Some(seek) = &seek {
                    after(&mut sql, &query, &seek.position);
                }
                sql.push(" ORDER BY ");
                for (index, sort) in query.sort().iter().enumerate() {
                    if index > 0 {
                        sql.push(",");
                    }
                    sql.push(column(sort.field)).push(if sort.descending {
                        " DESC NULLS LAST"
                    } else {
                        " ASC NULLS LAST"
                    });
                }
                sql.push(" LIMIT ").push_bind(i64::from(query.limit()) + 1);
                let values: Vec<Value> = sql.build_query_scalar().fetch_all(&mut *c).await?;
                let more = values.len() > usize::from(query.limit());
                let values: Vec<_> = values
                    .into_iter()
                    .take(usize::from(query.limit()))
                    .collect();
                let next_cursor = if more {
                    let last = values.last().ok_or_else(corrupt)?;
                    Some(encode(
                        &key,
                        &Cursor {
                            binding,
                            expires: window.valid_until,
                            position: query
                                .sort()
                                .iter()
                                .map(|s| last[s.field.name()].clone())
                                .collect(),
                        },
                    )?)
                } else {
                    None
                };
                let accounts = values
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| corrupt())?;
                if std::time::Instant::now() >= window.expires {
                    return Err(reject().into());
                }
                Ok(AccountPage {
                    accounts,
                    fields: query.fields().to_vec(),
                    next_cursor,
                })
            })
        })
        .await
    }
}
