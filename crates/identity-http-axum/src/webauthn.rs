//! Same-origin self-service ceremonies. Host operation contexts enter through typed extensions.
use crate::{boundary::*, *};
use axum::{
    Extension, Json,
    extract::{Path, Request, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use rss_identity_core::step_up::StepUpContext;
use rss_identity_postgres::{AuthenticatedSession, RegistrationAuthorization, WebauthnAuthority};
use serde::Deserialize;
use uuid::Uuid;
const GRANT_COOKIE: &str = "__Host-identity-operation";
#[derive(Clone)]
struct StateData {
    webauthn: WebauthnAuthority,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Operation {
    Register,
    Remove { credential: Uuid },
    Recover,
    Host,
}
impl Operation {
    pub(crate) fn context(
        &self,
        actor: &AuthenticatedSession,
        host: Option<StepUpContext>,
    ) -> Result<StepUpContext, HttpError> {
        let (op, credential) = match self {
            Self::Register => ("register", None),
            Self::Remove { credential } => ("remove", Some(*credential)),
            Self::Recover => ("recover", None),
            Self::Host => return host.ok_or(BAD),
        };
        rss_identity_postgres::webauthn_management_context(actor.account(), op, credential)
            .map_err(Into::into)
    }
}
pub fn webauthn_router(
    webauthn: WebauthnAuthority,
    config: HttpConfig,
) -> Result<Router, AuthorityError> {
    let local = AppState {
        authority: webauthn.authority(),
        config,
    };
    Ok(crate::mount(
        Router::new()
            .route(
                "/tenants/{tenant}/webauthn/operation/cancel",
                post(cancel_operation),
            )
            .route("/tenants/{tenant}/webauthn/credentials", get(list))
            .route(
                "/tenants/{tenant}/webauthn/register/begin",
                post(register_begin),
            )
            .route(
                "/tenants/{tenant}/webauthn/register/finish",
                post(register_finish),
            )
            .route(
                "/tenants/{tenant}/webauthn/authenticate/begin",
                post(auth_begin),
            )
            .route(
                "/tenants/{tenant}/webauthn/authenticate/finish",
                post(auth_finish),
            )
            .route(
                "/tenants/{tenant}/webauthn/credentials/{credential}/remove",
                post(remove),
            )
            .route("/tenants/{tenant}/webauthn/{ceremony}/cancel", post(cancel))
            .layer(axum::extract::DefaultBodyLimit::max(65536))
            .route_layer(middleware::from_fn_with_state(
                local,
                boundary::request_boundary,
            ))
            .with_state(StateData { webauthn }),
    ))
}
async fn actor(
    s: &StateData,
    t: &str,
    h: &HeaderMap,
    b: RequestBudget,
    write: bool,
) -> Result<AuthenticatedSession, HttpError> {
    let secret = cookie(h)?.ok_or(UNAUTH)?;
    if write {
        if unique(h, "x-identity-request")? != Some("1") {
            return Err(BAD);
        }
        csrf(h, &secret)?;
    }
    s.webauthn
        .authority()
        .inspect_session(tenant(t)?, secret, b.remaining())
        .await
        .map_err(Into::into)
}
async fn body<T: serde::de::DeserializeOwned>(
    request: Request,
    b: RequestBudget,
) -> Result<T, HttpError> {
    let bytes =
        tokio::time::timeout_at(b.cutoff(), axum::body::to_bytes(request.into_body(), 65536))
            .await
            .map_err(|_| HttpError::request_timeout())?
            .map_err(|_| BAD)?;
    serde_json::from_slice(&bytes).map_err(|_| BAD)
}
pub(crate) fn grant_cookie(grant: &rss_identity_postgres::StepUpGrant) -> String {
    format!(
        "{GRANT_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=300",
        grant.expose()
    )
}
fn grant(headers: &HeaderMap) -> Result<Option<String>, HttpError> {
    Ok(named_cookie(headers, GRANT_COOKIE)?.map(str::to_owned))
}
fn clear(mut response: Response) -> Response {
    response.headers_mut().append(
        header::SET_COOKIE,
        format!("{GRANT_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
            .parse()
            .expect("fixed cookie"),
    );
    response
}
async fn list(
    State(s): State<StateData>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, &headers, b, false).await?;
    Ok(Json(s.webauthn.list(actor, b.remaining()).await?).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    label: String,
    recover: bool,
}
async fn register_begin(
    State(s): State<StateData>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, request.headers(), b, true).await?;
    let token = grant(request.headers())?;
    let input: Register = body(request, b).await?;
    let authorization = token
        .map(RegistrationAuthorization::StepUp)
        .unwrap_or(RegistrationAuthorization::First);
    Ok(clear(
        Json(
            s.webauthn
                .begin_registration(
                    actor,
                    input.label,
                    input.recover,
                    authorization,
                    b.remaining(),
                )
                .await?,
        )
        .into_response(),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    id: Uuid,
    response: serde_json::Value,
}
async fn register_finish(
    State(s): State<StateData>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, request.headers(), b, true).await?;
    let input: Finish = body(request, b).await?;
    Ok(Json(
        s.webauthn
            .finish_registration(
                actor,
                input.id,
                serde_json::from_value(input.response).map_err(|_| BAD)?,
                b.remaining(),
            )
            .await?,
    )
    .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    operation: Operation,
}
async fn auth_begin(
    State(s): State<StateData>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, request.headers(), b, true).await?;
    let host = request.extensions().get::<StepUpContext>().cloned();
    let input: Begin = body(request, b).await?;
    let context = input.operation.context(&actor, host)?;
    Ok(Json(
        s.webauthn
            .begin_authentication(actor, context, b.remaining())
            .await?,
    )
    .into_response())
}
async fn auth_finish(
    State(s): State<StateData>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    request: Request,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, request.headers(), b, true).await?;
    let input: Finish = body(request, b).await?;
    let grant = s
        .webauthn
        .finish_authentication(
            actor,
            input.id,
            serde_json::from_value(input.response).map_err(|_| BAD)?,
            b.remaining(),
        )
        .await?;
    let mut response = Json(serde_json::json!({"expiresAt":grant.expires_at})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        grant_cookie(&grant).parse().map_err(|_| BAD)?,
    );
    Ok(response)
}
async fn remove(
    State(s): State<StateData>,
    Path((t, id)): Path<(String, Uuid)>,
    Extension(b): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, &headers, b, true).await?;
    let token = grant(&headers)?.ok_or(UNAUTH)?;
    s.webauthn.remove(actor, id, token, b.remaining()).await?;
    Ok(clear(
        Json(serde_json::json!({"removed":true})).into_response(),
    ))
}
async fn cancel(
    State(s): State<StateData>,
    Path((t, id)): Path<(String, Uuid)>,
    Extension(b): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, &headers, b, true).await?;
    s.webauthn.cancel(actor, id, b.remaining()).await?;
    Ok(Json(serde_json::json!({"cancelled":true})).into_response())
}

async fn cancel_operation(
    State(s): State<StateData>,
    Path(t): Path<String>,
    Extension(b): Extension<RequestBudget>,
    headers: HeaderMap,
) -> Result<Response, HttpError> {
    let actor = actor(&s, &t, &headers, b, true).await?;
    if let Some(handle) = grant(&headers)? {
        s.webauthn
            .authority()
            .cancel_step_up(actor, handle, b.remaining())
            .await?;
    }
    Ok(clear(
        Json(serde_json::json!({"cancelled":true})).into_response(),
    ))
}
