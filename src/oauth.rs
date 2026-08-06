use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use aes_gcm::aead::{OsRng, rand_core::RngCore};
use axum::{
    Form, Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use url::Url;

use crate::{
    auth::manager::AuthManager,
    startup_config::normalize_base_url,
    types::{AuthenticatedSession, LoginInput},
};

const AUTHORIZATION_CODE_TTL_MINUTES: i64 = 5;
const PENDING_LOGIN_TTL_MINUTES: i64 = 10;
const ACCESS_TOKEN_TTL_MINUTES: i64 = 60;
const LOGIN_FAILURE_WINDOW_MINUTES: i64 = 15;
const MAX_LOGIN_FAILURES_PER_ACCOUNT: usize = 5;
const MAX_REGISTERED_CLIENTS: usize = 1_024;
const MAX_PENDING_AUTHORIZATIONS: usize = 4_096;
const MAX_COMPLETED_AUTHORIZATIONS: usize = 4_096;
const MAX_ACCESS_GRANTS: usize = 8_192;
const MAX_REFRESH_GRANTS: usize = 4_096;
const DEFAULT_SCOPE: &str = "docmost";
/// Product name on the sign-in pages when the operator sets no `DOCMOST_MCP_BRAND`.
pub const DEFAULT_BRAND: &str = "Docmost";
const MAX_BRAND_LENGTH: usize = 60;
/// Shown in place of a client's name when it registered without one. The pages
/// must never name a specific MCP client: Claude Code, Claude Desktop, Codex and
/// Cursor all speak this protocol, and the user is looking at whichever they used.
const UNNAMED_CLIENT: &str = "your MCP client";

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub public_url: String,
    pub docmost_base_url: String,
    /// Product name shown on the sign-in and authorized pages. Deployments that
    /// rebrand Docmost set `DOCMOST_MCP_BRAND`; everyone else gets `DEFAULT_BRAND`.
    pub brand: String,
}

#[derive(Clone)]
pub struct OAuthState {
    inner: Arc<OAuthInner>,
}

struct OAuthInner {
    public_url: String,
    resource_url: String,
    docmost_base_url: String,
    brand: String,
    clients: RwLock<HashMap<String, RegisteredClient>>,
    pending: RwLock<HashMap<String, PendingAuthorization>>,
    completed: RwLock<HashMap<String, CompletedAuthorization>>,
    codes: RwLock<HashMap<String, AuthorizationCode>>,
    access_tokens: RwLock<HashMap<String, AccessGrant>>,
    refresh_tokens: RwLock<HashMap<String, RefreshGrant>>,
    login_failures: RwLock<HashMap<String, Vec<DateTime<Utc>>>>,
}

#[derive(Clone)]
struct RegisteredClient {
    redirect_uris: Vec<String>,
    /// Self-declared at registration, so it is untrusted input and is always
    /// escaped before it reaches a page.
    client_name: Option<String>,
}

#[derive(Clone)]
struct PendingAuthorization {
    client_id: String,
    client_name: Option<String>,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    scope: String,
    csrf_hash: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct CompletedAuthorization {
    location: String,
    /// Carried so a refreshed browser replays the same page it saw the first
    /// time, naming the same client.
    client_name: Option<String>,
    expires_at: DateTime<Utc>,
}

struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scope: String,
    session: AuthenticatedSession,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct AccessGrant {
    session: AuthenticatedSession,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct RefreshGrant {
    client_id: String,
    scope: String,
    session: AuthenticatedSession,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegistrationResponse {
    client_id: String,
    client_id_issued_at: i64,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    request_id: String,
    csrf: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

impl OAuthState {
    pub fn new(config: OAuthConfig) -> anyhow::Result<Self> {
        let public_url = normalize_public_url(&config.public_url)?;
        Ok(Self {
            inner: Arc::new(OAuthInner {
                resource_url: format!("{public_url}/mcp"),
                public_url,
                docmost_base_url: normalize_base_url(&config.docmost_base_url),
                brand: normalize_brand(&config.brand),
                clients: RwLock::new(HashMap::new()),
                pending: RwLock::new(HashMap::new()),
                completed: RwLock::new(HashMap::new()),
                codes: RwLock::new(HashMap::new()),
                access_tokens: RwLock::new(HashMap::new()),
                refresh_tokens: RwLock::new(HashMap::new()),
                login_failures: RwLock::new(HashMap::new()),
            }),
        })
    }

    pub fn routes(self) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(authorization_server_metadata),
            )
            .route(
                "/.well-known/openid-configuration",
                get(authorization_server_metadata),
            )
            .route("/oauth/register", post(register_client))
            .route(
                "/oauth/authorize",
                get(authorize).post(complete_authorization),
            )
            .route("/oauth/token", post(exchange_token))
            .layer(DefaultBodyLimit::max(16 * 1_024))
            .with_state(self)
    }

    pub fn resource_metadata_url(&self) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource",
            self.inner.public_url
        )
    }

    pub async fn access_session(&self, token: &str) -> Option<AuthenticatedSession> {
        let key = token_hash(token);
        let grant = self.inner.access_tokens.read().await.get(&key).cloned();
        match grant {
            Some(grant) if grant.expires_at > Utc::now() => Some(grant.session),
            Some(_) => {
                self.inner.access_tokens.write().await.remove(&key);
                None
            }
            None => None,
        }
    }

    pub fn session_fingerprint(session: &AuthenticatedSession) -> String {
        token_hash(&session.token)
    }

    pub async fn active_session_fingerprints(&self) -> HashSet<String> {
        cleanup_expired(self).await;
        let mut active = HashSet::new();
        active.extend(
            self.inner
                .access_tokens
                .read()
                .await
                .values()
                .map(|grant| Self::session_fingerprint(&grant.session)),
        );
        active.extend(
            self.inner
                .refresh_tokens
                .read()
                .await
                .values()
                .map(|grant| Self::session_fingerprint(&grant.session)),
        );
        active
    }
}

async fn protected_resource_metadata(State(state): State<OAuthState>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": state.inner.resource_url,
        "authorization_servers": [state.inner.public_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [DEFAULT_SCOPE]
    }))
}

async fn authorization_server_metadata(State(state): State<OAuthState>) -> Json<serde_json::Value> {
    let base = &state.inner.public_url;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [DEFAULT_SCOPE]
    }))
}

async fn register_client(
    State(state): State<OAuthState>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    if request.redirect_uris.is_empty()
        || request.redirect_uris.len() > 10
        || request
            .redirect_uris
            .iter()
            .any(|uri| uri.len() > 2_048 || !valid_redirect_uri(uri))
        || request
            .client_name
            .as_deref()
            .is_some_and(|name| name.len() > 200)
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "Every redirect URI must be HTTPS, or loopback HTTP for a native client.",
        );
    }

    let mut clients = state.inner.clients.write().await;
    if clients.len() >= MAX_REGISTERED_CLIENTS {
        return oauth_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Client registration capacity is temporarily exhausted.",
        );
    }

    let client_id = random_token(24);
    let issued_at = Utc::now().timestamp();
    let client = RegisteredClient {
        redirect_uris: request.redirect_uris.clone(),
        client_name: request
            .client_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string),
    };
    clients.insert(client_id.clone(), client);
    drop(clients);

    (
        StatusCode::CREATED,
        Json(RegistrationResponse {
            client_id,
            client_id_issued_at: issued_at,
            redirect_uris: request.redirect_uris,
            token_endpoint_auth_method: "none",
            client_name: request.client_name,
        }),
    )
        .into_response()
}

async fn authorize(
    State(state): State<OAuthState>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let pending = match validate_authorize_request(&state, query).await {
        Ok(pending) => pending,
        Err(response) => return response,
    };

    cleanup_expired(&state).await;
    if state.inner.pending.read().await.len() >= MAX_PENDING_AUTHORIZATIONS
        || state.inner.completed.read().await.len() >= MAX_COMPLETED_AUTHORIZATIONS
    {
        return oauth_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Authorization capacity is temporarily exhausted.",
        );
    }

    let request_id = random_token(24);
    let csrf = random_token(24);
    let mut pending = pending;
    pending.csrf_hash = token_hash(&csrf);
    state
        .inner
        .pending
        .write()
        .await
        .insert(request_id.clone(), pending);

    let html = render_login_page(&request_id, &csrf, None, &state.inner.brand);
    let cookie = format!(
        "mcp_auth_csrf={csrf}; Path=/oauth/authorize; Max-Age=600; HttpOnly; Secure; SameSite=Strict"
    );
    let mut response = hardened_auth_response(Html(html).into_response());
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated cookie is valid"),
    );
    response
}

async fn complete_authorization(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let pending = state
        .inner
        .pending
        .read()
        .await
        .get(&form.request_id)
        .cloned();
    let Some(pending) = pending else {
        let completed = state
            .inner
            .completed
            .read()
            .await
            .get(&form.request_id)
            .cloned();
        if let Some(completed) = completed.filter(|grant| grant.expires_at > Utc::now()) {
            return authorization_response(
                &completed.location,
                &state.inner.brand,
                completed.client_name.as_deref(),
            );
        }
        return oauth_html_error(
            StatusCode::BAD_REQUEST,
            "This login request is no longer valid.",
        );
    };
    if pending.expires_at <= Utc::now() {
        state.inner.pending.write().await.remove(&form.request_id);
        return oauth_html_error(StatusCode::BAD_REQUEST, "This login request has expired.");
    }

    let cookie_csrf = cookie_value(&headers, "mcp_auth_csrf");
    let csrf_matches = cookie_csrf.as_deref().is_some_and(|cookie| {
        constant_time_equal(&token_hash(cookie), &pending.csrf_hash)
            && constant_time_equal(&token_hash(&form.csrf), &pending.csrf_hash)
    });
    if !csrf_matches {
        return oauth_html_error(StatusCode::BAD_REQUEST, "Login security check failed.");
    }

    let normalized_email = form.email.trim().to_ascii_lowercase();
    if normalized_email.is_empty()
        || normalized_email.len() > 320
        || form.password.is_empty()
        || form.password.len() > 1_024
    {
        return oauth_html_error(StatusCode::BAD_REQUEST, "Email or password is invalid.");
    }
    if login_is_rate_limited(&state, &normalized_email).await {
        return oauth_html_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed sign-in attempts. Try again in 15 minutes.",
        );
    }

    let session = match AuthManager::authenticate_once(LoginInput {
        base_url: state.inner.docmost_base_url.clone(),
        email: normalized_email.clone(),
        password: form.password,
    })
    .await
    {
        Ok(session) => session,
        Err(_) => {
            record_login_failure(&state, &normalized_email).await;
            return hardened_auth_response(
                (
                    StatusCode::UNAUTHORIZED,
                    Html(render_login_page(
                        &form.request_id,
                        &form.csrf,
                        Some("Email or password was not accepted by Docmost."),
                        &state.inner.brand,
                    )),
                )
                    .into_response(),
            );
        }
    };
    clear_login_failures(&state, &normalized_email).await;

    let code = random_token(32);
    let mut redirect = match Url::parse(&pending.redirect_uri) {
        Ok(url) => url,
        Err(_) => return oauth_html_error(StatusCode::BAD_REQUEST, "Invalid redirect URI."),
    };
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("code", &code);
        if let Some(state_value) = pending.state {
            pairs.append_pair("state", &state_value);
        }
    }
    let location = redirect.to_string();
    let expires_at = Utc::now() + Duration::minutes(AUTHORIZATION_CODE_TTL_MINUTES);
    state.inner.codes.write().await.insert(
        token_hash(&code),
        AuthorizationCode {
            client_id: pending.client_id,
            redirect_uri: pending.redirect_uri,
            code_challenge: pending.code_challenge,
            scope: pending.scope,
            session,
            expires_at,
        },
    );
    state.inner.completed.write().await.insert(
        form.request_id.clone(),
        CompletedAuthorization {
            location: location.clone(),
            client_name: pending.client_name.clone(),
            expires_at,
        },
    );
    state.inner.pending.write().await.remove(&form.request_id);

    authorization_response(
        &location,
        &state.inner.brand,
        pending.client_name.as_deref(),
    )
}

fn authorization_response(location: &str, brand: &str, client_name: Option<&str>) -> Response {
    let uses_loopback_callback = Url::parse(location)
        .is_ok_and(|url| url.scheme() == "http" && is_loopback_host(url.host_str()));
    if uses_loopback_callback {
        return authorization_loopback_bridge(location, brand, client_name);
    }

    let mut response = Redirect::to(location).into_response();
    clear_csrf_cookie(&mut response);
    response
}

fn authorization_loopback_bridge(
    location: &str,
    brand: &str,
    client_name: Option<&str>,
) -> Response {
    let escaped_location = escape_html(location);
    let brand = escape_html(brand);
    let client = display_client_name(client_name);
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{brand} authorized</title>
<style>
body{{font-family:system-ui,sans-serif;background:#f5f6f8;margin:0;display:grid;place-items:center;min-height:100vh;color:#17202a}}
main{{width:min(420px,calc(100% - 40px));background:white;padding:32px;border-radius:14px;box-shadow:0 10px 30px #0002}}
h1{{font-size:1.35rem;margin:0 0 8px}}p{{color:#59636e;line-height:1.5}}
a{{box-sizing:border-box;display:block;width:100%;margin-top:24px;padding:12px;border-radius:8px;background:#202938;color:white;text-align:center;text-decoration:none;font-weight:700}}
small{{display:block;margin-top:16px;color:#697482;line-height:1.45}}
</style></head><body><main><h1>{brand} authorized</h1>
<p>Your {brand} account was accepted. Continue to {client} to finish connecting the MCP.</p>
<a id="continue-to-client" href="{escaped_location}">Continue to {client}</a>
<small>Browsers may block automatic navigation from a public site to localhost. This explicit button keeps the callback secure and reliable.</small>
</main></body></html>"#
    );
    let mut response = hardened_auth_response(Html(html).into_response());
    clear_csrf_cookie(&mut response);
    response
}

fn clear_csrf_cookie(response: &mut Response) {
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "mcp_auth_csrf=; Path=/oauth/authorize; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
        ),
    );
}

async fn exchange_token(State(state): State<OAuthState>, Form(form): Form<TokenForm>) -> Response {
    if form
        .resource
        .as_deref()
        .is_some_and(|resource| resource != state.inner.resource_url)
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "The requested resource is not this MCP server.",
        );
    }

    match form.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&state, form).await,
        "refresh_token" => exchange_refresh_token(&state, form).await,
        _ => oauth_json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Supported grants are authorization_code and refresh_token.",
        ),
    }
}

async fn exchange_authorization_code(state: &OAuthState, form: TokenForm) -> Response {
    let Some(code) = form.code else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required.",
        );
    };
    let Some(client_id) = form.client_id else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required.",
        );
    };
    let Some(redirect_uri) = form.redirect_uri else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required.",
        );
    };
    let Some(verifier) = form.code_verifier else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_verifier is required.",
        );
    };
    if !valid_pkce_value(&verifier, 43, 128) {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code_verifier must contain 43 to 128 unreserved characters.",
        );
    }

    let grant = state.inner.codes.write().await.remove(&token_hash(&code));
    let Some(grant) = grant else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code is invalid or was already used.",
        );
    };
    if grant.expires_at <= Utc::now()
        || grant.client_id != client_id
        || grant.redirect_uri != redirect_uri
        || !constant_time_equal(&pkce_challenge(&verifier), &grant.code_challenge)
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code validation failed.",
        );
    }

    issue_tokens(state, grant.client_id, grant.scope, grant.session, true).await
}

async fn exchange_refresh_token(state: &OAuthState, form: TokenForm) -> Response {
    let Some(refresh_token) = form.refresh_token else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required.",
        );
    };
    let grant = state
        .inner
        .refresh_tokens
        .write()
        .await
        .remove(&token_hash(&refresh_token));
    let Some(grant) = grant else {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token is invalid.",
        );
    };
    if grant.expires_at <= Utc::now()
        || form
            .client_id
            .as_deref()
            .is_some_and(|client_id| client_id != grant.client_id)
    {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Docmost session expired; sign in again.",
        );
    }

    issue_tokens(state, grant.client_id, grant.scope, grant.session, true).await
}

async fn issue_tokens(
    state: &OAuthState,
    client_id: String,
    scope: String,
    session: AuthenticatedSession,
    include_refresh: bool,
) -> Response {
    cleanup_expired(state).await;
    if state.inner.access_tokens.read().await.len() >= MAX_ACCESS_GRANTS
        || (include_refresh && state.inner.refresh_tokens.read().await.len() >= MAX_REFRESH_GRANTS)
    {
        return oauth_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Authorization grant capacity is temporarily exhausted.",
        );
    }

    let now = Utc::now();
    let docmost_expiry = session
        .expires_at
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let access_expiry = docmost_expiry
        .map(|expiry| expiry.min(now + Duration::minutes(ACCESS_TOKEN_TTL_MINUTES)))
        .unwrap_or(now + Duration::minutes(ACCESS_TOKEN_TTL_MINUTES));
    if access_expiry <= now + Duration::seconds(30) {
        return oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Docmost session is already expired; sign in again.",
        );
    }

    let access_token = random_token(32);
    state.inner.access_tokens.write().await.insert(
        token_hash(&access_token),
        AccessGrant {
            session: session.clone(),
            expires_at: access_expiry,
        },
    );

    let refresh_token = if include_refresh {
        let token = random_token(32);
        state.inner.refresh_tokens.write().await.insert(
            token_hash(&token),
            RefreshGrant {
                client_id,
                scope: scope.clone(),
                session,
                expires_at: docmost_expiry.unwrap_or(access_expiry),
            },
        );
        Some(token)
    } else {
        None
    };

    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: (access_expiry - now).num_seconds(),
        scope,
        refresh_token,
    })
    .into_response()
}

async fn validate_authorize_request(
    state: &OAuthState,
    query: AuthorizeQuery,
) -> Result<PendingAuthorization, Response> {
    if query.response_type != "code" {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "Only authorization code flow is supported.",
        ));
    }
    if query.code_challenge_method.as_deref() != Some("S256") {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "PKCE with code_challenge_method=S256 is required.",
        ));
    }
    let Some(code_challenge) = query.code_challenge else {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge is required.",
        ));
    };
    if code_challenge.len() != 43
        || !code_challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge must be a 43-character base64url SHA-256 value.",
        ));
    }
    if query
        .resource
        .as_deref()
        .is_some_and(|resource| resource != state.inner.resource_url)
    {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "The requested resource is not this MCP server.",
        ));
    }
    let scope = query.scope.unwrap_or_else(|| DEFAULT_SCOPE.to_string());
    if scope.split_whitespace().any(|value| value != DEFAULT_SCOPE)
        || !scope.split_whitespace().any(|value| value == DEFAULT_SCOPE)
    {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "The only supported scope is docmost.",
        ));
    }

    let clients = state.inner.clients.read().await;
    let Some(client) = clients.get(&query.client_id) else {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Register this MCP client before authorizing.",
        ));
    };
    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(oauth_json_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri is not registered for this client.",
        ));
    }

    let client_name = client.client_name.clone();

    Ok(PendingAuthorization {
        client_id: query.client_id,
        client_name,
        redirect_uri: query.redirect_uri,
        state: query.state,
        code_challenge,
        scope,
        csrf_hash: String::new(),
        expires_at: Utc::now() + Duration::minutes(PENDING_LOGIN_TTL_MINUTES),
    })
}

fn render_login_page(request_id: &str, csrf: &str, error: Option<&str>, brand: &str) -> String {
    let error = error
        .map(|message| format!("<p class=\"error\">{}</p>", escape_html(message)))
        .unwrap_or_default();
    let brand = escape_html(brand);
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to {brand} MCP</title>
<style>
body{{font-family:system-ui,sans-serif;background:#f5f6f8;margin:0;display:grid;place-items:center;min-height:100vh;color:#17202a}}
main{{width:min(420px,calc(100% - 40px));background:white;padding:32px;border-radius:14px;box-shadow:0 10px 30px #0002}}
h1{{font-size:1.35rem;margin:0 0 8px}}p{{color:#59636e}}label{{display:block;font-weight:600;margin-top:18px}}
input{{box-sizing:border-box;width:100%;margin-top:7px;padding:11px 12px;border:1px solid #c9ced6;border-radius:8px;font:inherit}}
button{{width:100%;margin-top:24px;padding:12px;border:0;border-radius:8px;background:#202938;color:white;font:inherit;font-weight:700;cursor:pointer}}
.error{{color:#b42318;background:#fef3f2;padding:10px;border-radius:8px}}small{{display:block;margin-top:16px;color:#697482;line-height:1.45}}
</style></head><body><main><h1>Sign in to {brand} MCP</h1>
<p>Use your {brand} account. The MCP relays this login to {brand} over HTTPS and never stores your password.</p>
{error}<form method="post" action="/oauth/authorize">
<input type="hidden" name="request_id" value="{}"><input type="hidden" name="csrf" value="{}">
<label>Email<input name="email" type="email" autocomplete="username" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in and authorize</button></form>
<small>The MCP receives a time-limited Docmost session with the same spaces and permissions as your account.</small>
</main></body></html>"#,
        escape_html(request_id),
        escape_html(csrf)
    )
}

fn oauth_json_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}

fn oauth_html_error(status: StatusCode, message: &str) -> Response {
    hardened_auth_response((
        status,
        Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Authorization failed</title><h1>Authorization failed</h1><p>{}</p>",
            escape_html(message)
        )),
    )
        .into_response())
}

fn hardened_auth_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

fn normalize_public_url(value: &str) -> anyhow::Result<String> {
    let parsed = Url::parse(value)?;
    if parsed.scheme() != "https" && !is_loopback_host(parsed.host_str()) {
        anyhow::bail!("DOCMOST_MCP_PUBLIC_URL must use HTTPS outside localhost");
    }
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!(
            "DOCMOST_MCP_PUBLIC_URL must be an origin without credentials, path, query, or fragment"
        );
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn valid_redirect_uri(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.fragment().is_none()
            && (url.scheme() == "https"
                || (url.scheme() == "http" && is_loopback_host(url.host_str())))
    })
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn valid_pkce_value(value: &str, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && left.as_bytes().ct_eq(right.as_bytes()).into()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (key, value) = cookie.trim().split_once('=')?;
                (key == name).then(|| value.to_string())
            })
        })
}

async fn cleanup_expired(state: &OAuthState) {
    let now = Utc::now();
    state
        .inner
        .pending
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .completed
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .codes
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .access_tokens
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    state
        .inner
        .refresh_tokens
        .write()
        .await
        .retain(|_, grant| grant.expires_at > now);
    let window_start = now - Duration::minutes(LOGIN_FAILURE_WINDOW_MINUTES);
    state
        .inner
        .login_failures
        .write()
        .await
        .retain(|_, attempts| {
            attempts.retain(|attempt| *attempt > window_start);
            !attempts.is_empty()
        });
}

async fn login_is_rate_limited(state: &OAuthState, email: &str) -> bool {
    cleanup_expired(state).await;
    state
        .inner
        .login_failures
        .read()
        .await
        .get(&token_hash(email))
        .is_some_and(|attempts| attempts.len() >= MAX_LOGIN_FAILURES_PER_ACCOUNT)
}

async fn record_login_failure(state: &OAuthState, email: &str) {
    state
        .inner
        .login_failures
        .write()
        .await
        .entry(token_hash(email))
        .or_default()
        .push(Utc::now());
}

async fn clear_login_failures(state: &OAuthState, email: &str) {
    state
        .inner
        .login_failures
        .write()
        .await
        .remove(&token_hash(email));
}

/// Trim an operator-supplied brand down to something safe to render, falling back
/// to `DEFAULT_BRAND` when it is blank. Length is capped so a stray value cannot
/// blow out the page title.
fn normalize_brand(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return DEFAULT_BRAND.to_string();
    }
    trimmed.chars().take(MAX_BRAND_LENGTH).collect()
}

/// Render a registered client's name for display, escaped.
///
/// Any client can register with any `client_name`, so this string is attacker
/// controlled and must never reach a page unescaped.
fn display_client_name(client_name: Option<&str>) -> String {
    client_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(escape_html)
        .unwrap_or_else(|| UNNAMED_CLIENT.to_string())
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, http::header::SET_COOKIE, routing::post};
    use reqwest::{Client, redirect::Policy};
    use serde::Deserialize;
    use tokio::net::TcpListener;

    #[derive(Deserialize)]
    struct TestRegistrationResponse {
        client_id: String,
    }

    #[derive(Deserialize)]
    struct TestTokenResponse {
        access_token: String,
    }

    #[test]
    fn pkce_matches_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn only_https_or_loopback_redirects_are_allowed() {
        assert!(valid_redirect_uri("https://client.example/callback"));
        assert!(valid_redirect_uri("http://127.0.0.1:43210/callback"));
        assert!(!valid_redirect_uri("http://client.example/callback"));
        assert!(!valid_redirect_uri("javascript:alert(1)"));
    }

    #[test]
    fn public_url_requires_https_outside_loopback() {
        assert!(normalize_public_url("https://mcp.example").is_ok());
        assert!(normalize_public_url("http://localhost:8787").is_ok());
        assert!(normalize_public_url("http://mcp.example").is_err());
        assert!(normalize_public_url("https://mcp.example/path").is_err());
        assert!(normalize_public_url("https://user@mcp.example").is_err());
    }

    #[test]
    fn brand_falls_back_to_docmost_and_is_bounded() {
        assert_eq!(normalize_brand(""), DEFAULT_BRAND);
        assert_eq!(normalize_brand("   "), DEFAULT_BRAND);
        assert_eq!(normalize_brand("  PREP Docs  "), "PREP Docs");
        assert_eq!(
            normalize_brand(&"x".repeat(500)).chars().count(),
            MAX_BRAND_LENGTH
        );
    }

    #[test]
    fn unnamed_clients_get_a_generic_label() {
        // The pages must never hardcode one client's name: this server is used from
        // Claude Code, Claude Desktop, Codex and Cursor alike.
        assert_eq!(display_client_name(None), UNNAMED_CLIENT);
        assert_eq!(display_client_name(Some("   ")), UNNAMED_CLIENT);
        assert_eq!(display_client_name(Some("Cursor")), "Cursor");
    }

    #[test]
    fn client_name_is_escaped_before_it_reaches_a_page() {
        // client_name is self-declared at registration, so any client can supply
        // markup. It lands in both the heading and the button label.
        let displayed = display_client_name(Some("<script>alert(1)</script>"));
        assert!(!displayed.contains('<'), "unescaped markup: {displayed}");
        assert_eq!(displayed, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn login_page_shows_the_configured_brand_and_no_vendor_name() {
        let page = render_login_page("request-1", "csrf-1", None, "PREP Docs");
        assert!(page.contains("Sign in to PREP Docs MCP"));
        assert!(page.contains("Use your PREP Docs account"));
        assert!(!page.contains("Codex"), "no client should be named here");
    }

    #[tokio::test]
    async fn repeated_login_failures_lock_one_account_without_touching_others() {
        let state = OAuthState::new(OAuthConfig {
            public_url: "http://localhost:8787".to_string(),
            docmost_base_url: "http://localhost:3000".to_string(),
            brand: DEFAULT_BRAND.to_string(),
        })
        .expect("state builds");

        for _ in 0..MAX_LOGIN_FAILURES_PER_ACCOUNT {
            record_login_failure(&state, "victim@example.com").await;
        }

        assert!(login_is_rate_limited(&state, "victim@example.com").await);
        // Lockout is per account, so one user cannot lock another out.
        assert!(!login_is_rate_limited(&state, "bystander@example.com").await);

        clear_login_failures(&state, "victim@example.com").await;
        assert!(!login_is_rate_limited(&state, "victim@example.com").await);
    }

    #[tokio::test]
    async fn oauth_tokens_are_bound_to_separate_docmost_accounts() -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct MockLogin {
            email: String,
        }

        async fn mock_login(Json(login): Json<MockLogin>) -> Response {
            let payload = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "exp": (Utc::now() + Duration::hours(2)).timestamp(),
                    "email": login.email
                }))
                .expect("payload serializes"),
            );
            let token = format!("header.{payload}.signature");
            let mut response = Json(json!({ "ok": true })).into_response();
            response.headers_mut().insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!("authToken={token}; Path=/; HttpOnly"))
                    .expect("cookie is valid"),
            );
            response
        }

        let docmost_listener = TcpListener::bind("127.0.0.1:0").await?;
        let docmost_address = docmost_listener.local_addr()?;
        let docmost_task = tokio::spawn(async move {
            let app = Router::new().route("/api/auth/login", post(mock_login));
            let _ = axum::serve(docmost_listener, app).await;
        });

        let oauth_listener = TcpListener::bind("127.0.0.1:0").await?;
        let oauth_address = oauth_listener.local_addr()?;
        let oauth_state = OAuthState::new(OAuthConfig {
            public_url: format!("http://{oauth_address}"),
            docmost_base_url: format!("http://{docmost_address}"),
            brand: DEFAULT_BRAND.to_string(),
        })?;
        let oauth_task = {
            let app = oauth_state.clone().routes();
            tokio::spawn(async move {
                let _ = axum::serve(oauth_listener, app).await;
            })
        };

        let alice =
            authenticate_test_account(&oauth_state, oauth_address, "alice@example.com").await?;
        let bob = authenticate_test_account(&oauth_state, oauth_address, "bob@example.com").await?;

        assert_ne!(alice.access_token, bob.access_token);
        assert_eq!(
            oauth_state
                .access_session(&alice.access_token)
                .await
                .expect("alice session")
                .email,
            "alice@example.com"
        );
        assert_eq!(
            oauth_state
                .access_session(&bob.access_token)
                .await
                .expect("bob session")
                .email,
            "bob@example.com"
        );

        oauth_task.abort();
        docmost_task.abort();
        Ok(())
    }

    async fn authenticate_test_account(
        state: &OAuthState,
        oauth_address: std::net::SocketAddr,
        email: &str,
    ) -> anyhow::Result<TestTokenResponse> {
        let client = Client::builder().redirect(Policy::none()).build()?;
        let base = format!("http://{oauth_address}");
        let callback = "http://127.0.0.1:49123/callback";
        let registration: TestRegistrationResponse = client
            .post(format!("{base}/oauth/register"))
            .json(&json!({
                "redirect_uris": [callback],
                "client_name": "test client"
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let verifier = random_token(32);
        let authorize = client
            .get(format!("{base}/oauth/authorize"))
            .query(&[
                ("response_type", "code"),
                ("client_id", registration.client_id.as_str()),
                ("redirect_uri", callback),
                ("state", "test-state"),
                ("code_challenge", pkce_challenge(&verifier).as_str()),
                ("code_challenge_method", "S256"),
                ("resource", state.inner.resource_url.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?;
        let cookie = authorize
            .headers()
            .get(SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .expect("CSRF cookie")
            .to_string();
        let html = authorize.text().await?;
        let request_id = hidden_value(&html, "request_id").expect("request id");
        let csrf = hidden_value(&html, "csrf").expect("csrf token");

        let login_form = [
            ("request_id", request_id.as_str()),
            ("csrf", csrf.as_str()),
            ("email", email),
            ("password", "correct-password"),
        ];
        let authorized = client
            .post(format!("{base}/oauth/authorize"))
            .header(header::COOKIE, cookie)
            .form(&login_form)
            .send()
            .await?;
        assert_eq!(authorized.status(), StatusCode::OK);
        let authorized_html = authorized.text().await?;
        // The bridge names whichever client registered, never a hardcoded one.
        assert!(authorized_html.contains("Continue to test client"));
        let location = callback_href(&authorized_html).expect("authorization callback link");

        // Browsers can submit the form twice before following the first redirect.
        // The cleared CSRF cookie means the duplicate must replay the completed
        // callback bridge rather than trying to authorize the account again.
        let duplicate = client
            .post(format!("{base}/oauth/authorize"))
            .form(&login_form)
            .send()
            .await?;
        assert_eq!(duplicate.status(), StatusCode::OK);
        let duplicate_html = duplicate.text().await?;
        assert_eq!(
            callback_href(&duplicate_html).as_deref(),
            Some(location.as_str())
        );

        let redirect = Url::parse(&location)?;
        let code = redirect
            .query_pairs()
            .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
            .expect("authorization code");

        Ok(client
            .post(format!("{base}/oauth/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", registration.client_id.as_str()),
                ("redirect_uri", callback),
                ("code_verifier", verifier.as_str()),
                ("resource", state.inner.resource_url.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn hidden_value(html: &str, name: &str) -> Option<String> {
        let marker = format!("name=\"{name}\" value=\"");
        let remainder = html.split_once(&marker)?.1;
        Some(remainder.split_once('"')?.0.to_string())
    }

    fn callback_href(html: &str) -> Option<String> {
        let marker = "id=\"continue-to-client\" href=\"";
        let remainder = html.split_once(marker)?.1;
        Some(remainder.split_once('"')?.0.replace("&amp;", "&"))
    }
}
