use std::{env, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::{server::DocmostMcpServer, types::StartupConfig};

const MIN_BEARER_TOKEN_BYTES: usize = 32;

fn validate_bearer_token(token: &str) -> Result<()> {
    if token.len() < MIN_BEARER_TOKEN_BYTES {
        bail!(
            "DOCMOST_MCP_BEARER_TOKEN must be at least {MIN_BEARER_TOKEN_BYTES} bytes; generate one with `openssl rand -hex 32`"
        );
    }

    let normalized = token.trim().to_ascii_lowercase();
    if normalized.contains("replace-with")
        || normalized.contains("change-me")
        || normalized.contains("changeme")
    {
        bail!(
            "DOCMOST_MCP_BEARER_TOKEN still contains an example value; generate one with `openssl rand -hex 32`"
        );
    }

    Ok(())
}

#[derive(Clone)]
struct AuthState {
    token: Arc<[u8]>,
}

#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    pub bind: SocketAddr,
    pub bearer_token: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
}

impl HttpServerConfig {
    pub fn from_env_and_bind(bind: &str) -> Result<Self> {
        let bind: SocketAddr = bind
            .parse()
            .with_context(|| format!("DOCMOST_MCP_BIND is not a valid socket address: {bind}"))?;
        let bearer_token = env::var("DOCMOST_MCP_BEARER_TOKEN")
            .context("DOCMOST_MCP_BEARER_TOKEN is required for HTTP transport")?;
        validate_bearer_token(&bearer_token)?;

        let default_hosts = match bind.ip() {
            address if address.is_loopback() => vec![
                format!("localhost:{}", bind.port()),
                format!("127.0.0.1:{}", bind.port()),
                format!("[::1]:{}", bind.port()),
            ],
            address => vec![format!("{address}:{}", bind.port())],
        };
        let allowed_hosts =
            comma_separated_env("DOCMOST_MCP_ALLOWED_HOSTS").unwrap_or(default_hosts);
        let allowed_origins =
            comma_separated_env("DOCMOST_MCP_ALLOWED_ORIGINS").unwrap_or_else(|| {
                vec![
                    format!("http://localhost:{}", bind.port()),
                    format!("http://127.0.0.1:{}", bind.port()),
                ]
            });

        if allowed_hosts.is_empty() {
            bail!("DOCMOST_MCP_ALLOWED_HOSTS must contain at least one host");
        }
        if allowed_origins.is_empty() {
            bail!("DOCMOST_MCP_ALLOWED_ORIGINS must contain at least one origin");
        }

        Ok(Self {
            bind,
            bearer_token,
            allowed_hosts,
            allowed_origins,
        })
    }
}

fn comma_separated_env(name: &str) -> Option<Vec<String>> {
    env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

pub async fn serve_http(startup_config: StartupConfig, config: HttpServerConfig) -> Result<()> {
    let bind = config.bind;
    let app = build_router(startup_config, config);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("Failed to bind Docmost MCP HTTP server to {bind}"))?;
    let actual_bind = listener.local_addr().unwrap_or(bind);
    tracing::info!(%actual_bind, endpoint = %format!("http://{actual_bind}/mcp"), "Docmost MCP HTTP server listening");
    axum::serve(listener, app)
        .await
        .context("Docmost MCP HTTP server stopped unexpectedly")
}

fn build_router(startup_config: StartupConfig, config: HttpServerConfig) -> Router {
    let mcp_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(config.allowed_hosts)
        .with_allowed_origins(config.allowed_origins);
    let service = StreamableHttpService::new(
        move || DocmostMcpServer::new(startup_config.clone()).map_err(std::io::Error::other),
        LocalSessionManager::default().into(),
        mcp_config,
    );

    let protected_mcp =
        Router::new()
            .nest_service("/mcp", service)
            .route_layer(middleware::from_fn_with_state(
                AuthState {
                    token: Arc::from(config.bearer_token.into_bytes()),
                },
                require_bearer,
            ));
    Router::new()
        .route("/health", get(health))
        .merge(protected_mcp)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "docmost-mcp" }))
}

async fn require_bearer(
    State(state): State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let authenticated = supplied.is_some_and(|value| {
        let supplied = value.as_bytes();
        supplied.len() == state.token.len() && supplied.ct_eq(state.token.as_ref()).into()
    });
    if authenticated {
        return next.run(request).await;
    }

    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid or missing bearer token" })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN};

    #[test]
    fn parses_comma_separated_values() {
        unsafe { env::set_var("DOCMOST_MCP_TEST_LIST", " a.example, b.example ") };
        assert_eq!(
            comma_separated_env("DOCMOST_MCP_TEST_LIST"),
            Some(vec!["a.example".to_string(), "b.example".to_string()])
        );
        unsafe { env::remove_var("DOCMOST_MCP_TEST_LIST") };
    }

    #[test]
    fn rejects_example_bearer_tokens_even_when_they_are_long_enough() {
        let error = validate_bearer_token("replace-with-at-least-32-random-bytes")
            .expect_err("example bearer token must be rejected");
        assert!(error.to_string().contains("example value"));
    }

    #[test]
    fn accepts_generated_length_bearer_tokens() {
        validate_bearer_token("9035bc2907f9f10ca6dcbe33a96ab7ec20ac97eb7e80cdfe771f589aa7508e86")
            .expect("random 32-byte hex token should be accepted");
    }

    #[tokio::test]
    async fn http_endpoint_requires_bearer_and_rejects_untrusted_origin() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let app = build_router(
            StartupConfig::default(),
            HttpServerConfig {
                bind: address,
                bearer_token: token.to_string(),
                allowed_hosts: vec![address.to_string()],
                allowed_origins: vec![format!("http://{address}")],
            },
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = reqwest::Client::new();
        let endpoint = format!("http://{address}/mcp");

        let unauthorized = client.post(&endpoint).send().await?;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );

        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "http-test", "version": "1.0.0" }
            }
        });
        let trusted = client
            .post(&endpoint)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, format!("http://{address}"))
            .json(&initialize)
            .send()
            .await?;
        assert!(trusted.status().is_success(), "status={}", trusted.status());

        let untrusted_origin = client
            .post(&endpoint)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header(ORIGIN, "https://attacker.example")
            .json(&initialize)
            .send()
            .await?;
        assert_eq!(untrusted_origin.status(), StatusCode::FORBIDDEN);

        task.abort();
        Ok(())
    }
}
