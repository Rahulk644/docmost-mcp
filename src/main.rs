use anyhow::Result;
use clap::Parser;
use docmost_mcp::{
    http_server::{HttpServerConfig, serve_http},
    server::DocmostMcpServer,
    startup_config::normalize_base_url,
    types::StartupConfig,
};
use rmcp::{ServiceExt, transport::io::stdio};

#[derive(Parser, Debug)]
#[command(name = "docmost-local-mcp")]
#[command(about = "Docmost MCP server for local IDE integrations")]
struct Cli {
    #[arg(long, env = "DOCMOST_BASE_URL")]
    base_url: Option<String>,
    #[arg(long, env = "DOCMOST_MCP_TRANSPORT", value_enum, default_value_t = Transport::Http)]
    transport: Transport,
    #[arg(long, env = "DOCMOST_MCP_BIND", default_value = "127.0.0.1:8787")]
    bind: String,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum Transport {
    Http,
    Stdio,
}

#[tokio::main]
async fn main() {
    if let Err(error) = try_main().await {
        eprintln!("{:#}", error);
        std::process::exit(1);
    }
}

async fn try_main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
    let cli = Cli::parse();

    let startup_config = StartupConfig {
        base_url: cli.base_url.as_deref().map(normalize_base_url),
        interactive_auth: matches!(cli.transport, Transport::Stdio),
    };
    match cli.transport {
        Transport::Http => {
            let config = HttpServerConfig::from_env_and_bind(&cli.bind)?;
            serve_http(startup_config, config).await
        }
        Transport::Stdio => {
            let server = DocmostMcpServer::new(startup_config)?;
            server.serve(stdio()).await?.waiting().await?;
            Ok(())
        }
    }
}
