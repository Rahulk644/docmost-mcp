use std::{env, path::PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationEvent<'a> {
    timestamp: String,
    operation: &'a str,
    target: &'a str,
    status: &'a str,
}

pub async fn record_mutation(operation: &str, target: &str, status: &str) -> Result<()> {
    let path = audit_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create audit directory {}", parent.display()))?;
        set_mode(parent, 0o700).await?;
    }
    let event = MutationEvent {
        timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        operation,
        target,
        status,
    };
    let mut line = serde_json::to_vec(&event).context("Failed to encode mutation audit event")?;
    line.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("Failed to open mutation audit log {}", path.display()))?;
    file.write_all(&line)
        .await
        .with_context(|| format!("Failed to write mutation audit log {}", path.display()))?;
    file.flush()
        .await
        .context("Failed to flush mutation audit log")?;
    set_mode(&path, 0o600).await
}

fn audit_path() -> Result<PathBuf> {
    if let Some(path) = env::var("DOCMOST_MCP_AUDIT_LOG")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    Ok(dirs::home_dir()
        .context("Unable to determine home directory for mutation audit log")?
        .join(".docmost-local-mcp/mutations.jsonl"))
}

#[cfg(unix)]
async fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
async fn set_mode(_path: &std::path::Path, _mode: u32) -> Result<()> {
    Ok(())
}
