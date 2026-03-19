use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    seren_mcp::run_cli().await
}
