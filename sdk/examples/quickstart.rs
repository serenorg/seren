use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::from_env();
    if config.bearer_token.is_none() {
        eprintln!("Set SEREN_API_KEY to run this example against the Seren API.");
        std::process::exit(1);
    }

    let client = Client::from_config(&config)?;
    let projects = client.seren_db_list_projects().await?.into_inner().data;

    println!("Found {} project(s)", projects.len());
    for project in projects {
        println!("  {} ({})", project.name, project.region);
    }

    Ok(())
}
