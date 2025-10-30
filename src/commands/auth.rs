use anyhow::Result;
use colored::Colorize;
use std::io::{self, Write};

use crate::config::Config;
use crate::output;
use crate::OutputFormat;

pub async fn login() -> Result<()> {
    println!("{}", "Seren CLI Authentication".bold().green());
    println!();
    println!("To authenticate, you need an API key from your Seren account.");
    println!("You can create one at: https://app.seren.com/settings/api-keys");
    println!();

    print!("Enter your API key (seren_...): ");
    io::stdout().flush()?;

    let mut api_key = String::new();
    io::stdin().read_line(&mut api_key)?;
    let api_key = api_key.trim().to_string();

    // Validate API key format
    if !api_key.starts_with("seren_") {
        anyhow::bail!("Invalid API key format. API keys should start with 'seren_'");
    }

    // TODO: Verify the API key by making a test request to the API
    // For now, we'll just save it

    let config = Config { api_key };
    config.save()?;

    println!();
    println!("{}", "✓ Successfully authenticated!".green().bold());
    println!();
    println!("Try running: seren projects list");

    Ok(())
}

pub async fn status() -> Result<()> {
    match Config::load() {
        Ok(config) => {
            let masked_key = mask_api_key(&config.api_key);
            println!("{}", "✓ Authenticated".green().bold());
            println!("API Key: {}", masked_key);
            
            if let Ok(path) = Config::config_path() {
                println!("Config: {}", path.display());
            }
        }
        Err(_) => {
            println!("{}", "✗ Not authenticated".red().bold());
            println!("Run 'seren auth login' to authenticate");
        }
    }

    Ok(())
}

pub async fn logout() -> Result<()> {
    Config::delete()?;
    println!("{}", "✓ Successfully logged out".green().bold());
    Ok(())
}

fn mask_api_key(key: &str) -> String {
    if key.len() <= 12 {
        return "*".repeat(key.len());
    }
    
    let prefix = &key[..7]; // "seren_"
    let suffix = &key[key.len() - 4..];
    format!("{}...{}", prefix, suffix)
}

pub async fn me(format: OutputFormat, api_host: Option<String>) -> Result<()> {
    let config = Config::load()?;
    
    let mut client_config = seren::ClientConfig::new(config.api_key);
    if let Some(base_url) = api_host {
        client_config = client_config.with_base_url(base_url);
    }
    
    let client = seren::Client::new(client_config)?;
    let user = client.me().await?;
    
    match format {
        OutputFormat::Json => output::print_json(&user)?,
        OutputFormat::Table => output::print_user(&user)?,
    }
    
    Ok(())
}

pub async fn organizations(format: OutputFormat, api_host: Option<String>) -> Result<()> {
    let config = Config::load()?;
    
    let mut client_config = seren::ClientConfig::new(config.api_key);
    if let Some(base_url) = api_host {
        client_config = client_config.with_base_url(base_url);
    }
    
    let client = seren::Client::new(client_config)?;
    let orgs = client.organizations().await?;
    
    match format {
        OutputFormat::Json => output::print_json(&orgs)?,
        OutputFormat::Table => output::print_organizations_table(&orgs),
    }
    
    Ok(())
}
