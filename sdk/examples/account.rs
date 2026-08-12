use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Account security and organization memberships require an interactive
    // user session, so this example takes a user access token rather than the
    // API key the other examples read from SEREN_API_KEY.
    let Ok(access_token) = std::env::var("SEREN_ACCESS_TOKEN") else {
        eprintln!("Set SEREN_ACCESS_TOKEN to a user access token to run this example.");
        std::process::exit(1);
    };
    let config = ClientConfig::from_env().with_bearer_token(access_token);
    let client = Client::from_config(&config)?;

    let user = client.get_current_user().await?.into_inner().data;
    let security = client.get_account_security().await?.into_inner().data;
    let memberships = client
        .list_current_user_organization_memberships()
        .await?
        .into_inner()
        .data;

    println!("Signed in as {} ({})", user.name, user.email);
    println!(
        "Recovery email: {}",
        security
            .recovery_email
            .as_deref()
            .unwrap_or("not configured")
    );
    if let Some(pending) = security.pending_recovery_email.as_deref() {
        println!("Pending verification: {}", pending);
    }
    for membership in memberships {
        println!(
            "{}: {} ({})",
            membership.name, membership.role, membership.id
        );
    }

    Ok(())
}
