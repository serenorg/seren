use seren::{Client, ClientConfig, SerenMemoryRecallParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::from_env();
    if config.bearer_token.is_none() {
        eprintln!("Set SEREN_API_KEY to run this example against the Seren API.");
        std::process::exit(1);
    }

    let query = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "release approval process".to_string());
    let client = Client::from_config(&config)?;
    let response = client
        .seren_memory_recall(&SerenMemoryRecallParams {
            created_after: None,
            created_before: None,
            query,
            limit: Some(5),
            memory_types: None,
            min_relevance: None,
            org_id: None,
            project_id: None,
            search_mode: Some("hybrid".to_string()),
        })
        .await?
        .into_inner();

    println!("Recalled {} memory item(s)", response.data.memories.len());
    // Memory bodies are omitted so private recalled content is not copied into terminal logs.
    for memory in response.data.memories {
        println!(
            "  {:.2}  {}  {}",
            memory.relevance_score, memory.memory_type, memory.id
        );
    }

    Ok(())
}
