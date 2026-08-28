use seren::{Client, ClientConfig, QueryRequest, QueryResult};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const EXACT_DECIMAL: &str = "123456789012345678901234567890.12345678901234567890";
const TINY_DECIMAL: &str = "0.00000000000000000001";

fn query_request() -> QueryRequest {
    QueryRequest {
        branch_id: None,
        database: None,
        database_identifier: None,
        project_id: None,
        query: "SELECT 1".to_string(),
        read_only: Some(true),
        scope: None,
        skill_slug: None,
    }
}

async fn query_result(body: &'static str) -> QueryResult {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/publishers/seren-db/query"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .mount(&server)
        .await;

    let client = Client::from_config(&ClientConfig::unauthenticated().with_base_url(server.uri()))
        .expect("client initializes");
    client
        .seren_db_query(&query_request())
        .await
        .expect("query response deserializes")
        .into_inner()
        .data
}

#[tokio::test]
async fn query_result_preserves_positional_json_cells() {
    let result = query_result(concat!(
        r#"{"data":{"columns":["text","integer","decimal","boolean","null","object","array"],"#,
        r#""rows":[["plain",7,123456789012345678901234567890.12345678901234567890,true,null,"#,
        r#"{"nested":["value",false]},["entry",2]],"#,
        r#"["second",8,0.00000000000000000001,false,null,{},[]]],"row_count":2}}"#
    ))
    .await;

    // The cell type is unconstrained JSON, not a map: a narrower generated type
    // would fail to compile here.
    let cells: &Vec<Vec<serde_json::Value>> = &result.rows;

    assert_eq!(
        result.columns,
        [
            "text", "integer", "decimal", "boolean", "null", "object", "array"
        ]
    );
    assert_eq!(result.row_count, 2);
    assert_eq!(cells.len(), 2);

    assert_eq!(cells[0][0], serde_json::json!("plain"));
    assert_eq!(cells[0][1], serde_json::json!(7));
    assert_eq!(cells[0][2].to_string(), EXACT_DECIMAL);
    assert_eq!(cells[0][3], serde_json::json!(true));
    assert!(cells[0][4].is_null());
    assert_eq!(cells[0][5], serde_json::json!({"nested": ["value", false]}));
    assert_eq!(cells[0][6], serde_json::json!(["entry", 2]));

    assert_eq!(cells[1][0], serde_json::json!("second"));
    assert_eq!(cells[1][1], serde_json::json!(8));
    assert_eq!(cells[1][2].to_string(), TINY_DECIMAL);
    assert_eq!(cells[1][3], serde_json::json!(false));
    assert!(cells[1][4].is_null());
    assert_eq!(cells[1][5], serde_json::json!({}));
    assert_eq!(cells[1][6], serde_json::json!([]));
}

/// Consumers hand the decoded result straight back to a JSON sink, so the exact
/// decimal token has to survive re-serialization as well as decoding.
#[tokio::test]
async fn query_result_reserializes_exact_decimal_tokens() {
    let result = query_result(concat!(
        r#"{"data":{"columns":["decimal"],"#,
        r#""rows":[[123456789012345678901234567890.12345678901234567890],"#,
        r#"[0.00000000000000000001]],"row_count":2}}"#
    ))
    .await;

    let encoded = serde_json::to_string(&result).expect("result re-serializes");
    assert!(
        encoded.contains(EXACT_DECIMAL),
        "high-precision decimal was rounded: {encoded}"
    );
    assert!(
        encoded.contains(TINY_DECIMAL),
        "small-magnitude decimal was rounded: {encoded}"
    );
}

#[tokio::test]
async fn query_result_allows_empty_rows() {
    let result = query_result(r#"{"data":{"columns":[],"rows":[],"row_count":0}}"#).await;

    assert!(result.columns.is_empty());
    assert!(result.rows.is_empty());
    assert_eq!(result.row_count, 0);
}
