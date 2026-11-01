use serde_json::{Value, json};
use seren::Client;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn prices(changed_at: Value) -> Value {
    json!([
        {
            "key": "work", "name": "Work", "charge": "fee",
            "amount": {"atomic": 1000000, "usd": "$1.00"}, "changed_at": changed_at,
            "triggers": ["chat"], "expected_cost_atomic": 300000
        },
        {
            "key": "care", "name": "Care", "charge": "cost",
            "triggers": ["hire_cron", "schedule", "webhook", "api"], "expected_cost_atomic": 300000
        }
    ])
}

fn owner(deployment_id: Uuid, run_kinds: Value) -> Value {
    json!({
        "id": deployment_id, "organization_id": Uuid::from_u128(1), "name": "Pricing contract",
        "skill_slug": "pricing-contract", "mode": "always_on", "platform_managed": true,
        "status": "running", "desired_lifecycle_state": "running", "serving_fallback": false,
        "template": {"slug": "pricing-contract", "display_name": "Pricing contract", "revision": 1},
        "run_kinds": run_kinds.clone(),
        "spend_limits": {
            "per_task_atomic": 2000000, "per_day_atomic": 10000000, "day_timezone": "UTC",
            "defaults": {"per_task_atomic": 2000000, "per_day_atomic": 10000000},
            "run_kinds": run_kinds
        },
        "created_at": "2026-10-23T00:00:00Z", "updated_at": "2026-10-23T00:00:00Z"
    })
}

/// Preserve each complete price object, treating an absent optional timestamp and null equally.
fn assert_prices(actual: &Value, wire: &Value) {
    let mut expected = wire.clone();
    let mut actual = actual.clone();
    for prices in [&mut expected, &mut actual] {
        for price in prices.as_array_mut().unwrap() {
            let price = price.as_object_mut().unwrap();
            if price.get("charge").and_then(Value::as_str) == Some("fee")
                && price.get("changed_at").is_some_and(Value::is_null)
            {
                price.remove("changed_at");
            }
        }
    }
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn managed_pricing_success_bodies_preserve_fee_and_cost_contracts() {
    for changed_at in [Value::Null, json!("2026-10-22T12:00:00Z")] {
        let server = MockServer::start().await;
        let deployment_id = Uuid::from_u128(42);
        let run_kinds = prices(changed_at);
        let owner = owner(deployment_id, run_kinds.clone());
        Mock::given(method("GET"))
            .and(path(format!(
                "/publishers/seren-agent/deployments/{deployment_id}/managed"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": owner.clone()})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/publishers/seren-agent/deployments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [owner]})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/publishers/seren-agent/templates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [{
                "slug": "pricing-contract", "display_name": "Pricing contract",
                "publisher": {"organization_id": Uuid::from_u128(1), "name": "Studio",
                    "made_by_seren": false, "verified": false},
                "owner_connection": "sign_in_only", "published_at": "2026-10-23T00:00:00Z",
                "capabilities": [], "example_tasks": ["Run a pricing task"],
                "works_in": ["slack"], "pronouns": "they/them", "run_kinds": run_kinds.clone(),
                "spend_limit_defaults": {"per_task_atomic": 2000000, "per_day_atomic": 10000000},
                "catalog": {"hires_30d": 0, "hours_of_work": 0, "active_hires": 0,
                    "best_sellers_rank": null, "seren_choice": false, "also_hired": [],
                    "rating": null, "updated_at": null},
                "similar": []
            }]})))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri());
        let detail = client
            .seren_agent_get_managed_deployment(&deployment_id)
            .await
            .unwrap()
            .into_inner();
        let detail = serde_json::to_value(detail).unwrap();
        assert_eq!(detail["data"]["serving_fallback"], false);
        assert_prices(&detail["data"]["run_kinds"], &run_kinds);
        assert_prices(&detail["data"]["spend_limits"]["run_kinds"], &run_kinds);
        let list = client
            .seren_agent_list_deployments()
            .await
            .unwrap()
            .into_inner();
        let list = serde_json::to_value(list).unwrap();
        assert_eq!(list["data"][0]["serving_fallback"], false);
        assert_prices(&list["data"][0]["run_kinds"], &run_kinds);
        assert_prices(&list["data"][0]["spend_limits"]["run_kinds"], &run_kinds);
        let templates = client
            .seren_agent_list_managed_agent_templates()
            .await
            .unwrap()
            .into_inner();
        let templates = serde_json::to_value(templates).unwrap();
        assert_eq!(templates["data"][0]["publisher"]["made_by_seren"], false);
        assert_eq!(templates["data"][0]["publisher"]["verified"], false);
        assert_eq!(
            templates["data"][0]["example_tasks"],
            json!(["Run a pricing task"])
        );
        assert_eq!(templates["data"][0]["works_in"], json!(["slack"]));
        assert_eq!(templates["data"][0]["pronouns"], "they/them");
        assert_prices(&templates["data"][0]["run_kinds"], &run_kinds);
        server.verify().await;
    }
}

#[test]
fn invalid_charge_or_missing_fee_amount_is_not_a_price() {
    for mut wire in [
        prices(Value::Null)[0].clone(),
        prices(Value::Null)[1].clone(),
    ] {
        wire["charge"] = json!("unknown");
        assert!(serde_json::from_value::<seren::ManagedAgentRunKindPrice>(wire).is_err());
    }
    let mut fee = prices(Value::Null)[0].clone();
    fee.as_object_mut().unwrap().remove("amount");
    assert!(serde_json::from_value::<seren::ManagedAgentRunKindPrice>(fee).is_err());
}

#[tokio::test]
async fn managed_owner_pricing_rejects_missing_serving_fallback() {
    let server = MockServer::start().await;
    let deployment_id = Uuid::from_u128(42);
    let mut owner = owner(deployment_id, prices(Value::Null));
    owner.as_object_mut().unwrap().remove("serving_fallback");
    Mock::given(method("GET"))
        .and(path(format!(
            "/publishers/seren-agent/deployments/{deployment_id}/managed"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": owner})))
        .expect(1)
        .mount(&server)
        .await;
    let error = Client::new(&server.uri())
        .seren_agent_get_managed_deployment(&deployment_id)
        .await
        .unwrap_err();
    assert!(matches!(error, seren::Error::InvalidResponsePayload(_, _)));
    server.verify().await;
}
