# Geographic Routing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add geographic routing support so geo-restricted publishers (like Polymarket CLOB) can be accessed via a per-publisher user opt-in that routes requests through an EU proxy.

**Architecture:** Seren Core handles all routing logic, user opt-in storage, and publisher config. This repo (seren/seren) updates the OpenAPI spec with new schemas and endpoints, adds a 403 `geo_restricted` error handler to the MCP server, and adds an `enable_geo_routing` / `disable_geo_routing` / `get_geo_routing` tool so AI agents can manage routing opt-ins.

**Tech Stack:** Rust, serde, rmcp macros, OpenAPI/JSON, progenitor codegen

**Design Doc:** `docs/plans/2026-02-16-geographic-routing-design.md`

---

### Task 1: Add GeoRoutingConfig schema to OpenAPI spec

**Files:**
- Modify: `openapi/openapi.json`

**Step 1: Add GeoRoutingConfig schema**

In `components.schemas`, add:

```json
"GeoRoutingConfig": {
  "type": "object",
  "description": "Geographic routing configuration for publishers with geo-restricted upstream APIs",
  "required": ["geo_restricted_regions", "proxy_regions"],
  "properties": {
    "geo_restricted_regions": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Country/region codes where direct access is blocked (e.g. [\"US\"])"
    },
    "proxy_regions": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Available proxy regions to route through (e.g. [\"EU\"])"
    },
    "premium_per_call": {
      "type": "number",
      "format": "double",
      "description": "Additional charge per geo-routed request"
    },
    "premium_currency": {
      "type": "string",
      "description": "Currency for the premium charge (e.g. \"USDC\")"
    }
  }
}
```

**Step 2: Add `routing` field to publisher schemas**

Add to both `CreatePublisherRequest` and `UpdatePublisherRequest` schemas:

```json
"routing": {
  "allOf": [{ "$ref": "#/components/schemas/GeoRoutingConfig" }],
  "nullable": true,
  "description": "Geographic routing configuration for geo-restricted upstream APIs"
}
```

Also add to `PublisherDataResponse` (or equivalent response schema) so routing config is returned when fetching publisher info.

**Step 3: Add GeoRestrictedError schema**

```json
"GeoRestrictedError": {
  "type": "object",
  "description": "Error returned when a publisher is geo-restricted and the user has not opted in",
  "required": ["error", "message", "publisher", "restricted_region", "available_proxy_regions"],
  "properties": {
    "error": {
      "type": "string",
      "enum": ["geo_restricted"],
      "description": "Error code"
    },
    "message": {
      "type": "string",
      "description": "Human-readable explanation"
    },
    "publisher": {
      "type": "string",
      "description": "Publisher slug"
    },
    "restricted_region": {
      "type": "string",
      "description": "The user's detected region that is restricted"
    },
    "available_proxy_regions": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Regions the user can opt in to route through"
    },
    "premium_per_call": {
      "type": "number",
      "format": "double",
      "nullable": true,
      "description": "Cost premium per routed call"
    },
    "opt_in_endpoint": {
      "type": "string",
      "description": "API endpoint to enable routing"
    }
  }
}
```

**Step 4: Verify the spec is valid JSON**

Run: `python3 -c "import json; json.load(open('openapi/openapi.json'))"`
Expected: No output (valid JSON)

**Step 5: Commit**

```bash
git add openapi/openapi.json
git commit -m "feat(openapi): add GeoRoutingConfig and GeoRestrictedError schemas"
```

---

### Task 2: Add user routing endpoints to OpenAPI spec

**Files:**
- Modify: `openapi/openapi.json`

**Step 1: Add UserRoutingOptIn schema**

```json
"UserRoutingOptIn": {
  "type": "object",
  "required": ["publisher_slug", "region"],
  "properties": {
    "publisher_slug": {
      "type": "string",
      "description": "Publisher slug"
    },
    "region": {
      "type": "string",
      "description": "Proxy region the user opted in to (e.g. \"EU\")"
    },
    "created_at": {
      "type": "string",
      "format": "date-time",
      "description": "When the opt-in was created"
    }
  }
},
"EnableGeoRoutingRequest": {
  "type": "object",
  "required": ["region"],
  "properties": {
    "region": {
      "type": "string",
      "description": "Proxy region to enable (e.g. \"EU\")"
    }
  }
}
```

**Step 2: Add `/user/routing` GET endpoint**

```json
"/user/routing": {
  "get": {
    "tags": ["User"],
    "summary": "GET /user/routing",
    "description": "List all geographic routing opt-ins for the authenticated user",
    "operationId": "list_user_routing",
    "responses": {
      "200": {
        "description": "List of routing opt-ins",
        "content": {
          "application/json": {
            "schema": {
              "type": "array",
              "items": { "$ref": "#/components/schemas/UserRoutingOptIn" }
            }
          }
        }
      },
      "401": { "description": "Unauthorized" }
    },
    "security": [{ "bearer_auth": [] }]
  }
}
```

**Step 3: Add `/user/routing/{publisher_slug}` endpoints**

```json
"/user/routing/{publisher_slug}": {
  "get": {
    "tags": ["User"],
    "summary": "GET /user/routing/:publisher_slug",
    "description": "Check geo-routing opt-in status for a specific publisher",
    "operationId": "get_user_routing",
    "parameters": [{
      "name": "publisher_slug",
      "in": "path",
      "required": true,
      "schema": { "type": "string" }
    }],
    "responses": {
      "200": {
        "description": "Routing opt-in details",
        "content": {
          "application/json": {
            "schema": { "$ref": "#/components/schemas/UserRoutingOptIn" }
          }
        }
      },
      "404": { "description": "No routing opt-in found for this publisher" },
      "401": { "description": "Unauthorized" }
    },
    "security": [{ "bearer_auth": [] }]
  },
  "put": {
    "tags": ["User"],
    "summary": "PUT /user/routing/:publisher_slug",
    "description": "Enable geographic routing for a publisher. The user acknowledges that requests will be routed through the specified proxy region and may incur additional charges.",
    "operationId": "enable_user_routing",
    "parameters": [{
      "name": "publisher_slug",
      "in": "path",
      "required": true,
      "schema": { "type": "string" }
    }],
    "requestBody": {
      "content": {
        "application/json": {
          "schema": { "$ref": "#/components/schemas/EnableGeoRoutingRequest" }
        }
      },
      "required": true
    },
    "responses": {
      "200": {
        "description": "Routing enabled",
        "content": {
          "application/json": {
            "schema": { "$ref": "#/components/schemas/UserRoutingOptIn" }
          }
        }
      },
      "400": { "description": "Publisher does not support routing or invalid region" },
      "401": { "description": "Unauthorized" }
    },
    "security": [{ "bearer_auth": [] }]
  },
  "delete": {
    "tags": ["User"],
    "summary": "DELETE /user/routing/:publisher_slug",
    "description": "Disable geographic routing for a publisher",
    "operationId": "disable_user_routing",
    "parameters": [{
      "name": "publisher_slug",
      "in": "path",
      "required": true,
      "schema": { "type": "string" }
    }],
    "responses": {
      "204": { "description": "Routing disabled" },
      "401": { "description": "Unauthorized" }
    },
    "security": [{ "bearer_auth": [] }]
  }
}
```

**Step 4: Verify the spec is valid JSON**

Run: `python3 -c "import json; json.load(open('openapi/openapi.json'))"`
Expected: No output (valid JSON)

**Step 5: Verify SDK codegen works**

Run: `cargo check --package seren 2>&1 | tail -20`
Expected: Compiles successfully (progenitor generates new methods from the spec)

**Step 6: Commit**

```bash
git add openapi/openapi.json
git commit -m "feat(openapi): add user routing opt-in endpoints"
```

---

### Task 3: Handle 403 geo_restricted error in MCP server

**Files:**
- Modify: `mcp/src/server.rs`

**Step 1: Add geo_restricted 403 handler in `handle_call_publisher_error`**

In `mcp/src/server.rs`, find `handle_call_publisher_error`. After the `StatusCode::BAD_REQUEST` block (around line 5115) and before the generic fallthrough (line 5116), add a `FORBIDDEN` check:

```rust
if status == reqwest::StatusCode::FORBIDDEN {
    let body_text = response.text().await.unwrap_or_default();
    // Check if this is a geo-restriction error from the gateway
    if body_text.contains("geo_restricted") {
        // Try to parse the structured error for a helpful message
        if let Ok(geo_error) = serde_json::from_str::<serde_json::Value>(&body_text) {
            let publisher = geo_error.get("publisher")
                .and_then(|v| v.as_str())
                .unwrap_or(&ctx.publisher);
            let regions = geo_error.get("available_proxy_regions")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_else(|| "EU".to_string());
            let premium = geo_error.get("premium_per_call")
                .and_then(|v| v.as_f64())
                .map(|p| format!(" Additional charges of ${:.2}/call apply.", p))
                .unwrap_or_default();

            return Err(McpError::internal_error(
                format!(
                    "Publisher '{}' is geo-restricted in your region. \
                     Available proxy regions: {}. \
                     To enable routing, use the enable_geo_routing tool with publisher='{}' and region='{}'. \
                     {}",
                    publisher, regions, publisher,
                    regions.split(", ").next().unwrap_or("EU"),
                    premium.trim(),
                ),
                None,
            ));
        }
        // Fallback if we can't parse the structured error
        return Err(McpError::internal_error(
            format!(
                "Publisher '{}' is geo-restricted in your region. \
                 Use the enable_geo_routing tool to enable geographic routing.",
                ctx.publisher
            ),
            None,
        ));
    }
    // Non-geo 403 errors fall through to generic handler
    return Err(McpError::internal_error(
        format!(
            "{} call failed ({}): {}",
            ctx.publisher_type,
            status,
            truncate_for_client(&body_text, 1200)
        ),
        None,
    ));
}
```

**Step 2: Verify it compiles**

Run: `cargo check --package seren-mcp 2>&1 | tail -10`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add mcp/src/server.rs
git commit -m "feat(mcp): handle 403 geo_restricted error with actionable message"
```

---

### Task 4: Add enable_geo_routing MCP tool

**Files:**
- Modify: `mcp/src/server.rs`

**Step 1: Add params struct**

Near the other params structs (around line 490), add:

```rust
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EnableGeoRoutingParams {
    /// Publisher slug to enable geo-routing for
    pub publisher: String,
    /// Proxy region to route through (e.g. "EU")
    pub region: String,
}
```

**Step 2: Add tool handler**

Inside the `#[tool_router] impl SerenMcpServer` block, add:

```rust
#[tool(
    description = "Enable geographic routing for a geo-restricted publisher. \
        When a publisher's upstream API is blocked in your region, this tool \
        opts you in to route requests through a proxy in the specified region. \
        Additional per-call charges may apply. Use get_geo_routing_status to \
        check current opt-in status.",
    annotations(
        read_only_hint = false,
        destructive_hint = false,
        open_world_hint = false
    )
)]
async fn enable_geo_routing(
    &self,
    Parameters(params): Parameters<EnableGeoRoutingParams>,
    extensions: Extensions,
) -> Result<CallToolResult, McpError> {
    ensure_writes_allowed(&extensions)?;

    let agent_metadata = extract_agent_metadata_from_extensions(&extensions);
    let body = serde_json::json!({ "region": params.region });
    let path = format!("/user/routing/{}", params.publisher);

    let response = self
        .execute_publisher_proxy_raw(
            &extensions,
            &agent_metadata,
            API_TIMEOUT,
            &reqwest::Method::PUT,
            &path,
            Some(&body),
            None,
            None,
            None,
        )
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    let status = response.status();
    if status.is_success() {
        let result: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"status": "enabled"}));
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Geographic routing enabled for publisher '{}' through {} region. \
             Subsequent calls to this publisher will be routed through the proxy.",
            params.publisher, params.region
        ))]))
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(McpError::internal_error(
            format!(
                "Failed to enable geo-routing for '{}' ({}): {}",
                params.publisher,
                status,
                truncate_for_client(&body, 1200)
            ),
            None,
        ))
    }
}
```

**Step 3: Verify it compiles**

Run: `cargo check --package seren-mcp 2>&1 | tail -10`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add mcp/src/server.rs
git commit -m "feat(mcp): add enable_geo_routing tool"
```

---

### Task 5: Add disable_geo_routing and get_geo_routing_status MCP tools

**Files:**
- Modify: `mcp/src/server.rs`

**Step 1: Add params struct for single-publisher lookup**

```rust
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GeoRoutingPublisherParams {
    /// Publisher slug to check or disable geo-routing for
    pub publisher: String,
}
```

**Step 2: Add disable_geo_routing tool handler**

```rust
#[tool(
    description = "Disable geographic routing for a publisher. \
        Stops routing requests through the proxy region. \
        Subsequent requests to a geo-restricted publisher will fail \
        if your region is blocked.",
    annotations(
        read_only_hint = false,
        destructive_hint = false,
        open_world_hint = false
    )
)]
async fn disable_geo_routing(
    &self,
    Parameters(params): Parameters<GeoRoutingPublisherParams>,
    extensions: Extensions,
) -> Result<CallToolResult, McpError> {
    ensure_writes_allowed(&extensions)?;

    let agent_metadata = extract_agent_metadata_from_extensions(&extensions);
    let path = format!("/user/routing/{}", params.publisher);

    let response = self
        .execute_publisher_proxy_raw::<serde_json::Value>(
            &extensions,
            &agent_metadata,
            API_TIMEOUT,
            &reqwest::Method::DELETE,
            &path,
            None,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    let status = response.status();
    if status.is_success() {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Geographic routing disabled for publisher '{}'.",
            params.publisher
        ))]))
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(McpError::internal_error(
            format!(
                "Failed to disable geo-routing for '{}' ({}): {}",
                params.publisher,
                status,
                truncate_for_client(&body, 1200)
            ),
            None,
        ))
    }
}
```

**Step 3: Add get_geo_routing_status tool handler**

```rust
#[tool(
    description = "Check geographic routing status for a publisher or list all routing opt-ins. \
        Shows whether geographic routing is enabled and which proxy region is being used.",
    annotations(read_only_hint = true, open_world_hint = false)
)]
async fn get_geo_routing_status(
    &self,
    Parameters(params): Parameters<GeoRoutingPublisherParams>,
    extensions: Extensions,
) -> Result<CallToolResult, McpError> {
    let agent_metadata = extract_agent_metadata_from_extensions(&extensions);
    let path = format!("/user/routing/{}", params.publisher);

    let response = self
        .execute_publisher_proxy_raw::<serde_json::Value>(
            &extensions,
            &agent_metadata,
            API_TIMEOUT,
            &reqwest::Method::GET,
            &path,
            None,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    let status = response.status();
    if status.is_success() {
        let result: serde_json::Value = response
            .json()
            .await
            .unwrap_or(serde_json::json!({"enabled": false}));
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    } else if status == reqwest::StatusCode::NOT_FOUND {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Geographic routing is not enabled for publisher '{}'.",
            params.publisher
        ))]))
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(McpError::internal_error(
            format!(
                "Failed to check geo-routing status for '{}' ({}): {}",
                params.publisher,
                status,
                truncate_for_client(&body, 1200)
            ),
            None,
        ))
    }
}
```

**Step 4: Verify it compiles**

Run: `cargo check --package seren-mcp 2>&1 | tail -10`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add mcp/src/server.rs
git commit -m "feat(mcp): add disable_geo_routing and get_geo_routing_status tools"
```

---

### Task 6: Run full checks

**Step 1: Run cargo check for the whole workspace**

Run: `cargo check --workspace 2>&1 | tail -20`
Expected: Compiles successfully

**Step 2: Run clippy**

Run: `cargo clippy --package seren-mcp -- -D warnings 2>&1 | tail -20`
Expected: No warnings

**Step 3: Run existing tests**

Run: `cargo test --package seren-mcp 2>&1 | tail -20`
Expected: All existing tests pass

**Step 4: Run fmt**

Run: `cargo fmt --all -- --check 2>&1 | tail -10`
Expected: No formatting issues (or run `cargo fmt --all` to fix)

**Step 5: Commit any fixes**

If clippy or fmt required changes:
```bash
git add -A
git commit -m "style: fix clippy warnings and formatting"
```

---

### Task 7: Final commit with design doc

**Step 1: Commit design docs**

```bash
git add docs/plans/2026-02-16-geographic-routing-design.md docs/plans/2026-02-16-geographic-routing-impl.md
git commit -m "docs: add geographic routing design and implementation plan"
```

---

## Implementation Notes

**What's NOT implemented here (Seren Core side):**
- Publisher `routing` field in database model and migrations
- `user_publisher_routing` table and migration
- `/user/routing` API handlers
- Gateway middleware geo-routing logic
- EU proxy service deployment (EC2 t4g.nano in eu-west-2)
- Billing integration for routing premiums

These are tracked in serenorg/seren-core#77 and will be implemented in the serencore repo.

**What IS implemented here:**
1. OpenAPI spec: `GeoRoutingConfig`, `GeoRestrictedError`, `UserRoutingOptIn` schemas
2. OpenAPI spec: `/user/routing` CRUD endpoints
3. MCP server: 403 `geo_restricted` error handler with actionable message
4. MCP server: `enable_geo_routing`, `disable_geo_routing`, `get_geo_routing_status` tools
5. SDK: Auto-generated from OpenAPI spec (no manual work)
