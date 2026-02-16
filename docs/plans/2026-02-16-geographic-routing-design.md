# Geographic Routing Design

## Problem

Certain publisher APIs enforce geographic restrictions by checking the IP of incoming requests. Seren Core runs in us-east-1, so all outbound requests to upstream APIs originate from US IPs. Publishers like Polymarket's CLOB API (CFTC compliance) block these requests outright.

Market data works fine (different upstream without geo-blocking), but trading requests fail with "Access restricted."

## Design Principles

1. **Two routing modes** — `always` (all requests proxied, e.g., upstream blocks US IPs) and `opt_in` (users choose to route through proxy).
2. **Publisher declares routing** — Publishers declare which proxy region to use and which mode.
3. **Simplest infrastructure** — A lightweight proxy in eu-west-2 on a t4g.nano EC2 instance.
4. **Separate proxy fee** — Infrastructure cost charged as a distinct per-call fee, not baked into publisher pricing.

## Architecture

```
User -> MCP Server -> Seren Core (us-east-1, EKS Graviton ARM64)
                        |
                        +-- Publisher has NO routing config
                        |   -> Direct outbound to upstream API
                        |
                        +-- Publisher has routing (mode: "always")
                        |   -> All requests routed through proxy -> upstream API
                        |
                        +-- Publisher has routing (mode: "opt_in")
                            +-- User has NOT opted in
                            |   -> Return 403 with opt-in instructions
                            +-- User HAS opted in
                                -> Route through proxy -> upstream API
```

### EU Proxy Service

A stateless reverse proxy running in eu-west-2 (London). London is chosen because Polymarket's CLOB infrastructure runs on AWS eu-west-2.

- **Endpoint:** `https://eu.serendb.com`
- **Function:** Receives requests from Seren Core, forwards them to the upstream API URL specified in the `X-Upstream-URL` header, returns the response as-is.
- **Security:** Shared secret via `X-Proxy-Secret` header, plus security group restricting inbound to Seren Core's IP range.
- **No business logic** — no auth, no billing, no database. Just HTTP forwarding with a European IP.

### Compute: EC2 t4g.nano (eu-west-2)

- **t4g.nano:** 2 vCPU, 0.5GB RAM, ARM64 Graviton2
- **Cost:** ~$3-4/month (~$0.0042/hour on-demand)
- Consistent with ARM64/Graviton strategy across the platform
- If traffic grows beyond what a nano can handle, upgrade to t4g.micro/small

## Components

### 1. Publisher Routing Config (Seren Core)

New optional `routing` field on the publisher model:

```json
// "always" — all requests proxied (e.g., Polymarket trading)
{
  "routing": {
    "proxy_region": "EU",
    "mode": "always"
  }
}

// "opt_in" — users choose to proxy
{
  "routing": {
    "proxy_region": "EU",
    "mode": "opt_in"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `proxy_region` | `string` | Region code for the proxy to route through (e.g., "EU") |
| `mode` | `string` | `"always"` (all requests proxied) or `"opt_in"` (user chooses) |

### 2. Proxy Region Config (Admin Settings)

Proxy endpoints are stored in the `agent_marketplace_settings.geo_proxy_regions` JSONB column, configurable at runtime via the admin API:

```json
{
  "EU": {
    "url": "https://eu.serendb.com",
    "secret": "shared-secret-here",
    "fee_per_call": "0.001"
  }
}
```

### 3. Gateway Middleware (Seren Core)

In `proxy_to_publisher_impl`:

1. Check if publisher has `routing` config
2. If `mode == "always"`: route all requests through the proxy
3. If `mode == "opt_in"`: check user's opt-in status via `user_publisher_routing` table
   - If opted in: route through proxy
   - If not opted in: return 403 with `GeoRestrictedError` body
4. When routing through proxy:
   - Look up proxy endpoint from admin settings cache (60s TTL)
   - Rewrite publisher's `api_url` to the proxy URL
   - Inject `X-Upstream-URL` (original upstream) and `X-Proxy-Secret` headers
   - Add proxy `fee_per_call` to billing (TODO: wire into payment flow)

### 4. User Opt-In (opt_in mode only)

For publishers with `mode: "opt_in"`, users manage routing via REST API:

- `GET /user/routing` — list all opt-ins
- `GET /user/routing/{publisher_slug}` — check specific opt-in
- `PUT /user/routing/{publisher_slug}` — enable routing
- `DELETE /user/routing/{publisher_slug}` — disable routing

### 5. Proxy Fee

A per-call infrastructure fee is charged when requests are routed through a proxy, separate from the publisher's base pricing. The fee amount is configured per proxy region in admin settings (`fee_per_call`).

**Status:** Fee field defined in admin settings schema. Wiring into the payment flow (adding to `calculate_query_cost()` result) is a follow-up task.

### 6. Changes in This Repo (seren/seren)

**OpenAPI spec (`openapi/openapi.json`):**
- `GeoRoutingConfig` schema (proxy_region + mode)
- `GeoRestrictedError` response schema (opt_in mode only)
- User routing endpoints (`/user/routing`, `/user/routing/{publisher_slug}`)

**MCP server (`mcp/src/server.rs`):**
- 403 `geo_restricted` error handler with clear message and opt-in endpoint

**CLI (`cli/src/commands/agent.rs`):**
- `routing: None` field on publisher create

## What This Doesn't Include

- **No CloudFront or Lambda@Edge** — overkill for the initial use case
- **No user settings UI** — API-only for now
- **No Asia proxy** — start with EU only, add regions as needed
- **No Cloudflare Workers** — EC2 is simpler and cheaper

## Cost Estimate

| Component | Cost | Notes |
|-----------|------|-------|
| EC2 t4g.nano (eu-west-2) | ~$3-4/month | 2 vCPU, 0.5GB RAM, ARM64, always-on |
| Data transfer | ~$0.09/GB | US -> EU cross-region |
| Per-call proxy fee | $0.001/call | Charged to user, offsets infra cost |

At just 400 routed requests/month, revenue from fees ($4) covers the EC2 cost.

## Rollout

1. Deploy EU proxy on EC2 t4g.nano in eu-west-2 (London)
2. Configure proxy region in admin settings (`geo_proxy_regions`)
3. Configure publisher with `routing: { "proxy_region": "EU", "mode": "always" }`
4. Wire proxy fee into payment flow
5. Test end-to-end with Polymarket CLOB API
