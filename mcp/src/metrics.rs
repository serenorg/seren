use axum::response::IntoResponse;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::sync::LazyLock;

/// Global metrics registry for seren-mcp.
static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// Total MCP tool calls by tool name and outcome.
pub static TOOL_CALLS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new("seren_mcp_tool_calls_total", "Total MCP tool calls"),
        &["tool", "outcome"],
    )
    .expect("metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// MCP tool call duration in seconds.
pub static TOOL_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    let hist = HistogramVec::new(
        HistogramOpts::new(
            "seren_mcp_tool_duration_seconds",
            "MCP tool call duration in seconds",
        )
        .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["tool"],
    )
    .expect("metric creation");
    REGISTRY.register(Box::new(hist.clone())).ok();
    hist
});

/// Active MCP sessions gauge.
pub static ACTIVE_SESSIONS: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    let gauge =
        prometheus::IntGauge::new("seren_mcp_active_sessions", "Number of active MCP sessions")
            .expect("metric creation");
    REGISTRY.register(Box::new(gauge.clone())).ok();
    gauge
});

/// HTTP request counter by method, path, and status.
pub static HTTP_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    let counter = IntCounterVec::new(
        Opts::new("seren_mcp_http_requests_total", "Total HTTP requests"),
        &["method", "path", "status"],
    )
    .expect("metric creation");
    REGISTRY.register(Box::new(counter.clone())).ok();
    counter
});

/// Handler for GET /metrics — returns Prometheus text format.
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).ok();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buffer,
    )
}
