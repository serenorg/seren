//! OpenTelemetry telemetry setup for the MCP server
//!
//! Provides distributed tracing via OpenTelemetry OTLP exporter.
//!
//! # Environment Variables
//!
//! - `OTEL_SDK_DISABLED` - Set to "true" to disable OpenTelemetry (default: enabled)
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` - OTLP collector endpoint (default: http://localhost:4318)
//! - `OTEL_SERVICE_NAME` - Service name override (default: "seren-mcp")

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::Resource;
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// OpenTelemetry provider guard - shuts down on drop
pub struct TelemetryGuard {
    provider: Option<TracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("Error shutting down OpenTelemetry provider: {:?}", e);
            }
        }
    }
}

/// Initialize OpenTelemetry tracing
///
/// Returns `None` if `OTEL_SDK_DISABLED=true` or if initialization fails.
pub fn init_tracing() -> Option<(TracerProvider, TelemetryGuard)> {
    // Check if disabled
    if std::env::var("OTEL_SDK_DISABLED")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        return None;
    }

    let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "seren-mcp".into());
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4318".into());

    // Build OTLP exporter using HTTP
    let exporter = match SpanExporter::builder()
        .with_http()
        .with_endpoint(&endpoint)
        .build()
    {
        Ok(exporter) => exporter,
        Err(e) => {
            eprintln!("Failed to create OTLP exporter: {}. Tracing disabled.", e);
            return None;
        }
    };

    // Set up W3C TraceContext propagation for distributed tracing
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    // Build resource with service name
    let resource = Resource::new(vec![KeyValue::new(
        opentelemetry_semantic_conventions::resource::SERVICE_NAME,
        service_name,
    )]);

    // Build provider
    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource)
        .build();

    let guard = TelemetryGuard {
        provider: Some(provider.clone()),
    };

    Some((provider, guard))
}

/// Create a tracing layer from a provider
pub fn otel_layer<S>(provider: &TracerProvider) -> impl Layer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    tracing_opentelemetry::layer().with_tracer(provider.tracer("seren-mcp"))
}

/// Initialize the full tracing subscriber with optional OpenTelemetry
///
/// This sets up:
/// - Console logging (stderr for stdio mode, stdout for HTTP mode)
/// - OpenTelemetry OTLP export (if not disabled)
pub fn init_subscriber(to_stderr: bool) -> Option<TelemetryGuard> {
    use tracing_subscriber::fmt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();

    // Initialize OpenTelemetry (may return None if disabled)
    let (otel_layer, guard) = match init_tracing() {
        Some((provider, guard)) => (Some(otel_layer(&provider)), Some(guard)),
        None => (None, None),
    };

    if to_stderr {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_layer)
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_layer)
            .with(fmt::layer())
            .init();
    }

    guard
}
