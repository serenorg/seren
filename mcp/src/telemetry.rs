//! Telemetry setup for the MCP server
//!
//! When compiled with the `telemetry` feature, provides distributed tracing
//! via OpenTelemetry OTLP exporter. Without the feature, provides simple
//! console logging only.
//!
//! # Environment Variables (with `telemetry` feature)
//!
//! - `OTEL_SDK_DISABLED` - Set to "true" to disable OpenTelemetry (default: enabled)
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` - OTLP collector endpoint (default: http://localhost:4318)
//! - `OTEL_SERVICE_NAME` - Service name override (default: "seren-mcp")

#[cfg(feature = "telemetry")]
mod otel {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing::Subscriber;
    use tracing_subscriber::Layer;
    use tracing_subscriber::registry::LookupSpan;

    /// OpenTelemetry provider guard - shuts down on drop
    pub struct TelemetryGuard {
        provider: Option<SdkTracerProvider>,
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
    pub fn init_tracing() -> Option<(SdkTracerProvider, TelemetryGuard)> {
        // Check if disabled
        if std::env::var("OTEL_SDK_DISABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            return None;
        }

        let service_name =
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| crate::MCP_SERVER_NAME.into());
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
        let resource = Resource::builder().with_service_name(service_name).build();

        // Build provider
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();

        let guard = TelemetryGuard {
            provider: Some(provider.clone()),
        };

        Some((provider, guard))
    }

    /// Create a tracing layer from a provider
    pub fn otel_layer<S>(provider: &SdkTracerProvider) -> impl Layer<S>
    where
        S: Subscriber + for<'span> LookupSpan<'span>,
    {
        tracing_opentelemetry::layer().with_tracer(provider.tracer(crate::MCP_SERVER_NAME))
    }
}

#[cfg(feature = "telemetry")]
pub use otel::TelemetryGuard;

/// Guard returned by init_subscriber - keeps telemetry alive
#[cfg(not(feature = "telemetry"))]
pub struct TelemetryGuard;

/// Use JSON log format when running in Kubernetes (auto-detected via injected env vars)
fn use_json() -> bool {
    std::env::var("KUBERNETES_SERVICE_HOST").is_ok() || std::env::var("KUBERNETES_PORT").is_ok()
}

/// Initialize the tracing subscriber
///
/// With `telemetry` feature:
/// - Console logging (stderr for stdio mode, stdout for HTTP mode)
/// - OpenTelemetry OTLP export (if not disabled via OTEL_SDK_DISABLED)
/// - JSON structured output when running in Kubernetes (auto-detected)
///
/// Without `telemetry` feature:
/// - Console logging only (lean binary for local use)
#[cfg(feature = "telemetry")]
pub fn init_subscriber(to_stderr: bool) -> Option<TelemetryGuard> {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();

    // Initialize OpenTelemetry (may return None if disabled)
    let (otel_layer, guard) = match otel::init_tracing() {
        Some((provider, guard)) => (Some(otel::otel_layer(&provider)), Some(guard)),
        None => (None, None),
    };

    match (to_stderr, use_json()) {
        (true, true) => tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_layer)
            .with(fmt::layer().json().with_writer(std::io::stderr))
            .init(),
        (true, false) => tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_layer)
            .with(fmt::layer().with_writer(std::io::stderr))
            .init(),
        (false, true) => tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_layer)
            .with(fmt::layer().json())
            .init(),
        (false, false) => tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_layer)
            .with(fmt::layer())
            .init(),
    }

    guard
}

/// Initialize the tracing subscriber (without telemetry feature)
///
/// Simple console logging only - lean binary for local/self-hosted use.
/// JSON structured output when running in Kubernetes (auto-detected).
#[cfg(not(feature = "telemetry"))]
pub fn init_subscriber(to_stderr: bool) -> Option<TelemetryGuard> {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();

    match (to_stderr, use_json()) {
        (true, true) => tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json().with_writer(std::io::stderr))
            .init(),
        (true, false) => tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_writer(std::io::stderr))
            .init(),
        (false, true) => tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init(),
        (false, false) => tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer())
            .init(),
    }

    Some(TelemetryGuard)
}
