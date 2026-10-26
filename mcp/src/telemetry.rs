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
            if let Some(provider) = self.provider.take()
                && let Err(e) = provider.shutdown()
            {
                eprintln!("Error shutting down OpenTelemetry provider: {:?}", e);
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

/// Cap protocol diagnostics independently of operator-selected span filters.
/// Raw rmcp service and codec diagnostics include arguments before tool handling.
fn subscriber_filter(
    environment: tracing_subscriber::EnvFilter,
) -> impl tracing_subscriber::Layer<tracing_subscriber::Registry> {
    use tracing_subscriber::Layer;

    environment
        .add_directive(
            "rmcp::service=info"
                .parse()
                .expect("valid rmcp service directive"),
        )
        .and_then(tracing_subscriber::filter::filter_fn(|metadata| {
            let target = metadata.target();
            let payload_target = ["rmcp::service", "rmcp::transport::async_rw"]
                .into_iter()
                .any(|module| {
                    target
                        .strip_prefix(module)
                        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with("::"))
                });
            !payload_target || *metadata.level() <= tracing::Level::INFO
        }))
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

    let env_filter = subscriber_filter(
        EnvFilter::builder()
            .with_default_directive(tracing::Level::INFO.into())
            .from_env_lossy(),
    );

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

    let env_filter = subscriber_filter(
        EnvFilter::builder()
            .with_default_directive(tracing::Level::INFO.into())
            .from_env_lossy(),
    );

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    const CONFIGURATIONS: &[(&str, bool)] = &[
        ("", false),
        ("debug", true),
        ("trace", true),
        ("seren_mcp::capture_test=debug", true),
        (
            "rmcp::transport::async_rw=trace,seren_mcp::capture_test=debug",
            true,
        ),
        ("rmcp::service=trace,seren_mcp::capture_test=debug", true),
        (
            "rmcp::service[serve_inner]=trace,seren_mcp::capture_test=debug",
            true,
        ),
    ];

    fn environment(directives: &str) -> EnvFilter {
        EnvFilter::builder()
            .with_default_directive(tracing::Level::INFO.into())
            .parse_lossy(directives)
    }

    fn emit_malformed_protocol_frame() {
        use tokio_util::codec::Decoder;

        let mut codec =
            rmcp::transport::async_rw::JsonRpcMessageCodec::<serde_json::Value>::default();
        let mut frame = tokio_util::bytes::BytesMut::from(
            &b"{\"params\":{\"headers\":{\"X-Seren-Run-Dispatch\":\"private-dispatch-value\"}},\"invalid\":\n"[..],
        );
        assert!(codec.decode(&mut frame).is_err());
    }

    fn emit_protocol_events() {
        let request = rmcp::model::CallToolRequestParams::new("call_publisher").with_arguments(
            serde_json::json!({"headers": {"X-Seren-Run-Dispatch": "private-dispatch-value"}})
                .as_object()
                .unwrap()
                .clone(),
        );
        let span = tracing::info_span!(target: "rmcp::service", "serve_inner");
        let _entered = span.enter();
        emit_malformed_protocol_frame();
        tracing::debug!(target: "rmcp::service", ?request, "received request");
        tracing::trace!(target: "rmcp::service", ?request, "new event");
        tracing::debug!(target: "rmcp::service::nested", ?request, "nested request");
        tracing::info!(target: "rmcp::service", "protocol-info-visible");
        tracing::debug!(target: "seren_mcp::capture_test", "unrelated-debug-visible");
    }

    fn assert_capture(text: &str, unrelated_debug: bool) {
        assert!(!text.contains("private-dispatch-value"));
        assert!(!text.contains("received request"));
        assert!(!text.contains("new event"));
        assert!(!text.contains("nested request"));
        assert!(!text.contains("Failed to parse message"));
        assert!(text.contains("protocol-info-visible"));
        assert_eq!(text.contains("unrelated-debug-visible"), unrelated_debug);
    }

    #[test]
    fn malformed_protocol_capture_exercises_the_actual_codec_logger() {
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::registry()
            .with(environment("debug"))
            .with(
                tracing_subscriber::fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_writer(move || writer.clone()),
            );
        tracing::subscriber::with_default(subscriber, emit_malformed_protocol_frame);
        let text = capture.text();
        assert!(text.contains("private-dispatch-value"));
        assert!(text.contains("Failed to parse message"));
    }

    #[test]
    fn protocol_payload_filter_captures_console_output_without_raw_arguments() {
        for &(directives, debug) in CONFIGURATIONS {
            for json in [false, true] {
                let capture = Capture::default();
                let writer = capture.clone();
                let format = tracing_subscriber::fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_writer(move || writer.clone());
                let registry =
                    tracing_subscriber::registry().with(subscriber_filter(environment(directives)));
                if json {
                    tracing::subscriber::with_default(
                        registry.with(format.json()),
                        emit_protocol_events,
                    );
                } else {
                    tracing::subscriber::with_default(registry.with(format), emit_protocol_events);
                }
                assert_capture(&capture.text(), debug);
            }
        }
    }

    #[cfg(feature = "telemetry")]
    #[derive(Clone, Debug, Default)]
    struct CaptureExporter(Arc<Mutex<Vec<opentelemetry_sdk::trace::SpanData>>>);

    #[cfg(feature = "telemetry")]
    impl opentelemetry_sdk::trace::SpanExporter for CaptureExporter {
        fn export(
            &self,
            batch: Vec<opentelemetry_sdk::trace::SpanData>,
        ) -> impl std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send
        {
            self.0.lock().unwrap().extend(batch);
            std::future::ready(Ok(()))
        }
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn protocol_payload_filter_captures_otel_and_console_without_raw_arguments() {
        use opentelemetry_sdk::trace::SdkTracerProvider;

        for &(directives, debug) in CONFIGURATIONS {
            for json in [false, true] {
                let exporter = CaptureExporter::default();
                let provider = SdkTracerProvider::builder()
                    .with_simple_exporter(exporter.clone())
                    .build();
                let capture = Capture::default();
                let writer = capture.clone();
                let format = tracing_subscriber::fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_writer(move || writer.clone());
                let registry = tracing_subscriber::registry()
                    .with(subscriber_filter(environment(directives)))
                    .with(otel::otel_layer(&provider));
                if json {
                    tracing::subscriber::with_default(
                        registry.with(format.json()),
                        emit_protocol_events,
                    );
                } else {
                    tracing::subscriber::with_default(registry.with(format), emit_protocol_events);
                }
                provider.force_flush().unwrap();
                assert_capture(&capture.text(), debug);
                let spans = exporter.0.lock().unwrap();
                assert!(!spans.is_empty());
                let events = spans
                    .iter()
                    .flat_map(|span| span.events.events.iter())
                    .map(|event| format!("{:?}", event))
                    .collect::<Vec<_>>()
                    .join("\n");
                assert_capture(&events, debug);
                drop(spans);
                provider.shutdown().unwrap();
            }
        }
    }
}
