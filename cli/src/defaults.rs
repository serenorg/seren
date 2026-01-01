/// Default configuration values
///
/// These values are automatically selected based on build profile:
/// - Debug builds (`cargo build`): API `http://localhost:8080`, OAuth `http://localhost:3000`
/// - Release builds (`cargo build --release`): `https://api.serendb.com`
///
/// Runtime overrides are available via:
/// - `SEREN_API_HOST` environment variable
/// - `SEREN_OAUTH_HOST` environment variable
/// - `--api-host` command-line flag
///
/// Default API host URL
/// - Debug builds: http://localhost:8080
/// - Release builds: https://api.serendb.com
pub const DEFAULT_API_HOST: &str = if cfg!(debug_assertions) {
    "http://localhost:8080"
} else {
    "https://api.serendb.com"
};

/// Default OAuth host URL
/// - Debug builds: http://localhost:3000
/// - Release builds: https://api.serendb.com
pub const DEFAULT_OAUTH_HOST: &str = if cfg!(debug_assertions) {
    "http://localhost:3000"
} else {
    "https://api.serendb.com"
};

/// Default OAuth client ID (same for all builds)
pub const DEFAULT_CLIENT_ID: &str = "seren-cli";

/// Normalize a CLI API host value.
///
/// The CLI treats `SEREN_API_HOST` / `--api-host` as a host (no `/api` suffix).
/// For backward compatibility, a trailing `/api` is stripped.
pub fn normalize_api_host(api_host: &str) -> String {
    let host = api_host.trim().trim_end_matches('/');
    host.strip_suffix("/api")
        .unwrap_or(host)
        .trim_end_matches('/')
        .to_string()
}

/// Convert a CLI API host value into the SDK base URL.
///
/// Note: The generated SDK methods already include the `/api/...` path prefix,
/// so the SDK base URL should *not* include `/api`.
pub fn api_base_url(api_host: &str) -> String {
    normalize_api_host(api_host)
}
