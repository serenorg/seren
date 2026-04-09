/// Default configuration values
///
/// These values are automatically selected based on build profile:
/// - Debug builds (`cargo build`): API `http://localhost:8080`, OAuth `http://localhost:3000`
/// - Release builds (`cargo build --release`): `https://api.serendb.com`
///
/// Runtime overrides are available via:
/// - `SEREN_API_BASE` environment variable
/// - `SEREN_OAUTH_HOST` environment variable
/// - `--api-base` command-line flag
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

pub fn env_api_host_override() -> Option<String> {
    std::env::var("SEREN_API_BASE")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub fn runtime_api_host() -> String {
    env_api_host_override().unwrap_or_else(|| DEFAULT_API_HOST.to_string())
}

/// Normalize a CLI API base value.
///
/// The CLI treats `SEREN_API_BASE` / `--api-base` as a base URL (no `/api` suffix).
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
/// Note: The generated SDK methods already include the `/...` path prefix,
/// so the SDK base URL should *not* include `/api`.
pub fn api_base_url(api_host: &str) -> String {
    normalize_api_host(api_host)
}
