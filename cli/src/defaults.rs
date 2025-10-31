/// Default configuration values
///
/// These values are automatically selected based on build profile:
/// - Debug builds (`cargo build`): Use localhost:3000 (developer-friendly)
/// - Release builds (`cargo build --release`): Use production URLs (api.serendb.com)
///
/// Runtime overrides are available via:
/// - `SEREN_API_HOST` environment variable
/// - `--api-host` command-line flag

/// Default API host URL
/// - Debug builds: http://localhost:3000
/// - Release builds: https://api.serendb.com
pub const DEFAULT_API_HOST: &str = if cfg!(debug_assertions) {
    "http://localhost:3000"
} else {
    "https://api.serendb.com"
};

/// Default OAuth host URL
/// - Debug builds: http://localhost:3000
/// - Release builds: https://oauth.serendb.com
pub const DEFAULT_OAUTH_HOST: &str = if cfg!(debug_assertions) {
    "http://localhost:3000"
} else {
    "https://oauth.serendb.com"
};

/// Default OAuth client ID (same for all builds)
pub const DEFAULT_CLIENT_ID: &str = "seren-cli";
