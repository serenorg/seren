//! Persistent Session Manager for rmcp
//!
//! Wraps rmcp's LocalSessionManager to add PostgreSQL-backed session tracking.
//! This enables detection of stale sessions after server restarts:
//!
//! - When a session is created, its ID is stored in PostgreSQL
//! - When a request comes with a session ID:
//!   - If in-memory session exists → proceed normally
//!   - If not in memory but in DB → session was lost due to restart (stale)
//!   - If not in DB either → unknown session
//!
//! This provides better observability and enables future session recovery features.

use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::server_side_http::{ServerSseMessage, SessionId};
use rmcp::transport::streamable_http_server::session::{
    SessionManager,
    local::{LocalSessionManager, LocalSessionManagerError, LocalSessionWorker},
};
use rmcp::transport::worker::WorkerTransport;
use std::sync::Arc;

use crate::oauth::store::TokenStore;

/// A session manager that wraps LocalSessionManager with PostgreSQL persistence.
///
/// This enables detection of stale sessions after pod restarts by tracking
/// session IDs in the database.
pub struct PersistentSessionManager {
    /// The underlying in-memory session manager
    inner: LocalSessionManager,
    /// PostgreSQL store for session persistence
    store: Arc<TokenStore>,
}

impl PersistentSessionManager {
    /// Create a new PersistentSessionManager wrapping a LocalSessionManager.
    #[allow(dead_code)]
    pub fn new(inner: LocalSessionManager, store: Arc<TokenStore>) -> Self {
        Self { inner, store }
    }

    /// Create a new PersistentSessionManager with default LocalSessionManager.
    #[allow(dead_code)]
    pub fn with_store(store: TokenStore) -> Self {
        Self {
            inner: LocalSessionManager::default(),
            store: Arc::new(store),
        }
    }
}

/// Custom error type that wraps LocalSessionManagerError and adds stale session detection.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Variants are used in tests and for future extension
pub enum PersistentSessionError {
    #[error("Session not found in memory")]
    SessionNotFound(String),

    #[error("Session was lost due to server restart (stale session)")]
    StaleSession(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Inner session manager error: {0}")]
    Inner(#[from] LocalSessionManagerError),
}

impl SessionManager for PersistentSessionManager {
    type Error = PersistentSessionError;
    type Transport = WorkerTransport<LocalSessionWorker>;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        // Create session in the inner manager
        let (session_id, transport) = self.inner.create_session().await?;

        // Store session ID in PostgreSQL for persistence tracking
        // We use a separate table/method to track rmcp sessions
        if let Err(e) = self.store.track_rmcp_session(session_id.as_ref()).await {
            tracing::warn!(
                event = "persistent_session_track_failed",
                session_id = %session_id,
                error = %e,
                "Failed to track session in database (session will still work but won't survive restart)"
            );
        } else {
            tracing::debug!(
                event = "persistent_session_created",
                session_id = %session_id,
                "Session created and tracked in database"
            );
        }

        Ok((session_id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.inner
            .initialize_session(id, message)
            .await
            .map_err(Into::into)
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        // Close in inner manager
        let result = self.inner.close_session(id).await;

        // Remove from PostgreSQL tracking
        if let Err(e) = self.store.untrack_rmcp_session(id.as_ref()).await {
            tracing::warn!(
                event = "persistent_session_untrack_failed",
                session_id = %id,
                error = %e,
                "Failed to remove session from database tracking"
            );
        } else {
            tracing::debug!(
                event = "persistent_session_closed",
                session_id = %id,
                "Session closed and removed from database"
            );
        }

        result.map_err(Into::into)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        // First check in-memory
        let in_memory = self.inner.has_session(id).await?;

        if in_memory {
            return Ok(true);
        }

        // Not in memory - check if it's a stale session (was in DB)
        match self.store.has_rmcp_session(id.as_ref()).await {
            Ok(true) => {
                // Session exists in DB but not in memory → stale session
                tracing::warn!(
                    event = "stale_rmcp_session_detected",
                    session_id = %id,
                    "Session found in database but not in memory - likely lost due to server restart"
                );
                // Return false so rmcp returns 401, but we've logged the stale session
                // The client should reconnect and re-initialize
                Ok(false)
            }
            Ok(false) => {
                // Not in DB either → unknown session
                tracing::debug!(
                    event = "unknown_session",
                    session_id = %id,
                    "Session not found in memory or database"
                );
                Ok(false)
            }
            Err(e) => {
                // Database error - log but don't fail the request
                tracing::warn!(
                    event = "persistent_session_check_failed",
                    session_id = %id,
                    error = %e,
                    "Failed to check session in database, falling back to in-memory only"
                );
                Ok(false)
            }
        }
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner
            .create_stream(id, message)
            .await
            .map_err(Into::into)
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner
            .create_standalone_stream(id)
            .await
            .map_err(Into::into)
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.inner
            .resume(id, last_event_id)
            .await
            .map_err(Into::into)
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        // Update last activity timestamp in database
        if let Err(e) = self.store.touch_rmcp_session(id.as_ref()).await {
            tracing::trace!(
                event = "persistent_session_touch_failed",
                session_id = %id,
                error = %e,
                "Failed to update session activity timestamp"
            );
        }

        self.inner
            .accept_message(id, message)
            .await
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests require a running PostgreSQL database.
    // Unit tests focus on error handling and basic struct behavior.

    #[test]
    fn test_persistent_session_error_display() {
        let err = PersistentSessionError::SessionNotFound("test-123".to_string());
        assert_eq!(err.to_string(), "Session not found in memory");

        let err = PersistentSessionError::StaleSession("test-456".to_string());
        assert_eq!(
            err.to_string(),
            "Session was lost due to server restart (stale session)"
        );

        let err = PersistentSessionError::Database("connection failed".to_string());
        assert_eq!(err.to_string(), "Database error: connection failed");
    }

    #[test]
    fn test_error_conversion_from_local_session_manager_error() {
        let inner_err = LocalSessionManagerError::SessionNotFound(SessionId::from("test-session"));
        let err: PersistentSessionError = inner_err.into();
        assert!(matches!(err, PersistentSessionError::Inner(_)));
    }

    #[test]
    fn test_error_debug_output() {
        let err = PersistentSessionError::SessionNotFound("sess-abc".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("SessionNotFound"));
        assert!(debug_str.contains("sess-abc"));

        let err = PersistentSessionError::Database("db error".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Database"));
        assert!(debug_str.contains("db error"));
    }

    #[test]
    fn test_error_is_send_and_sync() {
        fn assert_send<T: Send>() {}

        // These will fail to compile if the error type doesn't implement Send/Sync
        assert_send::<PersistentSessionError>();
        // Note: Inner error may not be Sync, so we don't test Sync for the outer error
    }

    #[test]
    fn test_persistent_session_manager_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        // PersistentSessionManager must be Send + Sync for async usage
        assert_send::<PersistentSessionManager>();
        assert_sync::<PersistentSessionManager>();
    }

    #[test]
    fn test_session_id_string_conversion() {
        // Test that SessionId can be converted to string for database storage
        let session_id = SessionId::from("test-session-id");
        let as_string = session_id.to_string();
        assert_eq!(as_string, "test-session-id");
    }

    #[test]
    fn test_all_error_variants_have_unique_messages() {
        let errors = [
            PersistentSessionError::SessionNotFound("x".to_string()),
            PersistentSessionError::StaleSession("x".to_string()),
            PersistentSessionError::Database("x".to_string()),
            PersistentSessionError::Inner(LocalSessionManagerError::SessionNotFound(
                SessionId::from("x"),
            )),
        ];

        let messages: Vec<String> = errors.iter().map(|e| e.to_string()).collect();

        // Ensure all error messages are unique
        for (i, msg1) in messages.iter().enumerate() {
            for (j, msg2) in messages.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        msg1, msg2,
                        "Error variants {} and {} have identical messages",
                        i, j
                    );
                }
            }
        }
    }

    // Integration tests that would require a database are below.
    // These are marked as ignored by default and can be run with:
    // cargo test --package seren-mcp persistent_session -- --ignored

    #[tokio::test]
    #[ignore = "requires DATABASE_URL environment variable"]
    async fn test_persistent_session_manager_create_session() {
        // This test requires a running PostgreSQL database
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for this test");
        let store = TokenStore::connect(&database_url)
            .await
            .expect("Failed to connect to database");
        let manager = PersistentSessionManager::with_store(store);

        // Create a session
        let result = manager.create_session().await;
        assert!(
            result.is_ok(),
            "Failed to create session: {}",
            result
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );

        let (session_id, _transport) = result.unwrap();
        assert!(!session_id.to_string().is_empty());

        // Verify session exists
        let has_session = manager.has_session(&session_id).await;
        assert!(has_session.is_ok());
        assert!(has_session.unwrap(), "Session should exist after creation");

        // Close the session
        let close_result = manager.close_session(&session_id).await;
        assert!(close_result.is_ok(), "Failed to close session");

        // Note: has_session will return false since session is closed in memory
        // but may still be in DB briefly (cleanup is async)
    }

    #[tokio::test]
    #[ignore = "requires DATABASE_URL environment variable"]
    async fn test_persistent_session_stale_detection() {
        // This test verifies that stale sessions (in DB but not in memory) are detected
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for this test");
        let store = TokenStore::connect(&database_url)
            .await
            .expect("Failed to connect to database");

        // Manually insert a session into the database without creating it in memory
        let fake_session_id = format!("stale-test-{}", uuid::Uuid::new_v4());
        let _ = store.track_rmcp_session(&fake_session_id).await;

        // Create a new manager (simulating a server restart)
        let manager = PersistentSessionManager::with_store(store.clone());

        // Check for the stale session
        let session_id = SessionId::from(fake_session_id.as_str());
        let has_session = manager.has_session(&session_id).await;

        // Should return false (not in memory) but the stale detection should be logged
        assert!(has_session.is_ok());
        assert!(
            !has_session.unwrap(),
            "Stale session should return false for has_session"
        );

        // Cleanup
        let _ = store.untrack_rmcp_session(&fake_session_id).await;
    }
}
