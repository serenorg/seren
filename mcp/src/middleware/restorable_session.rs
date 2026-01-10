//! Restorable Session Manager for rmcp
//!
//! This SessionManager implementation provides full session persistence across
//! server restarts. When a session is detected in the database but not in memory,
//! it is automatically restored by:
//! 1. Creating a new session with the original session ID
//! 2. Spawning a new service instance for the session
//! 3. Replaying the stored initialization message
//!
//! This allows clients to continue using their existing session ID without
//! needing to reconnect after server restarts.

use std::collections::HashMap;
use std::sync::Arc;

use futures::Stream;
use rmcp::model::{
    ClientJsonRpcMessage, ClientNotification, InitializedNotification, ServerJsonRpcMessage,
};
use rmcp::serve_server;
use rmcp::transport::common::server_side_http::{ServerSseMessage, SessionId};
use rmcp::transport::streamable_http_server::session::SessionManager;
use rmcp::transport::streamable_http_server::session::local::{
    EventId, LocalSessionHandle, LocalSessionManagerError, LocalSessionWorker, SessionConfig,
    SessionError, create_local_session,
};
use rmcp::transport::worker::WorkerTransport;
use time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::ReceiverStream;

use crate::oauth::store::TokenStore;
use crate::server::SerenMcpServer;

/// A session manager that persists session state to PostgreSQL and can restore
/// sessions after server restarts.
pub struct RestorableSessionManager {
    /// In-memory session storage
    sessions: RwLock<HashMap<SessionId, LocalSessionHandle>>,
    /// Session configuration for creating new sessions
    session_config: SessionConfig,
    /// PostgreSQL store for persistence
    store: Arc<TokenStore>,
    /// Per-session restoration locks to prevent race conditions
    restoration_locks: Mutex<HashMap<SessionId, Arc<Mutex<()>>>>,
    /// API base URL for creating service instances
    api_base_url: String,
}

/// Errors that can occur during session operations.
#[derive(Debug, thiserror::Error)]
pub enum RestorableSessionError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session expired or invalid")]
    #[allow(dead_code)]
    SessionExpired,

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Restoration failed: {0}")]
    RestorationFailed(String),

    #[error("Service creation failed: {0}")]
    ServiceCreation(String),

    #[error("Inner session error: {0}")]
    Inner(#[from] LocalSessionManagerError),

    #[error("Session error: {0}")]
    Session(#[from] SessionError),
}

impl RestorableSessionManager {
    /// Create a new RestorableSessionManager.
    ///
    /// # Arguments
    /// * `store` - PostgreSQL token store for session persistence
    /// * `session_config` - Configuration for rmcp sessions
    /// * `api_base_url` - Base URL for creating SerenMcpServer instances
    pub fn new(
        store: Arc<TokenStore>,
        session_config: SessionConfig,
        api_base_url: String,
    ) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            session_config,
            store,
            restoration_locks: Mutex::new(HashMap::new()),
            api_base_url,
        }
    }

    /// Attempt to restore a session from database state.
    ///
    /// This method:
    /// 1. Acquires a per-session lock to prevent concurrent restoration
    /// 2. Creates a new session with the original session ID
    /// 3. Spawns a new service instance
    /// 4. Replays the stored initialization message
    async fn restore_session(&self, id: &SessionId) -> Result<(), RestorableSessionError> {
        // Acquire per-session lock to prevent concurrent restoration attempts
        let lock = {
            let mut locks = self.restoration_locks.lock().await;
            locks
                .entry(id.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        // Double-check after acquiring lock (another request may have restored it)
        if self.sessions.read().await.contains_key(id) {
            return Ok(());
        }

        // Load session state from database
        let state = self
            .store
            .get_rmcp_session_state(id.as_ref())
            .await
            .map_err(|e| RestorableSessionError::Database(e.to_string()))?
            .ok_or_else(|| {
                RestorableSessionError::RestorationFailed(
                    "Session state not found in database".into(),
                )
            })?;

        // Create new session infrastructure with the SAME session ID
        let (handle, worker) = create_local_session(id.clone(), self.session_config.clone());

        // Spawn the worker transport
        let transport = WorkerTransport::spawn(worker);

        // Create a new service instance
        let service = SerenMcpServer::new_oauth(&self.api_base_url)
            .map_err(|e| RestorableSessionError::ServiceCreation(e.to_string()))?;

        // Spawn the service task to handle MCP requests and wait for it to finish the
        // MCP handshake (initialize + initialized).
        //
        // If service startup fails, leaving the restored handle in-memory will cause
        // HTTP 500s ("Session service terminated") on subsequent requests.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let session_id_for_logs = id.clone();
        tokio::spawn(async move {
            match serve_server(service, transport).await {
                Ok(running_service) => {
                    let _ = ready_tx.send(Ok(()));
                    let _ = running_service.waiting().await;
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    tracing::error!(
                        event = "restored_service_spawn_failed",
                        session_id = %session_id_for_logs,
                        error = %e,
                        "Failed to spawn restored service"
                    );
                }
            }
        });

        // Parse and replay the stored initialization request
        // Note: initialize_request is guaranteed to be Some because get_session_for_restore
        // filters for `initialize_request IS NOT NULL`
        let init_request: ClientJsonRpcMessage =
            serde_json::from_value(state.initialize_request.ok_or_else(|| {
                RestorableSessionError::RestorationFailed("Missing initialize_request".into())
            })?)
            .map_err(|e| RestorableSessionError::Serialization(e.to_string()))?;

        // Replay initialization to set up the session state.
        // Use timeout to avoid hanging forever if the spawned service dies before responding.
        let _init_response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            handle.initialize(init_request),
        )
        .await
        .map_err(|_| {
            RestorableSessionError::RestorationFailed(
                "Timed out waiting for initialization response".into(),
            )
        })?
        .map_err(|e| RestorableSessionError::RestorationFailed(e.to_string()))?;

        // MCP handshake requires the client to send `notifications/initialized` after `initialize`.
        //
        // Clients will not resend this after a server restart, so restoration must do it, otherwise
        // the restored service will reject subsequent requests (e.g. tool calls) with errors like:
        // "expect initialized notification, but received: CallToolRequest".
        handle
            .push_message(
                ClientJsonRpcMessage::notification(ClientNotification::InitializedNotification(
                    InitializedNotification {
                        method: Default::default(),
                        extensions: Default::default(),
                    },
                )),
                None,
            )
            .await?;

        match tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => {
                return Err(RestorableSessionError::RestorationFailed(format!(
                    "Restored service failed to start: {}",
                    e
                )));
            }
            Ok(Err(_closed)) => {
                return Err(RestorableSessionError::RestorationFailed(
                    "Restored service failed to start (start signal dropped)".into(),
                ));
            }
            Err(_elapsed) => {
                return Err(RestorableSessionError::RestorationFailed(
                    "Timed out waiting for restored service to start".into(),
                ));
            }
        }

        // Add the restored session to in-memory map
        self.sessions.write().await.insert(id.clone(), handle);

        // Update last activity timestamp
        let _ = self.store.touch_rmcp_session(id.as_ref()).await;

        tracing::info!(
            event = "session_restored",
            session_id = %id,
            "Session successfully restored from database"
        );

        Ok(())
    }

    async fn session_handle(
        &self,
        id: &SessionId,
    ) -> Result<LocalSessionHandle, RestorableSessionError> {
        if let Some(handle) = self.sessions.read().await.get(id).cloned() {
            return Ok(handle);
        }
        self.restore_session(id).await?;
        self.sessions
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| RestorableSessionError::SessionNotFound(id.to_string()))
    }

    async fn restore_after_terminated(
        &self,
        id: &SessionId,
    ) -> Result<LocalSessionHandle, RestorableSessionError> {
        self.sessions.write().await.remove(id);
        self.restore_session(id).await?;
        self.sessions
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| RestorableSessionError::SessionNotFound(id.to_string()))
    }
}

impl SessionManager for RestorableSessionManager {
    type Error = RestorableSessionError;
    type Transport = WorkerTransport<LocalSessionWorker>;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        // Generate a new session ID
        let id: SessionId = uuid::Uuid::new_v4().to_string().into();

        // Create session infrastructure
        let (handle, worker) = create_local_session(id.clone(), self.session_config.clone());

        // Store handle in memory
        self.sessions.write().await.insert(id.clone(), handle);

        // Track in database (initialization state saved later during initialize_session)
        if let Err(e) = self.store.track_rmcp_session(id.as_ref()).await {
            tracing::warn!(
                event = "session_track_failed",
                session_id = %id,
                error = %e,
                "Failed to track session in database"
            );
        }

        tracing::debug!(
            event = "session_created",
            session_id = %id,
            "New session created"
        );

        Ok((id, WorkerTransport::spawn(worker)))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        let handle = self
            .sessions
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| RestorableSessionError::SessionNotFound(id.to_string()))?;

        // Process the initialization message
        let response = handle.initialize(message.clone()).await?;

        // Persist initialization state for future restoration
        let init_request = serde_json::to_value(&message)
            .map_err(|e| RestorableSessionError::Serialization(e.to_string()))?;
        let init_response = serde_json::to_value(&response)
            .map_err(|e| RestorableSessionError::Serialization(e.to_string()))?;

        // Extract protocol version from the response if available
        // The protocol version is in the result.protocolVersion field
        let protocol_version: Option<String> = None; // TODO: extract from response if needed

        if let Err(e) = self
            .store
            .save_rmcp_session_state(
                id.as_ref(),
                &init_request,
                &init_response,
                protocol_version.as_deref(),
            )
            .await
        {
            tracing::warn!(
                event = "session_state_save_failed",
                session_id = %id,
                error = %e,
                "Failed to save session state (session will not survive restart)"
            );
        } else {
            tracing::debug!(
                event = "session_state_saved",
                session_id = %id,
                "Session initialization state saved for restoration"
            );
        }

        Ok(response)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        // Check in-memory first
        if self.sessions.read().await.contains_key(id) {
            // Best-effort keepalive: prevent active sessions from being cleaned up
            // by the DB retention policy.
            let _ = self
                .store
                .touch_rmcp_session_if_older_than(id.as_ref(), Duration::hours(1))
                .await;
            return Ok(true);
        }

        // Not in memory - check if we can restore from database
        match self.store.get_rmcp_session_state(id.as_ref()).await {
            Ok(Some(_state)) => {
                // Session exists in DB with initialization state - attempt restoration
                match self.restore_session(id).await {
                    Ok(()) => {
                        tracing::info!(
                            event = "session_restored_on_check",
                            session_id = %id,
                            "Session restored from database during has_session check"
                        );
                        Ok(true)
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "session_restore_failed",
                            session_id = %id,
                            error = %e,
                            "Failed to restore session, client must reconnect"
                        );
                        Ok(false)
                    }
                }
            }
            Ok(None) => {
                // Check if it's a tracked but non-restorable session (no init state)
                match self.store.has_rmcp_session(id.as_ref()).await {
                    Ok(true) => {
                        tracing::warn!(
                            event = "stale_session_no_state",
                            session_id = %id,
                            "Session tracked but has no restoration state"
                        );
                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            Err(e) => {
                tracing::warn!(
                    event = "session_state_lookup_failed",
                    session_id = %id,
                    error = %e,
                    "Database error checking session state"
                );
                Ok(false)
            }
        }
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        // Remove from memory
        if let Some(handle) = self.sessions.write().await.remove(id) {
            let _ = handle.close().await;
        }

        // Note: We intentionally do NOT delete the DB session record here.
        //
        // rmcp calls `close_session` when the in-process service task exits (including
        // graceful shutdowns). If we delete the DB record here, the session cannot be
        // restored after a restart. Stale DB rows are cleaned up by `mcp_oauth.cleanup_expired`.

        // Clean up restoration lock
        self.restoration_locks.lock().await.remove(id);

        tracing::debug!(
            event = "session_closed",
            session_id = %id,
            "Session closed (in-memory only)"
        );

        Ok(())
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        // Best-effort recovery: if the in-memory session exists but the service died,
        // restore from DB state and retry once to avoid returning HTTP 500s.
        let mut attempt = 0;
        loop {
            attempt += 1;

            let handle = self.session_handle(id).await?;
            let receiver = match handle.establish_request_wise_channel().await {
                Ok(r) => r,
                Err(SessionError::SessionServiceTerminated) if attempt == 1 => {
                    tracing::warn!(
                        event = "session_recover_service_terminated",
                        session_id = %id,
                        "Session service terminated; attempting restore"
                    );
                    self.restore_after_terminated(id).await?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            match handle
                .push_message(message.clone(), receiver.http_request_id)
                .await
            {
                Ok(()) => return Ok(ReceiverStream::new(receiver.inner)),
                Err(SessionError::SessionServiceTerminated) if attempt == 1 => {
                    tracing::warn!(
                        event = "session_recover_service_terminated",
                        session_id = %id,
                        "Session service terminated; attempting restore"
                    );
                    self.restore_after_terminated(id).await?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let handle = self.session_handle(id).await?;
        match handle.establish_common_channel().await {
            Ok(receiver) => Ok(ReceiverStream::new(receiver.inner)),
            Err(SessionError::SessionServiceTerminated) => {
                tracing::warn!(
                    event = "session_recover_service_terminated",
                    session_id = %id,
                    "Session service terminated; attempting restore"
                );
                let handle = self.restore_after_terminated(id).await?;
                let receiver = handle.establish_common_channel().await?;
                Ok(ReceiverStream::new(receiver.inner))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        let event_id: EventId = last_event_id.parse().map_err(|e| {
            RestorableSessionError::RestorationFailed(format!("Invalid event ID: {}", e))
        })?;
        let handle = self.session_handle(id).await?;
        match handle.resume(event_id.clone()).await {
            Ok(receiver) => Ok(ReceiverStream::new(receiver.inner)),
            Err(SessionError::SessionServiceTerminated) => {
                tracing::warn!(
                    event = "session_recover_service_terminated",
                    session_id = %id,
                    "Session service terminated; attempting restore"
                );
                let handle = self.restore_after_terminated(id).await?;
                let receiver = handle.resume(event_id).await?;
                Ok(ReceiverStream::new(receiver.inner))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        // Update last activity timestamp (throttled)
        let _ = self
            .store
            .touch_rmcp_session_if_older_than(id.as_ref(), Duration::hours(1))
            .await;

        let handle = self.session_handle(id).await?;
        match handle.push_message(message.clone(), None).await {
            Ok(()) => {}
            Err(SessionError::SessionServiceTerminated) => {
                tracing::warn!(
                    event = "session_recover_service_terminated",
                    session_id = %id,
                    "Session service terminated; attempting restore"
                );
                let handle = self.restore_after_terminated(id).await?;
                handle.push_message(message, None).await?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}
