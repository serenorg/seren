-- Migration: Add session state columns for restoration after server restarts
--
-- This migration adds columns to store MCP initialization state, enabling
-- sessions to be restored transparently when clients reconnect after a
-- server restart. Instead of returning 401 (stale session), we can replay
-- the initialization and continue the session.

-- Add columns to store initialization state for restoration
ALTER TABLE mcp_oauth.rmcp_sessions
ADD COLUMN initialize_request jsonb,
ADD COLUMN initialize_response jsonb,
ADD COLUMN protocol_version text;

-- Index for efficient lookup of restorable sessions
-- Only sessions with stored initialization state can be restored
CREATE INDEX idx_rmcp_sessions_restorable
ON mcp_oauth.rmcp_sessions (session_id)
WHERE initialize_request IS NOT NULL;

-- Add comment explaining the columns
COMMENT ON COLUMN mcp_oauth.rmcp_sessions.initialize_request IS
    'The MCP initialize request (ClientJsonRpcMessage) for session restoration';
COMMENT ON COLUMN mcp_oauth.rmcp_sessions.initialize_response IS
    'The MCP initialize response (ServerJsonRpcMessage) for session restoration';
COMMENT ON COLUMN mcp_oauth.rmcp_sessions.protocol_version IS
    'Negotiated MCP protocol version (e.g., "2024-11-05")';
