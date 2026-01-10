-- Migration: Consolidate mcp_session_tokens and rmcp_sessions into a single mcp_sessions table
--
-- Previously we had two tables tracking MCP sessions:
-- - mcp_session_tokens: auth binding (session_id -> access_token, user_id)
-- - rmcp_sessions: protocol state (session_id -> init request/response)
--
-- This migration consolidates them into a single mcp_sessions table and extends
-- the session retention from 24 hours to 1 year.

-- Create the consolidated sessions table
CREATE TABLE mcp_oauth.mcp_sessions (
    session_id text PRIMARY KEY,

    -- Auth binding (from mcp_session_tokens)
    access_token text,              -- Encrypted access token for Seren API
    client_id text,                 -- OAuth client that created this session
    user_id uuid,                   -- User this session belongs to

    -- Protocol state (from rmcp_sessions)
    initialize_request jsonb,       -- MCP initialize request for session restoration
    initialize_response jsonb,      -- MCP initialize response for session restoration
    protocol_version text,          -- Negotiated MCP protocol version

    -- Timestamps
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    last_activity timestamptz NOT NULL DEFAULT NOW(),
    expires_at timestamptz          -- Token expiry (NULL = no expiry set yet)
);

-- Index for cleanup queries (sessions inactive for 1 year)
CREATE INDEX idx_mcp_sessions_last_activity ON mcp_oauth.mcp_sessions (last_activity);

-- Index for efficient lookup of restorable sessions (have init state)
CREATE INDEX idx_mcp_sessions_restorable ON mcp_oauth.mcp_sessions (session_id)
WHERE initialize_request IS NOT NULL;

-- Index for user session lookups
CREATE INDEX idx_mcp_sessions_user_id ON mcp_oauth.mcp_sessions (user_id)
WHERE user_id IS NOT NULL;

-- Migrate data from both old tables
-- First, insert all rmcp_sessions (they have the protocol state we need)
INSERT INTO mcp_oauth.mcp_sessions (
    session_id,
    initialize_request,
    initialize_response,
    protocol_version,
    created_at,
    last_activity,
    updated_at
)
SELECT
    session_id,
    initialize_request,
    initialize_response,
    protocol_version,
    created_at,
    last_activity,
    last_activity  -- use last_activity as updated_at
FROM mcp_oauth.rmcp_sessions;

-- Then, update with auth data from mcp_session_tokens where available
UPDATE mcp_oauth.mcp_sessions s
SET
    access_token = t.access_token,
    client_id = t.client_id,
    user_id = t.user_id,
    expires_at = t.expires_at,
    updated_at = GREATEST(s.updated_at, t.updated_at)
FROM mcp_oauth.mcp_session_tokens t
WHERE s.session_id = t.session_id;

-- Insert any mcp_session_tokens that don't have a corresponding rmcp_session
INSERT INTO mcp_oauth.mcp_sessions (
    session_id,
    access_token,
    client_id,
    user_id,
    created_at,
    updated_at,
    last_activity,
    expires_at
)
SELECT
    t.session_id,
    t.access_token,
    t.client_id,
    t.user_id,
    t.created_at,
    t.updated_at,
    t.updated_at,  -- use updated_at as last_activity
    t.expires_at
FROM mcp_oauth.mcp_session_tokens t
WHERE NOT EXISTS (
    SELECT 1 FROM mcp_oauth.mcp_sessions s WHERE s.session_id = t.session_id
);

-- Drop the old tables
DROP TABLE mcp_oauth.mcp_session_tokens;
DROP TABLE mcp_oauth.rmcp_sessions;

-- Drop and recreate cleanup function with consolidated table and 1 year retention
DROP FUNCTION mcp_oauth.cleanup_expired (integer);

CREATE FUNCTION mcp_oauth.cleanup_expired (batch_limit integer DEFAULT 1000)
    RETURNS integer
    AS $$
DECLARE
    total_deleted integer := 0;
    deleted_count integer;
BEGIN
    -- Clean auth_requests in batches
    DELETE FROM mcp_oauth.auth_requests
    WHERE id IN (
            SELECT id FROM mcp_oauth.auth_requests
            WHERE expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean pending_consents in batches
    DELETE FROM mcp_oauth.pending_consents
    WHERE id IN (
            SELECT id FROM mcp_oauth.pending_consents
            WHERE expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean authorization_codes in batches
    DELETE FROM mcp_oauth.authorization_codes
    WHERE code IN (
            SELECT code FROM mcp_oauth.authorization_codes
            WHERE expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean refresh_tokens in batches
    DELETE FROM mcp_oauth.refresh_tokens
    WHERE token_hash IN (
            SELECT token_hash FROM mcp_oauth.refresh_tokens
            WHERE expires_at IS NOT NULL AND expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean sessions in batches
    DELETE FROM mcp_oauth.sessions
    WHERE id IN (
            SELECT id FROM mcp_oauth.sessions
            WHERE expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean MCP sessions inactive for more than 1 year
    DELETE FROM mcp_oauth.mcp_sessions
    WHERE session_id IN (
            SELECT session_id FROM mcp_oauth.mcp_sessions
            WHERE last_activity < NOW() - INTERVAL '1 year'
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    RETURN total_deleted;
END;
$$
LANGUAGE plpgsql;

-- Add comments
COMMENT ON TABLE mcp_oauth.mcp_sessions IS
    'Consolidated MCP session storage: auth binding + protocol state for session persistence';
COMMENT ON COLUMN mcp_oauth.mcp_sessions.access_token IS
    'Encrypted access token for calling Seren API on behalf of the user';
COMMENT ON COLUMN mcp_oauth.mcp_sessions.initialize_request IS
    'MCP initialize request (ClientJsonRpcMessage) for session restoration after restart';
COMMENT ON COLUMN mcp_oauth.mcp_sessions.initialize_response IS
    'MCP initialize response (ServerJsonRpcMessage) for session restoration after restart';
