-- rmcp session tracking for persistence across server restarts
--
-- This table tracks active rmcp sessions to enable detection of stale sessions
-- after server restarts. When a client sends a request with a session ID that
-- exists in this table but not in memory, we know it's a stale session.
--
-- Note: This is separate from mcp_session_tokens which stores OAuth tokens.
-- This table tracks the rmcp transport layer sessions.
-- rmcp session metadata (lightweight tracking for stale session detection)
CREATE TABLE mcp_oauth.rmcp_sessions (
    session_id text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    last_activity timestamptz NOT NULL DEFAULT NOW()
);

-- Index for cleanup queries
CREATE INDEX idx_rmcp_sessions_last_activity ON mcp_oauth.rmcp_sessions (last_activity);

-- Drop the existing cleanup function so we can recreate it with rmcp cleanup added
DROP FUNCTION mcp_oauth.cleanup_expired (integer);

-- Recreate cleanup function with rmcp_sessions cleanup added
-- We clean up sessions that haven't had activity in 24 hours
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
            SELECT
                id
            FROM
                mcp_oauth.auth_requests
            WHERE
                expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    -- Clean pending_consents in batches
    DELETE FROM mcp_oauth.pending_consents
    WHERE id IN (
            SELECT
                id
            FROM
                mcp_oauth.pending_consents
            WHERE
                expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    -- Clean authorization_codes in batches
    DELETE FROM mcp_oauth.authorization_codes
    WHERE code IN (
            SELECT
                code
            FROM
                mcp_oauth.authorization_codes
            WHERE
                expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    -- Clean refresh_tokens in batches
    DELETE FROM mcp_oauth.refresh_tokens
    WHERE token_hash IN (
            SELECT
                token_hash
            FROM
                mcp_oauth.refresh_tokens
            WHERE
                expires_at IS NOT NULL
                AND expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    -- Clean sessions in batches
    DELETE FROM mcp_oauth.sessions
    WHERE id IN (
            SELECT
                id
            FROM
                mcp_oauth.sessions
            WHERE
                expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    -- Clean MCP session tokens in batches
    DELETE FROM mcp_oauth.mcp_session_tokens
    WHERE session_id IN (
            SELECT
                session_id
            FROM
                mcp_oauth.mcp_session_tokens
            WHERE
                expires_at < NOW()
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    -- Clean rmcp sessions inactive for more than 24 hours
    DELETE FROM mcp_oauth.rmcp_sessions
    WHERE session_id IN (
            SELECT
                session_id
            FROM
                mcp_oauth.rmcp_sessions
            WHERE
                last_activity < NOW() - INTERVAL '24 hours'
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    RETURN total_deleted;
END;
$$
LANGUAGE plpgsql;
