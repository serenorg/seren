-- Session token persistence for MCP sessions
-- Maps MCP session IDs to their associated OAuth access tokens
-- This enables sessions to survive pod restarts

-- MCP Session tokens table
-- Stores the mapping between MCP session IDs and OAuth access tokens
CREATE TABLE mcp_oauth.mcp_session_tokens (
    session_id text PRIMARY KEY,
    access_token text NOT NULL,
    -- Store client_id for tracking/debugging purposes
    client_id text REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    -- Expiry should be slightly longer than access token expiry to allow for refresh
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

-- Note: We don't add a foreign key to access_tokens because:
-- 1. Access tokens get rotated during refresh
-- 2. Access tokens may expire and be cleaned up before sessions
-- 3. The middleware already validates the token independently

-- Indexes
CREATE INDEX idx_mcp_session_tokens_expires ON mcp_oauth.mcp_session_tokens (expires_at);
CREATE INDEX idx_mcp_session_tokens_client ON mcp_oauth.mcp_session_tokens (client_id);
CREATE INDEX idx_mcp_session_tokens_access_token ON mcp_oauth.mcp_session_tokens (access_token);

-- Update the cleanup function to also clean up expired MCP session tokens
CREATE OR REPLACE FUNCTION mcp_oauth.cleanup_expired(batch_limit integer DEFAULT 1000)
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
        LIMIT batch_limit
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean pending_consents in batches
    DELETE FROM mcp_oauth.pending_consents
    WHERE id IN (
        SELECT id FROM mcp_oauth.pending_consents
        WHERE expires_at < NOW()
        LIMIT batch_limit
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean authorization_codes in batches
    DELETE FROM mcp_oauth.authorization_codes
    WHERE code IN (
        SELECT code FROM mcp_oauth.authorization_codes
        WHERE expires_at < NOW()
        LIMIT batch_limit
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean access_tokens in batches
    DELETE FROM mcp_oauth.access_tokens
    WHERE token IN (
        SELECT token FROM mcp_oauth.access_tokens
        WHERE expires_at < NOW()
        LIMIT batch_limit
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean refresh_tokens in batches
    DELETE FROM mcp_oauth.refresh_tokens
    WHERE token IN (
        SELECT token FROM mcp_oauth.refresh_tokens
        WHERE expires_at IS NOT NULL AND expires_at < NOW()
        LIMIT batch_limit
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean sessions in batches
    DELETE FROM mcp_oauth.sessions
    WHERE id IN (
        SELECT id FROM mcp_oauth.sessions
        WHERE expires_at < NOW()
        LIMIT batch_limit
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    -- Clean MCP session tokens in batches
    DELETE FROM mcp_oauth.mcp_session_tokens
    WHERE session_id IN (
        SELECT session_id FROM mcp_oauth.mcp_session_tokens
        WHERE expires_at < NOW()
        LIMIT batch_limit
    );
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;

    RETURN total_deleted;
END;
$$ LANGUAGE plpgsql;
