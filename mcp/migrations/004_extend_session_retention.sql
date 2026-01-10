-- Migration: Extend rmcp session retention from 24 hours to 1 year
--
-- Sessions should persist as long as possible to avoid forcing users to
-- re-authenticate. The 1-hour touch throttle keeps active sessions alive,
-- and this change ensures inactive sessions survive for up to a year.

-- Drop the existing cleanup function
DROP FUNCTION mcp_oauth.cleanup_expired (integer);

-- Recreate with 1 year retention for rmcp sessions
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
    -- Clean rmcp sessions inactive for more than 1 year
    DELETE FROM mcp_oauth.rmcp_sessions
    WHERE session_id IN (
            SELECT
                session_id
            FROM
                mcp_oauth.rmcp_sessions
            WHERE
                last_activity < NOW() - INTERVAL '1 year'
            LIMIT batch_limit);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    total_deleted := total_deleted + deleted_count;
    RETURN total_deleted;
END;
$$
LANGUAGE plpgsql;
