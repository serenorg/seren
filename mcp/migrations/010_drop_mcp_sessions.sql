-- Retire mcp_oauth.mcp_sessions: no code reads or writes it, and its access_token column held
-- unencrypted signed tokens. Recreate cleanup_expired without it.
DROP TABLE mcp_oauth.mcp_sessions;

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

    RETURN total_deleted;
END;
$$
LANGUAGE plpgsql;
