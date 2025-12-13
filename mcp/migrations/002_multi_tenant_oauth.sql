-- Multi-tenant OAuth upgrade for Seren MCP Server
--
-- This migration switches the hosted MCP OAuth mode from a single-tenant
-- "server API key" model to a true multi-tenant model where the issued access
-- token is the upstream SerenCore per-user bearer token.

-- Clear legacy tokens/codes from the single-tenant model.
-- Those tokens are not valid Seren bearer tokens and will fail API calls.
DELETE FROM mcp_oauth.refresh_tokens;
DELETE FROM mcp_oauth.access_tokens;
DELETE FROM mcp_oauth.authorization_codes;

-- Pending downstream authorization requests (before upstream login completes)
CREATE TABLE IF NOT EXISTS mcp_oauth.auth_requests (
    id text PRIMARY KEY,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scope text NOT NULL DEFAULT 'api',
    client_state text,
    code_challenge text NOT NULL,
    code_challenge_method text NOT NULL,
    upstream_code_verifier text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_requests_client ON mcp_oauth.auth_requests (client_id);

CREATE INDEX IF NOT EXISTS idx_auth_requests_expires ON mcp_oauth.auth_requests (expires_at);

-- Store upstream tokens on the downstream authorization code so /token can
-- return them (pass-through) and persist them to access/refresh token tables.
ALTER TABLE mcp_oauth.authorization_codes
    ADD COLUMN IF NOT EXISTS upstream_access_token text,
    ADD COLUMN IF NOT EXISTS upstream_refresh_token text,
    ADD COLUMN IF NOT EXISTS upstream_expires_at timestamptz;

UPDATE mcp_oauth.authorization_codes
SET
    upstream_access_token = COALESCE(upstream_access_token, ''),
    upstream_expires_at = COALESCE(upstream_expires_at, NOW())
WHERE upstream_access_token IS NULL
   OR upstream_expires_at IS NULL;

ALTER TABLE mcp_oauth.authorization_codes
    ALTER COLUMN upstream_access_token SET NOT NULL,
    ALTER COLUMN upstream_expires_at SET NOT NULL;

-- Access tokens are now the upstream SerenCore bearer tokens (no separate API key column).
ALTER TABLE mcp_oauth.access_tokens
    DROP COLUMN IF EXISTS seren_api_key;

-- Update cleanup function to include auth_requests
CREATE OR REPLACE FUNCTION mcp_oauth.cleanup_expired ()
    RETURNS void
    AS $$
BEGIN
    DELETE FROM mcp_oauth.auth_requests
    WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.authorization_codes
    WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.access_tokens
    WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.refresh_tokens
    WHERE expires_at IS NOT NULL
        AND expires_at < NOW();
    DELETE FROM mcp_oauth.sessions
    WHERE expires_at < NOW();
END;
$$
LANGUAGE plpgsql;
