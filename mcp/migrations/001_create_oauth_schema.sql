-- OAuth token storage schema for Seren MCP Server
-- This schema stores OAuth2 tokens, authorization codes, and client registrations
-- for the hosted MCP server mode.
--
-- Architecture: MCP issues its own tokens to clients. Upstream tokens
-- are stored server-side and used internally for API calls. Clients never see
-- upstream tokens directly.

CREATE SCHEMA mcp_oauth;

-- PKCE code challenge methods (RFC 7636)
CREATE TYPE mcp_oauth.pkce_method AS ENUM ('plain', 'S256');

-- OAuth2 Clients (dynamically registered via RFC 7591)
CREATE TABLE mcp_oauth.clients (
    id text PRIMARY KEY,
    name text NOT NULL,
    secret_hash text, -- NULL for public clients (PKCE)
    redirect_uris text[] NOT NULL DEFAULT '{}',
    grants text[] NOT NULL DEFAULT '{authorization_code}',
    scopes text[] NOT NULL DEFAULT '{api}',
    -- Optional metadata (RFC 7591)
    client_uri text,           -- Homepage URL
    software_id text,          -- Unique software identifier (e.g., "com.anthropic.claude-desktop")
    software_version text,     -- Version string
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

-- Pending authorization requests (before upstream login completes)
CREATE TABLE mcp_oauth.auth_requests (
    id text PRIMARY KEY,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scope text NOT NULL DEFAULT 'api',
    client_state text,
    code_challenge text NOT NULL,
    code_challenge_method mcp_oauth.pkce_method NOT NULL,
    upstream_code_verifier text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- Authorization codes (short-lived, exchanged for tokens)
CREATE TABLE mcp_oauth.authorization_codes (
    code text PRIMARY KEY,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    scope text NOT NULL DEFAULT 'api',
    code_challenge text,
    code_challenge_method mcp_oauth.pkce_method,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    -- Upstream tokens (temporarily stored during code exchange)
    upstream_access_token text NOT NULL,
    upstream_refresh_token text,
    upstream_expires_at timestamptz NOT NULL
);

-- MCP refresh tokens with server-side upstream token storage
-- The MCP refresh token is what clients use; upstream tokens are used internally
CREATE TABLE mcp_oauth.refresh_tokens (
    token text PRIMARY KEY,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    scope text NOT NULL DEFAULT 'api',
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    -- Upstream token vault (server-side only, never exposed to clients)
    upstream_access_token text NOT NULL,
    upstream_refresh_token text,
    upstream_expires_at timestamptz NOT NULL
);

-- User sessions (tracks OAuth consent and login state)
CREATE TABLE mcp_oauth.sessions (
    id text PRIMARY KEY,
    user_id uuid NOT NULL,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    state text,
    nonce text,
    data jsonb NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- Clients approved by a given Seren user (per-client consent)
CREATE TABLE mcp_oauth.approved_clients (
    user_id uuid NOT NULL,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    approved_at timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, client_id)
);

-- Pending user consent step during the OAuth callback flow
CREATE TABLE mcp_oauth.pending_consents (
    id text PRIMARY KEY,
    user_id uuid NOT NULL,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    authorization_code text NOT NULL REFERENCES mcp_oauth.authorization_codes (code) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    client_state text,
    scope text NOT NULL DEFAULT 'api',
    csrf_token text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- MCP Session tokens (maps MCP session IDs to MCP access tokens for pod restart survival)
CREATE TABLE mcp_oauth.mcp_session_tokens (
    session_id text PRIMARY KEY,
    access_token text NOT NULL,
    client_id text REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_auth_requests_client ON mcp_oauth.auth_requests (client_id);
CREATE INDEX idx_auth_requests_expires ON mcp_oauth.auth_requests (expires_at);
CREATE INDEX idx_auth_codes_client ON mcp_oauth.authorization_codes (client_id);
CREATE INDEX idx_auth_codes_user ON mcp_oauth.authorization_codes (user_id);
CREATE INDEX idx_auth_codes_expires ON mcp_oauth.authorization_codes (expires_at);
CREATE INDEX idx_refresh_tokens_client ON mcp_oauth.refresh_tokens (client_id);
CREATE INDEX idx_refresh_tokens_user ON mcp_oauth.refresh_tokens (user_id);
CREATE INDEX idx_sessions_user ON mcp_oauth.sessions (user_id);
CREATE INDEX idx_sessions_client ON mcp_oauth.sessions (client_id);
CREATE INDEX idx_sessions_expires ON mcp_oauth.sessions (expires_at);
CREATE INDEX idx_approved_clients_user ON mcp_oauth.approved_clients (user_id);
CREATE INDEX idx_pending_consents_client ON mcp_oauth.pending_consents (client_id);
CREATE INDEX idx_pending_consents_user ON mcp_oauth.pending_consents (user_id);
CREATE INDEX idx_pending_consents_expires ON mcp_oauth.pending_consents (expires_at);
CREATE INDEX idx_mcp_session_tokens_expires ON mcp_oauth.mcp_session_tokens (expires_at);
CREATE INDEX idx_mcp_session_tokens_client ON mcp_oauth.mcp_session_tokens (client_id);
CREATE INDEX idx_mcp_session_tokens_access_token ON mcp_oauth.mcp_session_tokens (access_token);
CREATE INDEX idx_mcp_session_tokens_user ON mcp_oauth.mcp_session_tokens (user_id);

-- Function to clean up expired records (batched to prevent table locks)
CREATE FUNCTION mcp_oauth.cleanup_expired(batch_limit integer DEFAULT 1000)
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
