-- OAuth token storage schema for Seren MCP Server
-- This schema stores OAuth2 tokens, authorization codes, and client registrations
-- for the hosted MCP server mode.

CREATE SCHEMA mcp_oauth;

-- OAuth2 Clients (registered MCP clients like Claude Desktop, Cursor, etc.)
CREATE TABLE mcp_oauth.clients (
    id text PRIMARY KEY,
    name text NOT NULL,
    secret_hash text, -- NULL for public clients (PKCE)
    redirect_uris text[] NOT NULL DEFAULT '{}',
    grants text[] NOT NULL DEFAULT '{authorization_code}',
    scopes text[] NOT NULL DEFAULT '{api}',
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
    code_challenge_method text NOT NULL,
    upstream_code_verifier text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- Authorization codes (short-lived, exchanged for tokens)
CREATE TABLE mcp_oauth.authorization_codes (
    code text PRIMARY KEY,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    user_id text NOT NULL,
    redirect_uri text NOT NULL,
    scope text NOT NULL DEFAULT 'api',
    code_challenge text,
    code_challenge_method text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    upstream_access_token text NOT NULL,
    upstream_refresh_token text,
    upstream_expires_at timestamptz NOT NULL
);

-- Access tokens (used for API authentication)
CREATE TABLE mcp_oauth.access_tokens (
    token text PRIMARY KEY,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    user_id text NOT NULL,
    scope text NOT NULL DEFAULT 'api',
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- Refresh tokens (long-lived, used to get new access tokens)
CREATE TABLE mcp_oauth.refresh_tokens (
    token text PRIMARY KEY,
    access_token text NOT NULL REFERENCES mcp_oauth.access_tokens (token) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    user_id text NOT NULL,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- User sessions (tracks OAuth consent and login state)
CREATE TABLE mcp_oauth.sessions (
    id text PRIMARY KEY,
    user_id text NOT NULL,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    state text,
    nonce text,
    data jsonb NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_auth_requests_client ON mcp_oauth.auth_requests (client_id);
CREATE INDEX idx_auth_requests_expires ON mcp_oauth.auth_requests (expires_at);
CREATE INDEX idx_auth_codes_client ON mcp_oauth.authorization_codes (client_id);
CREATE INDEX idx_auth_codes_user ON mcp_oauth.authorization_codes (user_id);
CREATE INDEX idx_auth_codes_expires ON mcp_oauth.authorization_codes (expires_at);
CREATE INDEX idx_access_tokens_client ON mcp_oauth.access_tokens (client_id);
CREATE INDEX idx_access_tokens_user ON mcp_oauth.access_tokens (user_id);
CREATE INDEX idx_access_tokens_expires ON mcp_oauth.access_tokens (expires_at);
CREATE INDEX idx_refresh_tokens_client ON mcp_oauth.refresh_tokens (client_id);
CREATE INDEX idx_refresh_tokens_user ON mcp_oauth.refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_access ON mcp_oauth.refresh_tokens (access_token);
CREATE INDEX idx_sessions_user ON mcp_oauth.sessions (user_id);
CREATE INDEX idx_sessions_client ON mcp_oauth.sessions (client_id);
CREATE INDEX idx_sessions_expires ON mcp_oauth.sessions (expires_at);

-- Function to clean up expired records
CREATE FUNCTION mcp_oauth.cleanup_expired()
    RETURNS void
    AS $$
BEGIN
    DELETE FROM mcp_oauth.auth_requests WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.authorization_codes WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.access_tokens WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.refresh_tokens WHERE expires_at IS NOT NULL AND expires_at < NOW();
    DELETE FROM mcp_oauth.sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Pre-register known MCP clients
-- These are public clients that use PKCE
INSERT INTO mcp_oauth.clients (id, name, redirect_uris, grants, scopes)
VALUES
    ('claude-desktop', 'Claude Desktop', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('claude-code', 'Claude Code', ARRAY['http://localhost:*', 'http://127.0.0.1:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('cursor', 'Cursor', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('windsurf', 'Windsurf', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('vscode', 'VS Code', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('zed', 'Zed', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('continue', 'Continue', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('cline', 'Cline', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('opencode', 'OpenCode', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('codex', 'Codex CLI', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('roo-code', 'Roo Code', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('amp', 'Amp', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']),
    ('kilo-code', 'Kilo Code', ARRAY['http://localhost:*'], ARRAY['authorization_code'], ARRAY['api']);
