-- Add per-user client consent tracking for Seren MCP OAuth server.

-- Clients approved by a given Seren user (per-client consent).
CREATE TABLE IF NOT EXISTS mcp_oauth.approved_clients (
    user_id text NOT NULL,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    approved_at timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, client_id)
);

-- Pending user consent step during the OAuth callback flow.
CREATE TABLE IF NOT EXISTS mcp_oauth.pending_consents (
    id text PRIMARY KEY,
    user_id text NOT NULL,
    client_id text NOT NULL REFERENCES mcp_oauth.clients (id) ON DELETE CASCADE,
    authorization_code text NOT NULL REFERENCES mcp_oauth.authorization_codes (code) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    client_state text,
    scope text NOT NULL DEFAULT 'api',
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_approved_clients_user ON mcp_oauth.approved_clients (user_id);
CREATE INDEX IF NOT EXISTS idx_pending_consents_client ON mcp_oauth.pending_consents (client_id);
CREATE INDEX IF NOT EXISTS idx_pending_consents_user ON mcp_oauth.pending_consents (user_id);
CREATE INDEX IF NOT EXISTS idx_pending_consents_expires ON mcp_oauth.pending_consents (expires_at);

-- Update cleanup function to include pending consents.
CREATE OR REPLACE FUNCTION mcp_oauth.cleanup_expired()
    RETURNS void
    AS $$
BEGIN
    DELETE FROM mcp_oauth.auth_requests WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.pending_consents WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.authorization_codes WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.access_tokens WHERE expires_at < NOW();
    DELETE FROM mcp_oauth.refresh_tokens WHERE expires_at IS NOT NULL AND expires_at < NOW();
    DELETE FROM mcp_oauth.sessions WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;
