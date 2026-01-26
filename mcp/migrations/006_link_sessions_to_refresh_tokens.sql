-- Migration: Link MCP sessions to their specific refresh tokens
--
-- Problem: Sessions were looking up upstream tokens by (user_id, client_id) which
-- returns the most recent token. This causes conflicts when a user has multiple
-- concurrent sessions (e.g., Claude Code + Cursor) because:
-- 1. Each login creates a new refresh_token row with fresh upstream tokens
-- 2. The old session's upstream tokens become stale (the upstream API rotates them)
-- 3. When the old session tries to refresh, it gets the wrong (newest) token
-- 4. Or worse, uses a stale upstream refresh token that triggers reuse detection
--
-- Solution: Each MCP session explicitly links to its own refresh_token row via
-- refresh_token_hash. This ensures each session maintains its own independent
-- upstream token lifecycle.
-- Add refresh_token_hash column to link sessions to their specific tokens
ALTER TABLE mcp_oauth.mcp_sessions
    ADD COLUMN refresh_token_hash text;

-- Add foreign key constraint with ON UPDATE CASCADE so session links remain valid
-- when MCP refresh tokens are rotated (token_hash updated in-place).
ALTER TABLE mcp_oauth.mcp_sessions
    ADD CONSTRAINT fk_mcp_sessions_refresh_token_hash FOREIGN KEY (refresh_token_hash) REFERENCES mcp_oauth.refresh_tokens (token_hash) ON DELETE SET NULL ON UPDATE CASCADE;

-- Index for efficient lookups
CREATE INDEX idx_mcp_sessions_refresh_token ON mcp_oauth.mcp_sessions (refresh_token_hash)
WHERE
    refresh_token_hash IS NOT NULL;

-- Backfill existing sessions: link each session to the most recent refresh token
-- for that user/client combination (best effort for existing sessions)
UPDATE
    mcp_oauth.mcp_sessions s
SET
    refresh_token_hash = (
        SELECT
            r.token_hash
        FROM
            mcp_oauth.refresh_tokens r
        WHERE
            r.user_id = s.user_id
            AND r.client_id = s.client_id
            AND (r.expires_at IS NULL
                OR r.expires_at > NOW())
        ORDER BY
            r.created_at DESC
        LIMIT 1)
WHERE
    s.user_id IS NOT NULL
    AND s.client_id IS NOT NULL
    AND s.refresh_token_hash IS NULL;

COMMENT ON COLUMN mcp_oauth.mcp_sessions.refresh_token_hash IS 'Links this session to its specific refresh token and upstream token vault. '
    'Each session maintains independent upstream tokens to support multiple concurrent '
    'sessions per user (e.g., Claude Code + Cursor) without token conflicts.';
