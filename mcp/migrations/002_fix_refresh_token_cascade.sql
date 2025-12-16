-- Fix: Refresh tokens should not be deleted when access tokens are deleted
-- The ON DELETE CASCADE was causing refresh tokens to be deleted when the
-- associated access token expired, breaking the refresh flow.

-- Drop the existing foreign key constraint
ALTER TABLE mcp_oauth.refresh_tokens
    DROP CONSTRAINT refresh_tokens_access_token_fkey;

-- Re-add without CASCADE - SET NULL allows the refresh token to survive
-- We also need to make access_token nullable for this to work
ALTER TABLE mcp_oauth.refresh_tokens
    ALTER COLUMN access_token DROP NOT NULL;

ALTER TABLE mcp_oauth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_access_token_fkey
    FOREIGN KEY (access_token)
    REFERENCES mcp_oauth.access_tokens (token)
    ON DELETE SET NULL;
