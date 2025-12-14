-- Add CSRF token to pending_consents for form protection.

ALTER TABLE mcp_oauth.pending_consents
    ADD COLUMN IF NOT EXISTS csrf_token text NOT NULL DEFAULT '';

-- Remove the default after adding the column (new rows must provide a value).
ALTER TABLE mcp_oauth.pending_consents
    ALTER COLUMN csrf_token DROP DEFAULT;
