-- Hosted Seren Passwords agent credentials for remote MCP.
--
-- A user can explicitly delegate a Seren Passwords agent identity to hosted MCP.
-- The private KEM key and agent API key are encrypted by the MCP token vault
-- before storage; this table never stores plaintext secret material.

CREATE FUNCTION mcp_oauth.tg__timestamps()
RETURNS trigger AS $$
BEGIN
    NEW.created_at = (
        CASE WHEN TG_OP = 'INSERT' THEN
            NOW()
        ELSE
            OLD.created_at
        END
    );
    NEW.updated_at = (
        CASE WHEN TG_OP = 'UPDATE'
            AND OLD.updated_at >= NOW() THEN
            OLD.updated_at + interval '1 millisecond'
        ELSE
            NOW()
        END
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE mcp_oauth.hosted_passwords_agents (
    user_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    display_name text NOT NULL,
    credential_ciphertext text NOT NULL,
    granted_vaults jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, identity_id),
    CONSTRAINT hosted_passwords_agents_display_name_len CHECK (
        char_length(display_name) BETWEEN 1 AND 128
    ),
    CONSTRAINT hosted_passwords_agents_credential_ciphertext_len CHECK (
        char_length(credential_ciphertext) BETWEEN 1 AND 16384
    ),
    CONSTRAINT hosted_passwords_agents_granted_vaults_array CHECK (
        jsonb_typeof(granted_vaults) = 'array'
    )
);

CREATE INDEX idx_hosted_passwords_agents_user_updated ON mcp_oauth.hosted_passwords_agents (
    user_id,
    updated_at DESC
);

CREATE TRIGGER _100_timestamps
    BEFORE INSERT OR UPDATE ON mcp_oauth.hosted_passwords_agents
    FOR EACH ROW
    EXECUTE FUNCTION mcp_oauth.tg__timestamps();
