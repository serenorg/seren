CREATE TABLE mcp_oauth.hosted_passwords_agent_requests (
    user_id uuid NOT NULL,
    request_id uuid NOT NULL,
    display_name text NOT NULL,
    kem_public text NOT NULL,
    signing_public text NOT NULL,
    credential_ciphertext text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    finalizing_at timestamptz,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, request_id),
    CONSTRAINT hosted_passwords_agent_requests_display_name_len CHECK (
        char_length(display_name) BETWEEN 1 AND 128
    ),
    CONSTRAINT hosted_passwords_agent_requests_credential_ciphertext_len CHECK (
        char_length(credential_ciphertext) BETWEEN 1 AND 16384
    )
);

CREATE UNIQUE INDEX hosted_passwords_agent_requests_user_idx
    ON mcp_oauth.hosted_passwords_agent_requests (user_id);
CREATE INDEX hosted_passwords_agent_requests_expiry_idx
    ON mcp_oauth.hosted_passwords_agent_requests (expires_at);
