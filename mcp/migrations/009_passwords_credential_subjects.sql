ALTER TABLE mcp_oauth.hosted_passwords_agents
    ADD COLUMN credential_subject text NOT NULL DEFAULT 'user',
    ADD CONSTRAINT hosted_passwords_agents_credential_subject_len CHECK (
        char_length(credential_subject) BETWEEN 1 AND 96
    );

ALTER TABLE mcp_oauth.hosted_passwords_agents
    DROP CONSTRAINT hosted_passwords_agents_pkey;

ALTER TABLE mcp_oauth.hosted_passwords_agents
    ADD PRIMARY KEY (user_id, credential_subject);

CREATE INDEX hosted_passwords_agents_user_subject_updated_idx
    ON mcp_oauth.hosted_passwords_agents (
        user_id,
        credential_subject,
        updated_at DESC
    );

ALTER TABLE mcp_oauth.hosted_passwords_agent_requests
    ADD COLUMN credential_subject text NOT NULL DEFAULT 'user',
    ADD CONSTRAINT hosted_passwords_agent_requests_credential_subject_len CHECK (
        char_length(credential_subject) BETWEEN 1 AND 96
    );

DROP INDEX mcp_oauth.hosted_passwords_agent_requests_user_idx;

CREATE UNIQUE INDEX hosted_passwords_agent_requests_user_subject_idx
    ON mcp_oauth.hosted_passwords_agent_requests (user_id, credential_subject);
