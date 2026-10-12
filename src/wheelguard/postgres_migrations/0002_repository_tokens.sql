CREATE TABLE IF NOT EXISTS repository_tokens (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL CHECK (length(trim(created_by)) > 0),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX IF NOT EXISTS repository_tokens_active_hash
    ON repository_tokens (token_hash)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS repository_tokens_active_name
    ON repository_tokens (name)
    WHERE revoked_at IS NULL;
