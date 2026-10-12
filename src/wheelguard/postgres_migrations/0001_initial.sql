CREATE TABLE IF NOT EXISTS projects (
    normalized_name TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    last_serial TEXT,
    fetched_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    sha256 TEXT NOT NULL,
    filename TEXT NOT NULL,
    source_url TEXT NOT NULL,
    size BIGINT,
    project TEXT,
    version TEXT,
    object_key TEXT,
    PRIMARY KEY (sha256, filename)
);
CREATE INDEX IF NOT EXISTS artifacts_release_lookup ON artifacts (project, version);

CREATE TABLE IF NOT EXISTS advisory_scans (
    project TEXT NOT NULL,
    versions_key TEXT NOT NULL,
    payload JSONB NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project, versions_key)
);
CREATE TABLE IF NOT EXISTS advisory_targets (
    project TEXT PRIMARY KEY,
    requested_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_overrides (
    id UUID PRIMARY KEY,
    project TEXT NOT NULL,
    version TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('allow', 'block')),
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_by TEXT,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS policy_overrides_lookup
    ON policy_overrides (project, version, created_at DESC);

CREATE TABLE IF NOT EXISTS policy_audit (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    override_id UUID REFERENCES policy_overrides(id),
    details JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_audit_occurred_at ON policy_audit (occurred_at DESC);

CREATE OR REPLACE FUNCTION reject_policy_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'policy_audit is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS policy_audit_reject_update ON policy_audit;
CREATE TRIGGER policy_audit_reject_update BEFORE UPDATE ON policy_audit
FOR EACH STATEMENT EXECUTE FUNCTION reject_policy_audit_mutation();
DROP TRIGGER IF EXISTS policy_audit_reject_delete ON policy_audit;
CREATE TRIGGER policy_audit_reject_delete BEFORE DELETE ON policy_audit
FOR EACH STATEMENT EXECUTE FUNCTION reject_policy_audit_mutation();

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS private_projects (
    normalized_name TEXT PRIMARY KEY,
    collisions JSONB NOT NULL DEFAULT '[]'::jsonb,
    approved_at TIMESTAMPTZ,
    approved_by TEXT,
    claimed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS private_artifacts (
    project TEXT NOT NULL REFERENCES private_projects(normalized_name),
    filename TEXT NOT NULL,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size > 0),
    object_key TEXT NOT NULL UNIQUE,
    requires_python TEXT,
    uploaded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project, filename)
);
CREATE INDEX IF NOT EXISTS private_artifacts_digest ON private_artifacts (sha256, filename);

CREATE OR REPLACE FUNCTION reject_private_artifact_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'private artifacts are immutable';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS private_artifacts_immutable ON private_artifacts;
CREATE TRIGGER private_artifacts_immutable BEFORE UPDATE ON private_artifacts
FOR EACH STATEMENT EXECUTE FUNCTION reject_private_artifact_mutation();
