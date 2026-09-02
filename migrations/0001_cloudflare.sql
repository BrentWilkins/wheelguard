CREATE TABLE projects (
    normalized_name TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    last_serial TEXT,
    fetched_at TEXT NOT NULL
);

CREATE TABLE artifacts (
    sha256 TEXT NOT NULL,
    filename TEXT NOT NULL,
    source_url TEXT NOT NULL,
    size INTEGER,
    verification_sha256 TEXT,
    PRIMARY KEY (sha256, filename)
);

CREATE TABLE advisory_scans (
    project TEXT NOT NULL,
    versions_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    PRIMARY KEY (project, versions_key)
);

CREATE TABLE advisory_targets (
    project TEXT PRIMARY KEY,
    requested_at TEXT NOT NULL
);

CREATE TABLE policy_overrides (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    version TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('allow', 'block')),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    revoked_by TEXT,
    revoke_reason TEXT
);

CREATE INDEX policy_overrides_lookup
    ON policy_overrides (project, version, created_at DESC);

CREATE TABLE policy_audit (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    override_id TEXT,
    details TEXT NOT NULL,
    FOREIGN KEY (override_id) REFERENCES policy_overrides (id)
);

CREATE INDEX policy_audit_occurred_at
    ON policy_audit (occurred_at DESC);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
