-- Private names and bytes are independent of the upstream cache.
CREATE TABLE private_projects (
    normalized_name TEXT PRIMARY KEY,
    collisions TEXT NOT NULL DEFAULT '[]',
    approved_at TEXT,
    approved_by TEXT,
    claimed_at TEXT
);

CREATE TABLE private_artifacts (
    project TEXT NOT NULL REFERENCES private_projects(normalized_name),
    filename TEXT NOT NULL,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size > 0),
    object_key TEXT NOT NULL UNIQUE,
    requires_python TEXT,
    uploaded_at TEXT NOT NULL,
    PRIMARY KEY (project, filename)
);
CREATE INDEX private_artifacts_digest ON private_artifacts (sha256, filename);

-- A concurrent retry must never silently replace an already published file.
CREATE TRIGGER private_artifacts_immutable
BEFORE UPDATE ON private_artifacts
BEGIN
    SELECT RAISE(ABORT, 'private artifacts are immutable');
END;
