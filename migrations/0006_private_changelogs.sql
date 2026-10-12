CREATE TABLE IF NOT EXISTS private_changelogs (
    project TEXT NOT NULL REFERENCES private_projects(normalized_name),
    version TEXT NOT NULL,
    content TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('markdown', 'rst', 'text')),
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (project, version)
);
