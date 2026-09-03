-- Associate immutable artifacts with the release policy that governs downloads.
ALTER TABLE artifacts ADD COLUMN project TEXT;
ALTER TABLE artifacts ADD COLUMN version TEXT;

CREATE INDEX artifacts_release_lookup ON artifacts (project, version);
