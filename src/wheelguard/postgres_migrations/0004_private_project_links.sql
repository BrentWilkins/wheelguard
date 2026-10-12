ALTER TABLE private_projects
ADD COLUMN IF NOT EXISTS repository_url TEXT;

ALTER TABLE private_projects
ADD COLUMN IF NOT EXISTS changelog_url TEXT;
