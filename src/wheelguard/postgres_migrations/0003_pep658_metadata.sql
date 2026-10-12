ALTER TABLE artifacts
ADD COLUMN IF NOT EXISTS verification_sha256 TEXT;

UPDATE artifacts
SET verification_sha256 = sha256
WHERE verification_sha256 IS NULL;
