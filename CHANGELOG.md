# Changelog

All notable changes to Wheelguard are documented here.

## 0.2.1 - 2026-09-07

### Security

- Apply the automatic vulnerability fallback cooldown to each artifact so an older source archive cannot admit a newly uploaded wheel.
- Recheck publication age and current fallback eligibility for direct Worker downloads after an administrator allow expires or is revoked. Metadata sidecars receive the same checks; missing publication metadata denies access.
- Hide self-hosted artifacts without a valid SHA-256 or a supported proxy URL so downloads cannot bypass authorization and verification.

No database migration is required.

## 0.2.0 - 2026-09-03

### Added

- Support multiple repository bearer tokens through the comma-separated
  `WHEELGUARD_AUTH_TOKENS` secret while retaining `WHEELGUARD_AUTH_TOKEN` for
  compatible, zero-downtime rotation.
- Associate artifact registrations with their project and release so current
  policy can be checked whenever an immutable artifact URL is requested.

### Changed

- Deny vulnerable, stale, or unevaluated artifact downloads when OSV policy is
  enabled, including artifacts already cached in R2 or local storage.
- Permit a denied release only through an active administrator `allow`
  override. An administrator `block` continues to take precedence over normal
  policy.
- Require D1 migration `0003_artifact_policy_identity.sql` before deploying
  the Worker. Existing artifact rows fail closed until their project metadata
  is requested again and the rows gain release identity.

### Security

- Close the path where a lockfile or previously issued content-addressed URL
  could continue downloading a release after Wheelguard learned it was
  vulnerable.

## 0.1.0 - 2026-09-02

- Initial public release.
