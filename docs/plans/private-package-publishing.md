# Private package publishing

## Goal

Support `uv publish` and Twine on the Cloudflare deployment. Private projects own
their normalized names; shadowing a public project requires an administrator's
explicit acknowledgment. The local/container server remains a proxy.

## Implementation

- Receive one wheel or source distribution through `POST /upload/` using the
  legacy PyPI multipart protocol. Require a separate publisher token.
- Stream bounded multipart chunks to unique R2 objects, computing SHA-256 and
  checking supplied digests. Validate filename, upload fields, and embedded core
  metadata before publishing the catalog entry.
- Store private ownership and artifact records separately from upstream caches.
  Publish with an atomic D1 batch; identical retries succeed, and existing
  filenames cannot be replaced with different bytes.
- Check PyPI and any separately configured upstream before claiming a name.
  Reject collisions with a link to the Access-protected administrator UI; record
  approval in the audit trail. Inconclusive checks are retryable errors.
- Resolve privately owned names exclusively from private artifacts. Skip public
  cooldown and PyPI OSV matching, while enforcing administrator blocks on both
  listings and downloads. Reject old upstream artifact URLs for those names.
- Keep an object if a D1 commit response is lost: retaining an unreferenced object
  is preferable to deleting published bytes. No automatic orphan sweep or package
  deletion is included in this release.

## Validation and rollout

Use actual SQLite migrations and storage/network fakes to exercise authentication,
collision approvals, corrupt uploads, retry and concurrency behavior, policy
enforcement, missing objects, and storage/catalog failures. Verify publishing with
uv and Twine against a local Worker and install through the Simple API. Run the
full test suite, Ruff, mypy, and a Worker bundle dry run.

Apply migration `0004_private_packages.sql` before deploying the new Worker.
Publishing remains disabled until `WHEELGUARD_UPLOAD_TOKEN` is configured. See the
README for setup, format limits, and operational details.
