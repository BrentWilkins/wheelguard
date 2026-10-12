# Wheelguard

Wheelguard is a policy-aware, outage-resistant proxy for Python package indexes.

The first vertical slice proxies project metadata from PyPI, serves both current Simple API
representations, and hides artifacts newer than a configurable minimum age. Unknown upstream
metadata is preserved so newer Simple API fields continue to pass through.

Wheelguard supports Python 3.13 and newer. Local development and CI currently use Python 3.14; Cloudflare Python Workers
currently use Python 3.13 through Pyodide.

## Current capabilities

- PEP 503 root/project routes, normalization, and HTML responses
- PEP 691 JSON content negotiation
- PEP 700 `versions`, `size`, and `upload-time` pass-through
- PEP 740 provenance-link pass-through
- Configurable release cooldown, defaulting to 14 days
- Upstream serial propagation and explicit upstream error handling
- Persistent SQLite metadata and artifact catalog
- Fresh-cache hits and stale metadata fallback during upstream outages
- Content-addressed artifact storage with mandatory SHA-256 verification
- Immutable local artifact URLs; unverified bytes are never served
- Optional OSV batch evaluation with persistent, stale-tolerant scan caching
- Periodic OSV refresh for projects requested within the active-use window
- Vulnerable releases are yanked from resolution and denied at artifact download unless an administrator allows them
- Optional Bearer and HTTP Basic authentication for repository routes

The Cloudflare Worker serves authenticated PEP 503/691 project routes from D1 and stores hash-addressed artifacts and
PEP 658 metadata sidecars in R2. Distribution files stream into R2 with R2 checksum verification; bounded metadata
sidecars are buffered and verified by Wheelguard before storage. A failed checksum is never committed. Active
administrator allow/block overrides are applied on every project response. OSV is checked on the
first request for a version set, cached in D1, and refreshed hourly for projects used within the last 30 days.

Known-vulnerable releases are marked as yanked and denied even through an exact lock or previously issued artifact
URL. An active administrator `allow` override is the deliberate bypass.
If every release old enough to satisfy the cooldown is known vulnerable, Wheelguard temporarily admits the newest fresh
non-vulnerable release. A manual block still wins over that automatic fallback.

## Private publishing (Cloudflare)

The Cloudflare service accepts wheels and source distributions through the standard
PyPI multipart upload protocol at `/upload/`. Private projects appear in the same
authenticated `/simple/` index used for proxied packages.

Before deploying this feature, apply the D1 migrations. Then configure a **separate**
publisher secret, at least 32 characters long, through Wrangler's secret prompt:

```shell
uv run pywrangler d1 migrations apply wheelguard --remote
uv run pywrangler secret put WHEELGUARD_UPLOAD_TOKEN
```

Publishing is disabled when that secret is unset. Existing repository tokens grant
read access only; the publisher token does not automatically grant download access.
For local development, set the publisher secret in the ignored `.dev.vars` file.

Build the package and publish with uv:

```shell
uv build
# Supply UV_PUBLISH_TOKEN through your secret manager or CI secret environment.
uv publish --publish-url https://wheelguard.example/upload/
```

Alternatively, set `TWINE_USERNAME=__token__` and supply `TWINE_PASSWORD` through
your secret environment, then run:

```shell
twine upload --repository-url https://wheelguard.example/upload/ dist/*
```

Replace `wheelguard.example` with your service hostname. Install using your existing
read credential and the `/simple/` index. Do not configure uv's optional publish
`--check-url` with the publisher token: that endpoint requires a read credential.

### Public name collisions

The first upload checks the normalized project name on PyPI and, when different,
the configured upstream. An existing public name causes a `409` response with a
link to **Administration → Private packages**. An Access-authenticated administrator
must click **Acknowledge and permit hiding all upstream releases**; then retry the
upload. Approval is audited and does not take ownership until publishing succeeds.
An unavailable or inconclusive public lookup returns `503`; retry later.

Once claimed, a private name exposes **only private releases**, including when the
private release set is empty or blocked. Old upstream artifact URLs are denied by
the server. Client-side copies already downloaded cannot be recalled. Later uploads
do not require repeated approval, and the administrator UI keeps the collision warning.

### Private release behavior and limits

- Private releases are available immediately, without the public-package cooldown
  or PyPI OSV lookup. Administrator allow/block overrides still apply.
- Upload exactly one file per request. Wheels, `.tar.gz`, and `.zip` source
  distributions must contain matching embedded core metadata. Uploaded code is
  never executed by Wheelguard.
- The configured artifact-size limit applies while streaming, even without a
  `Content-Length` header. Multipart fields, embedded metadata, and ZIP central
  directories are each limited to 1 MiB. ZIP64 directories and attestations are
  not supported. Source archive inspection stops at the smaller of 1 GiB or
  100 times compressed size (with a 1 MiB floor).
- Re-uploading identical bytes under the same filename succeeds. Different bytes
  for an existing filename return `409`; publish a new version instead.
- Verified bytes are stored before the catalog is committed. Failed uploads are
  aborted or removed where their outcome is known. An interrupted request or lost
  database response can leave an unreferenced R2 object; cleanup is intentionally
  conservative so a committed artifact is never deleted by a failed retry.
- Package deletion, releasing private names, and local/container publishing are
  outside this release.

## Development

```shell
uv sync --dev
uv run pytest
uv run ruff check .
uv run mypy
```

Run the service with `uv run wheelguard`, then request a project:

```shell
curl -H 'Accept: application/vnd.pypi.simple.v1+json' \
  http://127.0.0.1:8000/simple/requests/
```

Build and run the production container with persistent cache storage:

```shell
docker build -t wheelguard .
docker run --rm -p 127.0.0.1:8000:8000 \
  -e WHEELGUARD_AUTH_TOKEN="$WHEELGUARD_AUTH_TOKEN" \
  -v wheelguard-data:/data wheelguard
```

### PostgreSQL and Azure Blob runtime

Install the optional production dependencies with `wheelguard[azure]` to store
metadata in PostgreSQL and artifacts in Azure Blob Storage. The runtime uses
Azure's default credential chain, including managed identity when deployed in
Azure:

```shell
WHEELGUARD_DATABASE_URL='host=database.example dbname=wheelguard sslmode=require' \
WHEELGUARD_AZURE_STORAGE_ACCOUNT_URL='https://storage.example.com' \
WHEELGUARD_PUBLIC_URL='https://packages.example.com' \
uv run wheelguard
```

Run `wheelguard-migrate` before starting a new deployment and schedule
`wheelguard-refresh-advisories` to refresh active projects. Optional managed
repository tokens are created and revoked with `wheelguard token`; only their
digests are stored. Private publishing can use short-lived GitLab OIDC tokens
when `WHEELGUARD_PUBLISHER_OIDC_ISSUER` and an explicit
`WHEELGUARD_PUBLISHER_OIDC_PROJECTS` allowlist are configured.

### Cloudflare development

The Cloudflare entrypoint provides `/healthz`, authenticated repository routes under `/simple/` and `/files/`, and the
D1-backed administrator policy UI and API under `/admin/`. Simple API responses expose `X-Wheelguard-Cache`,
`X-Wheelguard-Advisories`, `X-Wheelguard-Hidden-Files`, and `X-Wheelguard-Policy` diagnostics.

The administrator page can change the minimum release age, metadata cache lifetime, per-artifact limit, OSV enablement,
advisory cache lifetime, and active-project scan window without a redeploy. Changes are validated and stored in D1,
applied on the next repository request, and written to `policy_audit`.
Each value can be reset to its deployment default.
Tokens, upstream URLs, and allowed artifact hosts remain deployment-only because they define the service's security
boundary.

Apply the D1 migration and run the Worker locally:

```shell
cp .dev.vars.example .dev.vars
uv run pywrangler d1 migrations apply wheelguard --local
uv run pywrangler dev
```

Replace the example token before starting Wrangler. Pywrangler currently requires uv 0.12.3 or newer. The local Wrangler
configuration simulates a Cloudflare Access identity as `admin@example.com`. Open `/admin/` on the origin Wrangler
prints (normally `http://127.0.0.1:8787`) to exercise create/list/revoke operations and their audit records.

For a local administrator smoke test:

1. Open `/admin/` on Wrangler's printed origin and confirm the simulated Access identity is `admin@example.com`.
2. Change a runtime setting, save it, confirm it is marked overridden, then reset it to the deployment default.
3. Create a release override with project `idna`, version `3.19`, action `block`, and reason `Local smoke test`.
4. Edit the active override and save its audited replacement. Enable **Show history** to see the replaced record.
5. Revoke the replacement and confirm no active overrides remain.
6. Stop the development server, then inspect the append-only audit trail:

   ```shell
   uv run pywrangler d1 execute wheelguard --local \
     --command "SELECT event_type, actor, occurred_at, details FROM policy_audit ORDER BY occurred_at;"
   ```

The page follows the operating-system light or dark color preference, formats integers with thousands separators, and
shows creation timestamps in the browser's local timezone. Project, version, action, and reason are required; expiry is
optional but must be a future timestamp. The server validates package names, normalizes projects according to PEP 503,
normalizes versions according to PEP 440, trims reasons, and reports validation errors or the normalized result beside
the relevant action.

The minimum release age controls automatic eligibility, not override lifetime. An override remains active until its
optional expiry, revocation, or replacement. Expired, replaced, and revoked records remain available in the history and
`policy_audit`; the interface deliberately does not permanently delete them.

The vulnerability fallback has its own floor (24 hours by default). If every normally aged release is known vulnerable,
Wheelguard may expose the newest non-vulnerable release only after that floor. Before then it keeps the known-vulnerable
release yanked and the too-new fix hidden; an administrator can make a documented override if waiting is riskier. Once
the floor is reached the exception is automatic until the release reaches the normal minimum age. Responses append
`vulnerability-fallback` to `X-Wheelguard-Policy`, and the Worker emits a structured
`policy.vulnerability_fallback` log event with the project and allowed versions.

Runtime integer settings are bounded: release age 1–365 days, fallback age 1–336 hours, metadata TTL 1–86,400 seconds,
artifact size 1–104,857,600 bytes, advisory TTL 60–604,800 seconds, and active-project window 1–365 days. Invalid values
return a visible `422` error and are not stored.

The automated suite separately verifies request validation, setting bounds, allow/block precedence, and default resets.
Use only disposable overrides for local testing. For production, configure Cloudflare Access first and use a short-lived
override that you immediately revoke.

Run Wrangler with `--test-scheduled`, then invoke the local hourly scanner directly when testing Cron behavior:

```shell
uv run pywrangler dev --test-scheduled
curl 'http://127.0.0.1:8787/cdn-cgi/handler/scheduled?cron=0+*+*+*+*&format=json'
```

Test the Worker with a real package-manager request while keeping credentials out of the index URL and lockfiles:

```shell
UV_INDEX='wheelguard=http://127.0.0.1:8787/simple/' \
UV_INDEX_WHEELGUARD_USERNAME=wheelguard \
UV_INDEX_WHEELGUARD_PASSWORD='your-local-token' \
uv pip install --python /path/to/venv/bin/python --no-cache idna
```

The D1 database ID and R2 bucket are already bound in `wrangler.jsonc`. Apply pending migrations and publish the Worker,
then set the repository secret through Wrangler's hidden prompt:

```shell
uv run pywrangler d1 migrations apply wheelguard --remote
uv run pywrangler deploy
uv run pywrangler secret put WHEELGUARD_AUTH_TOKEN
```

The initial publish deliberately returns `503` from repository routes until the secret exists. Updating the secret
creates a new Worker version, so a second deploy is not required.

Protect `/admin/*` with a Cloudflare Access application before treating the deployment as production. Set
`WHEELGUARD_ACCESS_AUD` to that application's audience tag to add an application-specific check on top of Cloudflare's
validated `ctx.access` identity. The administrator
interface uses the trusted Access identity; it does not have or need a second application token. The repository token is
separate because package managers do not authenticate through an interactive Access login.

Use a verified Custom Domain for production and set `workers_dev` to `false` after cutover. Repository paths still
require the repository token, and admin paths fail closed unless Access supplied a valid identity.

## Testing the proxy

### Automated checks

Run the same quality gate used by CI:

```shell
uv sync --frozen --dev
uv run --frozen ruff format --check src tests
uv run --frozen ruff check src tests
uv run --frozen mypy
uv run --frozen pytest -p no:cacheprovider -q
uv run --frozen bandit --recursive src
uv export --frozen --all-groups --no-emit-project --format requirements.txt \
  --output-file /tmp/wheelguard-requirements.txt
uv run --frozen pip-audit \
  --requirement /tmp/wheelguard-requirements.txt \
  --disable-pip --no-deps --progress-spinner off
```

CI runs the quality checks, Bandit, pip-audit, and a high/critical Trivy container scan on every
push and pull request. The complete workflow also runs every Monday at 12:00 UTC so newly published
advisories are detected even when Wheelguard's code has not changed.

### End-to-end package installation

Start Wheelguard in one terminal with isolated test state:

```shell
WHEELGUARD_DATA_DIR=/tmp/wheelguard-manual uv run wheelguard
```

In another terminal, check health and fetch project metadata:

```shell
curl -i http://127.0.0.1:8000/healthz
curl -i \
  -H 'Accept: application/vnd.pypi.simple.v1+json' \
  http://127.0.0.1:8000/simple/idna/
```

The first project response reports `X-Wheelguard-Cache: MISS`; repeating it reports
`X-Wheelguard-Cache: HIT`. Install a real package entirely through Wheelguard:

```shell
uv venv /tmp/wheelguard-client --python 3.14
UV_INDEX='wheelguard=http://127.0.0.1:8000/simple' \
uv pip install \
  --python /tmp/wheelguard-client/bin/python \
  --no-cache \
  'idna==3.10'

/tmp/wheelguard-client/bin/python -c 'import idna; print(idna.__version__)'
find /tmp/wheelguard-manual/artifacts -type f
```

The artifact appears beneath the content-addressed cache only after its SHA-256 digest has been
verified.

### Upstream outage fallback

After warming `idna`, stop Wheelguard and restart it with the same data directory, an expired
metadata cache, and an unreachable upstream:

```shell
WHEELGUARD_DATA_DIR=/tmp/wheelguard-manual \
WHEELGUARD_METADATA_TTL_SECONDS=0 \
WHEELGUARD_UPSTREAM_URL=https://127.0.0.1:9/simple/ \
uv run wheelguard
```

Request the project again. A successful response with `X-Wheelguard-Cache: STALE` confirms the
outage path, and the previously verified artifact remains available.

### OSV advisory evaluation

Enable OSV while starting Wheelguard:

```shell
WHEELGUARD_DATA_DIR=/tmp/wheelguard-osv-test \
WHEELGUARD_OSV_ENABLED=true \
uv run wheelguard
```

Fetch an established project such as `urllib3`. The `X-Wheelguard-Advisories` response header shows
`MISS` for the first evaluation and `HIT` for a cached evaluation. In JSON responses, files matched
to advisories have both a `yanked` reason and a `wheelguard-advisories` list. While OSV is enabled,
Wheelguard records successful project requests and periodically refreshes advisories for projects
used within the active window. The first request remains protected by the synchronous check.

For a clean locked CI install, warm the complete registry dependency set before `uv sync`. The command reads only
registry package names and versions from `uv.lock`; Wheelguard resolves URLs, hashes, and policy identities from its own
cached or upstream Simple metadata. Supply the normal repository credential through a masked CI variable:

```shell
uv run --no-project --no-config https://packages.example.com/tools/preflight.py \
  --lock uv.lock --index-url https://packages.example.com/simple/
uv sync --locked --group dev
```

`uv` remains the package client. It temporarily downloads and runs this standard-library-only preflight helper from the
same Wheelguard deployment before the package installation begins. The helper does not install a package or modify the
consuming repository's `pyproject.toml`, lockfile, or environment. Put these commands in a shared GitLab CI template and
include that template from every project that installs through Wheelguard; operators can run the same command manually
before a large dependency update. The helper reuses `UV_INDEX_WHEELGUARD_PASSWORD`; `WHEELGUARD_TOKEN` remains available
as an explicit override.

The shared template is [`ci/preflight.gitlab-ci.yml`](ci/preflight.gitlab-ci.yml). Pin its include to a reviewed
Wheelguard tag or commit:

```yaml
include:
  - project: your-group/wheelguard
    ref: <reviewed-tag-or-commit>
    file: /ci/preflight.gitlab-ci.yml
```

It creates a `.pre` job whenever `uv.lock` exists, so normal build and test stages start only after the complete locked
set is ready. This include is not inherited automatically: each consuming repository must add it, unless a GitLab group
pipeline execution policy injects it centrally.

The authenticated `POST /preflight` request is bounded to 500 entries and 2,000 version selections, normalizes and
deduplicates project names, and evaluates at most eight projects concurrently to bound upstream, OSV, and database
load. A 200 `READY` response means every selected version exists, passes publication policy, has a successful advisory
evaluation with at least 15 minutes remaining in its configured lifetime, and has an authoritative artifact identity
registered. Near-expiry evaluations refresh before the response so their authorization cannot expire during a normal
subsequent install; a warm repeat safely reuses the fresh evaluation. A 409 `DENIED` response identifies vulnerable,
missing, or otherwise policy-denied versions. A 503 `UNAVAILABLE` response includes `Retry-After: 30`; the CLI exits 3
so CI may retry the whole preflight with bounded exponential backoff. Re-running is safe because advisory writes and
artifact registration are idempotent. Do not proceed to `uv sync` after any nonzero preflight exit.

Simple API requests likewise return 503 with `X-Wheelguard-Policy: advisory-unavailable` when OSV fails and no fresh
evaluation exists. They do not advertise artifact links that the file endpoint would reject. For diagnosis, inspect
the non-secret `metadata.timing`, `advisory.timing`, `artifact_registration.timing`, `preflight.project`, and
`preflight.complete` application events and the response's per-project statuses. Timing events contain project names,
cache states, counts, and elapsed milliseconds, but not credentials or source URLs. After correcting upstream or OSV
availability, safely re-run the same command. The periodic refresh job orders targets by oldest successful evaluation,
with never-scanned targets first, so repeated bounded runs drain the active set without starvation.

The assumptions around OSV.dev availability, company use, privacy, and source licensing are recorded in
[`docs/external-services.md`](docs/external-services.md).

To see the resolver behavior against a deployed Worker, configure Wheelguard as the project's default uv index. The
index URL is safe to commit; the repository token is not:

```toml
[tool.uv]
# Store index credentials in the operating system's encrypted credential store.
preview-features = ["native-auth"]

[[tool.uv.index]]
name = "wheelguard"
url = "https://packages.example.com/simple/"
default = true
authenticate = "always"
```

On Ubuntu Desktop, uv's native authentication backend uses the Secret Service API provided by GNOME Keyring. Sign in
once from the consuming project and enter the Wheelguard repository token at the password prompt:

```shell
cd /path/to/project
UV_PREVIEW_FEATURES=native-auth \
  uv auth login packages.example.com --username wheelguard
uv add 'idna==3.10'
```

The explicit environment variable enables native storage for the login itself; the committed `preview-features`
setting enables retrieval during later project commands. Ubuntu Server and other headless sessions may not have an
unlocked Secret Service provider. In that case, use uv's user-local plaintext credential store by omitting
`UV_PREVIEW_FEATURES=native-auth` and the `preview-features` setting, or supply
`UV_INDEX_WHEELGUARD_USERNAME` and `UV_INDEX_WHEELGUARD_PASSWORD` from a secret manager. The plaintext uv store is
comparable to a carefully protected `.env` file, but it is shared by host rather than copied into each project.

An exact pin to this known-vulnerable release surfaces Wheelguard's PEP 592 warning, then the artifact request is
denied with HTTP `403` unless an active administrator `allow` override exists:

```text
warning: `idna==3.10` is yanked (reason: "Wheelguard advisories: GHSA-65pc-fj4g-8rjx, PYSEC-2026-215")
```

Without an exact pin, normal resolution avoids releases Wheelguard has marked as yanked:

```shell
uv add idna
```

```text
Resolved 2 packages in 2.29s
Installed 2 packages in 3ms
 + idna==3.19
```

Timings and package counts vary. Do not place the repository token in `pyproject.toml`, `uv.lock`, the index URL, or
shell history. Remove the locally stored credential with `uv auth logout packages.example.com`; this does not revoke
the token at the Wheelguard server.

### Authentication

Start Wheelguard with a test token:

```shell
WHEELGUARD_DATA_DIR=/tmp/wheelguard-auth-test \
WHEELGUARD_AUTH_TOKEN=test-secret-0123456789abcdef0123456789 \
uv run wheelguard
```

An unauthenticated `/simple/` request returns `401`. Test Bearer authentication with curl:

```shell
curl -i \
  -H 'Authorization: Bearer test-secret-0123456789abcdef0123456789' \
  -H 'Accept: application/vnd.pypi.simple.v1+json' \
  http://127.0.0.1:8000/simple/idna/
```

For uv, keep credentials out of the index URL and committed files by using named-index environment
variables:

```shell
UV_INDEX='wheelguard=http://127.0.0.1:8000/simple' \
UV_INDEX_WHEELGUARD_USERNAME=wheelguard \
UV_INDEX_WHEELGUARD_PASSWORD=test-secret-0123456789abcdef0123456789 \
uv pip install \
  --python /tmp/wheelguard-client/bin/python \
  --no-cache \
  'idna==3.10'
```

Plain HTTP is appropriate only for this localhost test; terminate TLS before Wheelguard in a real
deployment.

To give each user an independently revocable credential, keep your existing token in
`WHEELGUARD_AUTH_TOKEN` and put additional tokens in the comma-separated
`WHEELGUARD_AUTH_TOKENS` secret. Both variables are optional, but every configured token must
contain at least 32 characters. For example:

```shell
WHEELGUARD_AUTH_TOKEN='your-existing-token-at-least-32-characters' \
WHEELGUARD_AUTH_TOKENS='shared-token-at-least-32-characters' \
uv run wheelguard
```

This also permits rotation without downtime: add the replacement token, update clients, verify
they can authenticate, and only then remove the old token. On Cloudflare, store the complete
comma-separated list as an encrypted secret with
`uv run pywrangler secret put WHEELGUARD_AUTH_TOKENS`; do not add it to `wrangler.jsonc`.

## Configuration

| Environment variable | Default | Purpose |
|---|---:|---|
| `WHEELGUARD_UPSTREAM_URL` | `https://pypi.org/simple/` | Upstream Simple API |
| `WHEELGUARD_MINIMUM_AGE_DAYS` | `14` | Minimum artifact age |
| `WHEELGUARD_FALLBACK_MINIMUM_AGE_HOURS` | `24` | Minimum age before a fixed release may bypass the normal age policy |
| `WHEELGUARD_ALLOW_MISSING_UPLOAD_TIME` | `false` | Fail closed when upload timestamps are missing or invalid |
| `WHEELGUARD_ALLOWED_ARTIFACT_HOSTS` | `files.pythonhosted.org` | Exact HTTPS hosts the downloader may contact |
| `WHEELGUARD_UPSTREAM_TIMEOUT` | `30` | Upstream timeout in seconds |
| `WHEELGUARD_DATA_DIR` | `.wheelguard-data` | Metadata database and artifact storage |
| `WHEELGUARD_METADATA_TTL_SECONDS` | `300` | Fresh metadata cache lifetime |
| `WHEELGUARD_MAXIMUM_ARTIFACT_BYTES` | 100 MiB (104,857,600 bytes) | Per-artifact limit matching PyPI's default |
| `WHEELGUARD_OSV_ENABLED` | `false` | Enable OSV vulnerability evaluation |
| `WHEELGUARD_OSV_URL` | `https://api.osv.dev/v1/querybatch` | OSV-compatible batch endpoint |
| `WHEELGUARD_ADVISORY_TTL_SECONDS` | `21600` | Fresh advisory scan lifetime |
| `WHEELGUARD_ADVISORY_REFRESH_SECONDS` | `3600` | Interval between active-project refreshes |
| `WHEELGUARD_ADVISORY_ACTIVE_DAYS` | `30` | Retain and periodically scan recently requested projects |
| `WHEELGUARD_ADVISORY_REFRESH_BATCH_SIZE` | `25` | Maximum self-hosted projects scanned per periodic pass |
| `WHEELGUARD_AUTH_TOKEN` | unset | Protect `/simple` and `/files` with a shared token |
| `WHEELGUARD_AUTH_TOKENS` | unset | Comma-separated additional tokens for sharing and rotation |
| `WHEELGUARD_ACCESS_AUD` | unset | Optional expected Cloudflare Access application audience for `/admin` |
| `WHEELGUARD_HOST` | `127.0.0.1` | Listening host |
| `WHEELGUARD_PORT` | `8000` | Listening port |

Authentication tokens must contain at least 32 characters. Wheelguard refuses to bind the self-hosted server to a
non-loopback address without one. Upstream, OSV, and artifact-source URLs must use HTTPS; artifact redirects are checked
again after they are followed.

When authentication is enabled, Wheelguard accepts the token as either a Bearer token or an HTTP
Basic password (the username is ignored). Keep the repository URL itself credential-free in
committed configuration. Supply credentials through the package manager's environment-variable or
keyring support so private URLs cannot be written into a public lockfile.

## License

Copyright 2026 Brent Wilkins.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE).
