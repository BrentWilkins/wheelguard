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
- Vulnerable releases are yanked for normal resolution but remain available to exact pins
- Optional Bearer and HTTP Basic authentication for repository routes

The Cloudflare Worker serves authenticated PEP 503/691 project routes from D1 and stores hash-addressed artifacts and
PEP 658 metadata sidecars in R2. Distribution files stream into R2 with R2 checksum verification; bounded metadata
sidecars are buffered and verified by Wheelguard before storage. A failed checksum is never committed. Active
administrator allow/block overrides are applied on every project response. OSV is checked on the
first request for a version set, cached in D1, and refreshed hourly for projects used within the last 30 days.

Known-vulnerable releases remain addressable for exact pins but are marked as yanked, so normal resolution avoids them.
If every release old enough to satisfy the cooldown is known vulnerable, Wheelguard temporarily admits the newest fresh
non-vulnerable release. A manual block still wins over that automatic fallback.

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

An exact pin to this known-vulnerable release remains installable, but uv surfaces Wheelguard's PEP 592 warning:

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
