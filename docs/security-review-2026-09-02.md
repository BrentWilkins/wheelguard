# Wheelguard code and security review

**Date:** 2026-09-02
**Basis:** working tree at git `4d31d72` plus uncommitted edits. Review ran against a snapshot taken
at the start; the tree was re-diffed against that snapshot after the in-flight edits finished and is
byte-identical, so line numbers are accurate. Findings name the enclosing function as well.
**Live deployment probed (read-only GETs only):** the deployed Worker hostname

## Remediation status

All code-level findings were addressed in the hardening pass that followed this review:

| Finding | Resolution |
|---|---|
| 1 | Self-hosted upstreams now require HTTPS. Artifact URLs are admitted only from exact configured HTTPS hosts, and every redirect target is validated before its request on both serving paths. Cached project metadata no longer registers artifact URLs implicitly. |
| 2 | The automatic fixed-release exception has a configurable 1–336 hour floor (24 hours by default), a response marker, and a structured log event. |
| 3, 15 | Authenticated artifacts now use private caching with `Vary: Authorization`; both serving paths add `nosniff`. |
| 4, 5 | Missing timestamps fail closed by default but remain editable for compatibility, and every administrator-editable integer has an enforced upper and lower bound. |
| 6 | State-changing admin requests require a matching `Origin` or `Sec-Fetch-Site: same-origin`. |
| 7 | Admin identity must match a non-empty `WHEELGUARD_ACCESS_AUD`, and the `workers.dev` ingress is disabled after Custom Domain verification. |
| 8–10 | SQLite operations use the event loop's bounded executor without polling, artifact locks use weak ownership, and self-hosted advisory refreshes are capped at 25 projects per pass by default. |
| 11–13 | Repository authentication now precedes D1 settings reads, non-loopback self-hosted binds require authentication, and configured tokens must contain at least 32 characters. |
| 14 | D1 migration `0002_immutable_policy_audit.sql` rejects audit-row updates and deletes. |
| 16 | A CPython Worker-runtime harness now covers routing, pre-D1 authentication, Access audience checks, CSRF rejection, health access, and fallback observability. |
| 17 | `actions/checkout` is pinned to the verified full commit SHA for v7.0.1. |

The ingress change was staged as an operational transition: the Custom Domain and Access-protected admin paths were
verified before disabling the fallback `workers.dev` hostname.

## Summary

Wheelguard is in good shape. The central security claim — that unverified bytes are never served —
holds on both the self-hosted and Cloudflare paths, SQL is parameterized throughout, token
comparison is constant-time, and the admin UI is built without a single `innerHTML` assignment
behind a per-response CSP nonce. CI is stronger than most projects of this size.

The findings below cluster in three places: the self-hosted artifact fetcher, which lacks the host
allowlist its Cloudflare counterpart has; the caching headers on artifact responses; and the places
where policy deliberately or accidentally fails open.

Verified against the live deployment: `/admin/` and `/admin/api/*` return `403` on the `workers.dev`
hostname, and `/simple/` returns `401` with a `WWW-Authenticate` challenge. The admin surface fails
closed today.

Quality gate on the current tree: `ruff format`, `ruff check`, `mypy`, and `pytest` (50 tests) all pass.

| #    | Severity | Finding                                                                    |
| ---- | -------- | -------------------------------------------------------------------------- |
| 1    | High     | SSRF in the self-hosted artifact downloader — no host allowlist            |
| 2    | High     | Vulnerability fallback can bypass the release cooldown entirely            |
| 3    | Medium   | Authenticated artifact responses marked publicly cacheable                 |
| 4    | Medium   | Missing upload timestamps fail open and can't be tightened at the edge     |
| 5    | Medium   | No upper bounds on admin-editable settings                                 |
| 6    | Medium   | CSRF defense treats a missing `Origin` header as permission                |
| 7    | Medium   | Admin auth depends on `ctx.access` presence; `workers_dev` adds an ingress |
| 8–16 | Low      | Hardening and robustness items                                             |

---

## 1. High — SSRF in the self-hosted artifact downloader

`src/wheelguard/artifacts.py:118` (`ArtifactService._download`), fed by
`src/wheelguard/database.py:258` (`_artifact_records`).

The Cloudflare path validates every artifact URL through `_allowed_source()` — HTTPS only, hostname
in `WHEELGUARD_ALLOWED_ARTIFACT_HOSTS` — and re-validates after redirects
(`cloudflare_index.py:590,673,717`). The self-hosted path has no equivalent. `_artifact_records`
stores whatever string upstream put in `file["url"]` with no scheme or host check, and `_download`
hands it straight to `httpx.AsyncClient(follow_redirects=True)`.

Compounding it, `config.py:33` accepts any `WHEELGUARD_UPSTREAM_URL` without requiring HTTPS, while
`EdgeSettings.from_env` (`cloudflare_index.py:96`) rejects non-HTTPS upstreams.

A malicious, compromised, or misconfigured upstream index can therefore make Wheelguard issue
requests to arbitrary internal addresses — `http://169.254.169.254/latest/meta-data/`,
`http://127.0.0.1:6379/`, internal admin panels — and follow redirects into them. The SHA-256
verification at `artifacts.py:128` means the response body is not served back to the client, so this
is a _blind_ SSRF, but the request is still made from inside the network perimeter.

**Recommendation:** give the self-hosted path the same allowlist the edge already has. Add a
`WHEELGUARD_ALLOWED_ARTIFACT_HOSTS` setting, validate scheme and hostname in `_artifact_records`
(reject at registration, not just at download), re-check the final URL after redirects, and require
HTTPS for `WHEELGUARD_UPSTREAM_URL` in `config.py`.

## 2. High — the vulnerability fallback can bypass the cooldown entirely

`src/wheelguard/vulnerabilities.py:83` (`automatic_fixed_version_allows`), applied at
`cloudflare_index.py:215`.

When every release old enough to satisfy the cooldown is known-vulnerable, Wheelguard admits the
newest _fresh_ non-vulnerable release with **zero** cooldown. This is documented and intentional, and
the availability argument for it is real. The security consequence deserves to be stated plainly
anyway:

OSV cannot know about a release published an hour ago. So "no advisory against it" and "brand new"
are the same condition from OSV's point of view. The precise scenario the cooldown exists to defend
against — a compromised maintainer account publishing a malicious version — is the scenario in which
this fallback opens the gate, because the malicious new release is by definition unflagged and
therefore lands in `fresh_safe` (line 111) and gets `"allow"`.

This is not a rare corner. Any abandoned library whose entire release history carries an advisory
sits in this state permanently, so the cooldown is permanently off for it.

Manual `block` overrides do win (`cloudflare_index.py:222` applies overrides after the automatic
allows), which is the right precedence.

**Recommendation:** keep the fallback but bound it. Require a floor of some hours even in fallback
mode; prefer a version that OSV actually reports as _fixing_ the advisories over merely the newest
unflagged one; and surface it — `X-Wheelguard-Policy` is currently the static string
`"minimum-age, overrides"` (`cloudflare_index.py:829`) and never reports that the fallback fired.
Emit a `_log()` record too, so it is auditable.

## 3. Medium — authenticated artifact responses are marked publicly cacheable

`cloudflare_index.py:635` (`_artifact`) and `application.py:208` (`artifact`).

Both set `Cache-Control: public, max-age=31536000, immutable` with no `Vary: Authorization`. These
routes sit behind repository authentication, so this instructs every shared cache between Wheelguard
and the client — corporate proxy, CDN, any intermediary — to store an authenticated response and
replay it to clients that present no credentials at all.

The Simple API responses get this right: `private, no-cache` with `Vary: Accept, Authorization`
(`cloudflare_index.py:824,826`). The artifact routes are the inconsistency.

Impact today is bounded, because the bytes are public PyPI content. It matters because it breaks the
stated authentication boundary, and it becomes serious the moment Wheelguard fronts a private index.

**Recommendation:** `Cache-Control: private, max-age=31536000, immutable` plus
`Vary: Authorization`. Content-addressed URLs mean you keep essentially all of the caching benefit at
the client.

## 4. Medium — missing upload timestamps fail open, and can't be tightened at the edge

`cloudflare_index.py:223` constructs `ReleasePolicy(self._settings.minimum_age)` without passing
`allow_missing_upload_time`, so it takes the dataclass default of `True`
(`policy.py:76`). Any file whose `upload-time` upstream omits — or renders in a form
`_upload_time` (`policy.py:124`) can't parse, including a valid-but-naive timestamp — is treated as
old enough and served **immediately**, with no cooldown.

The self-hosted path at least exposes `WHEELGUARD_ALLOW_MISSING_UPLOAD_TIME`. The edge has no such
env var and no entry in `SETTING_DEFINITIONS`, so an edge operator cannot tighten this at all.

Since the cooldown is Wheelguard's primary control, the input that switches it off per-file should
not silently default to permissive on the path that has no override.

**Recommendation:** default the edge to fail closed (hide files with unusable timestamps), or at
minimum expose the toggle as a deployment variable, and log when a file is admitted for this reason.

## 5. Medium — no upper bounds on admin-editable settings

`runtime_settings.py:108` (`_serialize_value`) enforces `definition.minimum` but no maximum.

Consequences, all reachable by anyone holding an Access session:

- `maximum_artifact_bytes` can be set arbitrarily high. This is the control that keeps oversized
  objects out of R2 (`cloudflare_index.py:586,664,679`).
- `metadata_ttl_seconds` and `advisory_ttl_seconds` can be set to effectively infinity, freezing
  metadata and advisory data indefinitely while responses continue to report a cheerful `HIT`.
- `minimum_age_days` has a minimum of `0` (`runtime_settings.py:22`), so the cooldown can be
  disabled outright through the UI.

The README states the suite "separately verifies request validation, setting bounds, allow/block
precedence, and default resets." That is accurate only for the lower bound.

**Recommendation:** add a `maximum` to `SettingDefinition` and enforce it. Consider a floor above `0`
for `minimum_age_days`, so disabling the cooldown requires a redeploy rather than a form submission.

## 6. Medium — CSRF defense treats a missing `Origin` header as permission

`worker.py:411` (`_reject_cross_origin_write`):

```python
origin = request.headers.get("origin")
if origin is None:
    return None      # allowed
```

Today this is not an open hole: POST and PATCH require `Content-Type: application/json`
(`worker.py:131,188,294`), which a cross-site HTML form cannot produce, and `DELETE` is a non-simple
method that forces a CORS preflight. The browser will attach `Origin` in exactly the cases that
matter.

It is still fragile — the control is one header omission away from being absent, and the two `DELETE`
routes (`/admin/api/settings/{key}`, `/admin/api/overrides/{id}`) carry no content-type requirement as
a second layer.

**Recommendation:** require a matching `Origin`, or accept `Sec-Fetch-Site: same-origin`, and reject
state-changing requests that carry neither.

## 7. Medium — admin auth rests on `ctx.access` presence; `workers_dev` adds an ingress

`worker.py:97` (`_admin_actor`) returns `None` when `getattr(self.ctx, "access", None)` is absent,
and every admin route 403s on `None`. There is no `aud` verification in application code — the code
trusts that if `ctx.access` exists, the platform validated it.

I confirmed live that this fails closed: `/admin/`, `/admin/api/settings`, and `/admin/api/overrides`
all return `403 Cloudflare Access authentication required` on the `workers.dev` hostname.

The residual risk is structural. `wrangler.jsonc:53` configures `access` only under `dev`, and
`workers_dev: true` (line 9) publishes the Worker on a `*.workers.dev` hostname permanently. When a
production Access application is later attached to a custom domain, that second hostname remains a
separate ingress the Access application may not cover — at which point `ctx.access` behavior on it
determines whether the admin API is exposed. The README treats configuring Access as advice; it is
load-bearing.

**Recommendation:** set `"workers_dev": false` once a custom domain exists, and check the identity's
`aud` against an expected value in `_admin_actor` rather than relying on presence alone.

---

## Low severity and hardening

8. **Blocking SQLite inside `async def`** — `database.py` throughout. Every method is `async` but
   calls `sqlite3.connect(...)` synchronously, blocking the event loop for the duration of each
   query. Each call also opens a fresh connection and never closes it: `with sqlite3.connect(p)`
   commits the transaction but does not close the connection, leaving it to GC. Use a single
   connection (or a pool) and `asyncio.to_thread`.

9. **Unbounded lock dictionary** — `artifacts.py:66,97`. `self._locks.setdefault(key, asyncio.Lock())`
   adds one lock per `(digest, filename)` and never removes it. Memory grows with the number of
   distinct artifacts ever requested. Evict after download, or use a bounded LRU.

10. **Unbounded refresh loop** — `refresh.py:42`. `refresh_once` iterates _every_ active target with
    no limit, while the Cloudflare equivalent caps at `limit=25`
    (`cloudflare_index.py:455`). On a large catalog this is a long synchronous burst of OSV queries.

11. **Settings read before authentication** — `cloudflare_index.py:136`. `_load_runtime_settings()`
    runs before the auth check on line 139, so every unauthenticated request costs a D1 read. Move
    it after authorization.

12. **Docker default is an unauthenticated open proxy** — `Dockerfile`. The image sets
    `WHEELGUARD_HOST=0.0.0.0` with no `WHEELGUARD_AUTH_TOKEN`, so a plain `docker run` publishes an
    unauthenticated proxy to the network. The README covers TLS termination but not this. Consider
    defaulting to `127.0.0.1`, or refusing to bind a non-loopback address without a token.

13. **Empty-string token silently disables auth while reporting enabled** — `auth.py:18,31` with
    `cloudflare_index.py:132`. If `WHEELGUARD_AUTH_TOKEN` is set to `""`, `enabled` is `True` (the
    check is `is not None`), the `require_authentication` guard passes, and
    `compare_digest("", "")` succeeds — so `Authorization: Bearer ` authenticates. Reject empty or
    short tokens at construction.

14. **`policy_audit` is not actually append-only** — `migrations/0001_cloudflare.sql`. The README
    calls it an append-only audit trail, but nothing prevents `UPDATE` or `DELETE`; it is enforced
    only by application convention. Add triggers that raise on update/delete if the property matters.

15. **Self-hosted responses lack security headers present on the edge** — `application.py`. No
    `X-Content-Type-Options: nosniff` on the HTML or artifact responses, and `/simple/` sets
    `Vary: Accept` without `Authorization` (line 145) even though the route is authenticated.

16. **Test coverage gap on the security boundary** — `worker.py` has no tests at all: admin routing,
    the CSRF check, and actor resolution are entirely unexercised. `cloudflare_index.py` is reached
    only through `test_cloudflare_artifacts.py`, which targets `_populate_artifact`; the
    `CloudflareRepository.fetch` routing and auth ordering are untested. `test_admin.py` and
    `test_runtime_settings.py` cover the pure validation helpers only. Given that these modules are
    the largest and most security-relevant in the project, they are the ones most worth covering.

17. **One unpinned CI action** — `.github/workflows/ci.yml` pins `astral-sh/setup-uv` and the Trivy
    image by SHA/digest but uses `actions/checkout@v7.0.1` by tag.

---

## What holds up well

Worth recording, so it isn't lost in a list of findings:

- **Hash verification is genuinely mandatory.** Both paths verify before committing and never serve
  unverified bytes — streamed uploads delegate to R2's `sha256` put option
  (`cloudflare_index.py:701`), bounded sidecars are hashed in-Worker (line 694), and the self-hosted
  path hashes while streaming and only then `os.replace`s into place (`artifacts.py:128`).
- **No SQL injection anywhere.** Every statement is parameterized, including the batched artifact
  upsert that passes JSON as a single bound parameter and expands it with `json_each`
  (`cloudflare_index.py:545`) — an easy place to have concatenated instead.
- **Constant-time token comparison** via `hmac.compare_digest`, for both Bearer and Basic.
- **A genuinely tight admin CSP** — `default-src 'none'` with a per-response `secrets.token_urlsafe`
  nonce, `base-uri 'none'`, `frame-ancestors 'none'` (`admin.py:15`).
- **No XSS surface in the admin UI.** The entire page is built with `createElement` and `textContent`;
  there is no `innerHTML` assignment. The one server-interpolated value is `html.escape`d
  (`worker.py:435`).
- **Strict artifact sourcing at the edge** — HTTPS-only, host allowlist, and re-validation of the
  _final_ URL after redirects, which is the step most implementations skip.
- **Input validation is thorough** — PEP 503/440 normalization with `validate=True`, filename
  traversal and control-character rejection (`cloudflare_index.py:578`), size-bounded request and
  upstream bodies, and strict OSV response shape checking.
- **Secrets hygiene.** `.dev.vars` is gitignored and, per `git log --all`, was never committed.
- **CI** runs Bandit, pip-audit, and a high/critical Trivy scan, on a weekly schedule as well as per
  push, with `permissions: contents: read`.

## Suggested order of work

1. Add the host allowlist to the self-hosted artifact path and require HTTPS upstream (#1).
2. Fix the artifact cache headers — a two-line change (#3).
3. Bound the cooldown fallback and make it observable (#2).
4. Add maximums to the editable settings (#5).
5. Fail closed on missing upload timestamps at the edge (#4).
6. Tighten the CSRF check and the `workers_dev` ingress (#6, #7).
7. Add tests for `worker.py` routing and `CloudflareRepository.fetch` (#16) — this is what keeps the
   items above from regressing.
