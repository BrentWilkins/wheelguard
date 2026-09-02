"""Run Wheelguard's Cloudflare-native package repository and administration."""

import html
import json
import secrets
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from workers import Response, WorkerEntrypoint

from wheelguard.admin import InvalidOverrideError, admin_content_security_policy, parse_override_request
from wheelguard.cloudflare_index import CloudflareRepository, EdgeSettings, RepositoryError
from wheelguard.runtime_settings import (
    SETTING_DEFINITIONS,
    InvalidSettingsError,
    decode_stored_settings,
    parse_settings_update,
    setting_catalog,
)

JSON_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
}


class Default(WorkerEntrypoint):
    """Handle Cloudflare Worker requests and scheduled events."""

    async def fetch(self, request: Any) -> Response:
        """Route repository, health, and administrator requests."""
        path = urlsplit(request.url).path
        if path == "/simple" or path.startswith("/simple/") or path.startswith("/files/"):
            try:
                return await CloudflareRepository(self.env).fetch(request)
            except RepositoryError as error:
                return _error(str(error), 503)
        if path == "/healthz" and request.method == "GET":
            return Response.from_json({"status": "ok", "runtime": "cloudflare"})
        if path == "/admin" or path == "/admin/":
            actor = await self._admin_actor()
            if actor is None:
                return _error("Cloudflare Access authentication required", 403)
            return _admin_page(actor)
        if path == "/admin/api/settings":
            actor = await self._admin_actor()
            if actor is None:
                return _error("Cloudflare Access authentication required", 403)
            if request.method == "GET":
                return await self._list_settings()
            if request.method == "PATCH":
                return await self._update_settings(request, actor)
            return _error("Method not allowed", 405)
        if path.startswith("/admin/api/settings/"):
            actor = await self._admin_actor()
            if actor is None:
                return _error("Cloudflare Access authentication required", 403)
            if request.method != "DELETE":
                return _error("Method not allowed", 405)
            key = path.removeprefix("/admin/api/settings/")
            return await self._reset_setting(request, actor, key)
        if path == "/admin/api/overrides":
            actor = await self._admin_actor()
            if actor is None:
                return _error("Cloudflare Access authentication required", 403)
            if request.method == "GET":
                return await self._list_overrides()
            if request.method == "POST":
                return await self._create_override(request, actor)
            return _error("Method not allowed", 405)
        if path.startswith("/admin/api/overrides/"):
            actor = await self._admin_actor()
            if actor is None:
                return _error("Cloudflare Access authentication required", 403)
            override_id = path.removeprefix("/admin/api/overrides/")
            if request.method == "PATCH":
                return await self._replace_override(request, actor, override_id)
            if request.method == "DELETE":
                return await self._revoke_override(request, actor, override_id)
            return _error("Method not allowed", 405)
        return _error("Not found", 404)

    async def scheduled(self, controller: Any, env: Any, ctx: Any) -> None:
        """Refresh OSV results for recently requested projects on a Cron Trigger."""
        del env, ctx
        refreshed = await CloudflareRepository(self.env).refresh_active_advisories()
        print(  # noqa: T201
            json.dumps(
                {"event": "advisory.cron.complete", "cron": str(controller.cron), "refreshed": refreshed},
                separators=(",", ":"),
                sort_keys=True,
            )
        )

    async def _admin_actor(self) -> str | None:
        """Return the Access-authenticated administrator identity."""
        access = getattr(self.ctx, "access", None)
        if access is None:
            return None
        expected_audience = getattr(self.env, "WHEELGUARD_ACCESS_AUD", None)
        if expected_audience and not secrets.compare_digest(str(access.aud), str(expected_audience)):
            return None
        identity = await access.getIdentity()
        email = getattr(identity, "email", None)
        return str(email) if email else "unknown-access-user"

    async def _list_overrides(self) -> Response:
        """Return active and historical overrides newest first."""
        rows = await self.env.WHEELGUARD_DB.prepare(
            """
            SELECT id, project, version, action, reason, created_at, created_by,
                   expires_at, revoked_at, revoked_by, revoke_reason
            FROM policy_overrides
            ORDER BY created_at DESC
            LIMIT 500
            """
        ).raw(columnNames=True)
        return Response.from_json(list(rows), headers=JSON_HEADERS)

    async def _list_settings(self) -> Response:
        """Return deployment defaults and effective D1 runtime settings."""
        raw = await self.env.WHEELGUARD_DB.prepare("SELECT key, value FROM settings").raw()
        overrides = decode_stored_settings(_python(raw))
        defaults = EdgeSettings.from_env(self.env).editable_values()
        return Response.from_json({"settings": setting_catalog(defaults, overrides)}, headers=JSON_HEADERS)

    async def _update_settings(self, request: Any, actor: str) -> Response:
        """Validate, persist, and audit a partial runtime settings update."""
        rejected = _reject_cross_origin_write(request)
        if rejected is not None:
            return rejected
        if not (request.headers.get("content-type") or "").casefold().startswith("application/json"):
            return _error("Content-Type must be application/json", 415)
        try:
            updates = parse_settings_update(await _read_json_body(request))
        except (InvalidJsonBodyError, InvalidSettingsError) as error:
            return _error(str(error), 422)
        occurred_at = _now()
        audit_id = str(uuid4())
        details = json.dumps({"updates": updates}, separators=(",", ":"), sort_keys=True)
        statements = [
            self.env.WHEELGUARD_DB.prepare(
                """
                INSERT INTO settings (key, value)
                VALUES (?1, ?2)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """
            ).bind(key, value)
            for key, value in updates.items()
        ]
        statements.append(
            self.env.WHEELGUARD_DB.prepare(
                """
                INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details)
                VALUES (?1, 'settings.updated', ?2, ?3, NULL, ?4)
                """
            ).bind(audit_id, actor, occurred_at, details)
        )
        await self.env.WHEELGUARD_DB.batch(statements)
        return await self._list_settings()

    async def _reset_setting(self, request: Any, actor: str, key: str) -> Response:
        """Remove one runtime override and audit the reset to its deployment default."""
        rejected = _reject_cross_origin_write(request)
        if rejected is not None:
            return rejected
        if key not in SETTING_DEFINITIONS:
            return _error("Setting not found", 404)
        occurred_at = _now()
        details = json.dumps({"reset": key}, separators=(",", ":"), sort_keys=True)
        await self.env.WHEELGUARD_DB.batch(
            [
                self.env.WHEELGUARD_DB.prepare("DELETE FROM settings WHERE key = ?1").bind(key),
                self.env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details)
                    VALUES (?1, 'settings.reset', ?2, ?3, NULL, ?4)
                    """
                ).bind(str(uuid4()), actor, occurred_at, details),
            ]
        )
        return await self._list_settings()

    async def _create_override(self, request: Any, actor: str) -> Response:
        """Create and audit a release-policy override."""
        rejected = _reject_cross_origin_write(request)
        if rejected is not None:
            return rejected
        if not (request.headers.get("content-type") or "").casefold().startswith("application/json"):
            return _error("Content-Type must be application/json", 415)
        try:
            body = await _read_json_body(request)
            override = parse_override_request(body)
        except (InvalidJsonBodyError, InvalidOverrideError) as error:
            return _error(str(error), 422)

        override_id = str(uuid4())
        audit_id = str(uuid4())
        occurred_at = _now()
        details = json.dumps(
            {
                "action": override.action,
                "expires_at": override.expires_at,
                "project": override.project,
                "reason": override.reason,
                "version": override.version,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        await self.env.WHEELGUARD_DB.batch(
            [
                self.env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO policy_overrides
                        (id, project, version, action, reason, created_at, created_by, expires_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    """
                ).bind(
                    override_id,
                    override.project,
                    override.version,
                    override.action,
                    override.reason,
                    occurred_at,
                    actor,
                    override.expires_at,
                ),
                self.env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO policy_audit
                        (id, event_type, actor, occurred_at, override_id, details)
                    VALUES (?1, 'override.created', ?2, ?3, ?4, ?5)
                    """
                ).bind(audit_id, actor, occurred_at, override_id, details),
            ]
        )
        return Response.from_json(
            {
                "id": override_id,
                "override": {
                    "action": override.action,
                    "expires_at": override.expires_at,
                    "project": override.project,
                    "reason": override.reason,
                    "version": override.version,
                },
            },
            status=201,
            headers=JSON_HEADERS,
        )

    async def _revoke_override(self, request: Any, actor: str, override_id: str) -> Response:
        """Revoke an active override while preserving its audit history."""
        rejected = _reject_cross_origin_write(request)
        if rejected is not None:
            return rejected
        if not override_id:
            return _error("Override id is required", 404)
        existing = (
            await self.env.WHEELGUARD_DB.prepare("SELECT id FROM policy_overrides WHERE id = ?1 AND revoked_at IS NULL")
            .bind(override_id)
            .first("id")
        )
        if existing is None:
            return _error("Active override not found", 404)

        occurred_at = _now()
        audit_id = str(uuid4())
        await self.env.WHEELGUARD_DB.batch(
            [
                self.env.WHEELGUARD_DB.prepare(
                    """
                    UPDATE policy_overrides
                    SET revoked_at = ?1, revoked_by = ?2, revoke_reason = 'Revoked from admin UI'
                    WHERE id = ?3 AND revoked_at IS NULL
                    """
                ).bind(occurred_at, actor, override_id),
                self.env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO policy_audit
                        (id, event_type, actor, occurred_at, override_id, details)
                    VALUES (?1, 'override.revoked', ?2, ?3, ?4, '{}')
                    """
                ).bind(audit_id, actor, occurred_at, override_id),
            ]
        )
        return Response(status=204)

    async def _replace_override(self, request: Any, actor: str, override_id: str) -> Response:
        """Atomically replace an active override while preserving its audit history."""
        rejected = _reject_cross_origin_write(request)
        if rejected is not None:
            return rejected
        if not (request.headers.get("content-type") or "").casefold().startswith("application/json"):
            return _error("Content-Type must be application/json", 415)
        if not override_id:
            return _error("Override id is required", 404)
        existing = (
            await self.env.WHEELGUARD_DB.prepare("SELECT id FROM policy_overrides WHERE id = ?1 AND revoked_at IS NULL")
            .bind(override_id)
            .first("id")
        )
        if existing is None:
            return _error("Active override not found", 404)
        try:
            replacement = parse_override_request(await _read_json_body(request))
        except (InvalidJsonBodyError, InvalidOverrideError) as error:
            return _error(str(error), 422)

        occurred_at = _now()
        replacement_id = str(uuid4())
        replacement_details = {
            "action": replacement.action,
            "expires_at": replacement.expires_at,
            "project": replacement.project,
            "reason": replacement.reason,
            "replaces": override_id,
            "version": replacement.version,
        }
        await self.env.WHEELGUARD_DB.batch(
            [
                self.env.WHEELGUARD_DB.prepare(
                    """
                    UPDATE policy_overrides
                    SET revoked_at = ?1, revoked_by = ?2, revoke_reason = 'Replaced from admin UI'
                    WHERE id = ?3 AND revoked_at IS NULL
                    """
                ).bind(occurred_at, actor, override_id),
                self.env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO policy_overrides
                        (id, project, version, action, reason, created_at, created_by, expires_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    """
                ).bind(
                    replacement_id,
                    replacement.project,
                    replacement.version,
                    replacement.action,
                    replacement.reason,
                    occurred_at,
                    actor,
                    replacement.expires_at,
                ),
                self.env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details)
                    VALUES (?1, 'override.revoked', ?2, ?3, ?4, ?5)
                    """
                ).bind(
                    str(uuid4()),
                    actor,
                    occurred_at,
                    override_id,
                    json.dumps(
                        {"reason": "Replaced from admin UI", "replacement_id": replacement_id},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                ),
                self.env.WHEELGUARD_DB.prepare(
                    """
                    INSERT INTO policy_audit (id, event_type, actor, occurred_at, override_id, details)
                    VALUES (?1, 'override.created', ?2, ?3, ?4, ?5)
                    """
                ).bind(
                    str(uuid4()),
                    actor,
                    occurred_at,
                    replacement_id,
                    json.dumps(replacement_details, separators=(",", ":"), sort_keys=True),
                ),
            ]
        )
        return Response.from_json(
            {"id": replacement_id, "override": replacement_details},
            status=200,
            headers=JSON_HEADERS,
        )


class InvalidJsonBodyError(ValueError):
    """Indicate that an administrator request body is invalid or too large."""


async def _read_json_body(request: Any, *, maximum_bytes: int = 16_384) -> Any:
    """Read a size-bounded administrator JSON request body."""
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(str(declared))
        except ValueError as error:
            raise InvalidJsonBodyError("Content-Length must be an integer") from error
        if declared_size < 0 or declared_size > maximum_bytes:
            raise InvalidJsonBodyError("Request body is too large")
    text = await request.text()
    if len(text.encode("utf-8")) > maximum_bytes:
        raise InvalidJsonBodyError("Request body is too large")
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise InvalidJsonBodyError("Request body must be valid JSON") from error


def _python(value: Any) -> Any:
    """Convert a JavaScript proxy to native Python when required by Pyodide."""
    converter = getattr(value, "to_py", None)
    return converter() if callable(converter) else value


def _reject_cross_origin_write(request: Any) -> Response | None:
    """Require browser evidence that an administrator write is same-origin."""
    origin = request.headers.get("origin")
    fetch_site = (request.headers.get("sec-fetch-site") or "").casefold()
    target = urlsplit(request.url)
    expected = f"{target.scheme}://{target.netloc}"
    if origin == expected or (origin is None and fetch_site == "same-origin"):
        return None
    if origin is None and not fetch_site:
        return _error("Administrator writes require Origin or Sec-Fetch-Site", 403)
    return _error("Cross-origin administrator writes are not allowed", 403)


def _now() -> str:
    """Return the current UTC timestamp in an interoperable form."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _error(message: str, status: int) -> Response:
    """Build a non-cacheable JSON error response."""
    return Response.from_json({"detail": message}, status=status, headers=JSON_HEADERS)


def _admin_page(actor: str) -> Response:
    """Render the deliberately small administrator interface."""
    safe_actor = html.escape(actor)
    nonce = secrets.token_urlsafe(24)
    body = _ADMIN_HTML.replace("{{ actor }}", safe_actor).replace("{{ nonce }}", nonce)
    return Response(
        body,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": admin_content_security_policy(nonce),
            "Content-Type": "text/html; charset=utf-8",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


_ADMIN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Wheelguard policy</title>
  <style>
    :root { color-scheme: light dark; --border: #c7c7c7; --error: #b00020; --success: #137333;
      --surface: #f5f5f5; }
    @media (prefers-color-scheme: dark) {
      :root { --border: #5f6368; --error: #ffb4ab; --success: #81c995; --surface: #202124; }
    }
    * { box-sizing: border-box; }
    body { background: Canvas; color: CanvasText; font: 16px/1.45 system-ui, sans-serif; margin: 2rem auto;
      max-width: 72rem; padding: 0 1.25rem 3rem; }
    h1 { margin-bottom: .35rem; } h2 { margin: 2rem 0 .35rem; }
    form { display: grid; gap: 1rem; grid-template-columns: repeat(2, minmax(16rem, 1fr)); margin: 1.5rem 0; }
    label { display: grid; font-weight: 600; gap: .35rem; } .wide { grid-column: 1 / -1; }
    input, select, button { border: 1px solid var(--border); border-radius: .4rem; font: inherit; min-height: 2.75rem;
      padding: .55rem .7rem; }
    input, select { background: Field; color: FieldText; width: 100%; }
    button { background: ButtonFace; color: ButtonText; cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .55; }
    button:not(:disabled):hover { filter: brightness(.96); }
    button:focus-visible, input:focus-visible, select:focus-visible {
      outline: 3px solid Highlight; outline-offset: 2px;
    }
    .setting { background: var(--surface); border: 1px solid var(--border); border-radius: .55rem; display: flex;
      flex-direction: column; gap: .55rem; padding: 1rem; }
    .setting small { color: GrayText; flex: 1; min-height: 3em; }
    .setting button, #create button { width: 100%; }
    .form-actions, .row-actions { display: flex; gap: .5rem; }
    .form-actions { grid-column: 1 / -1; } .form-actions button { flex: 1; }
    .muted { color: GrayText; }
    .history-toggle { align-items: center; display: flex; font-weight: 400; margin: 1rem 0; }
    .history-toggle input { min-height: auto; width: auto; }
    .status { display: block; grid-column: 1 / -1; min-height: 1.5rem; }
    .error { color: var(--error); } .success { color: var(--success); }
    .table-wrap { overflow-x: auto; } table { border-collapse: collapse; min-width: 48rem; width: 100%; }
    th, td { border-bottom: 1px solid var(--border); padding: .75rem; text-align: left; vertical-align: top; }
    th { background: var(--surface); }
    @media (max-width: 700px) {
      body { margin-top: 1rem; } form { grid-template-columns: 1fr; } .wide { grid-column: auto; }
      .setting small { min-height: auto; }
    }
  </style>
</head>
<body>
  <h1>Wheelguard administration</h1>
  <p>Signed in through Cloudflare Access as <strong>{{ actor }}</strong>.</p>
  <h2>Runtime policy settings</h2>
  <p>These values take effect on the next repository request. Resetting a value restores its deployment default.</p>
  <form id="settings"></form>
  <p>
    <button id="save-settings" type="button" disabled>Save settings</button>
    <span id="settings-status" class="status" role="status" aria-live="polite"></span>
  </p>
  <h2>Release overrides</h2>
  <p class="muted">Active overrides can be replaced or revoked. Expired and revoked records remain as audit history.</p>
  <form id="create">
    <label>Project (required) <input name="project" maxlength="200" required></label>
    <label>Version (required) <input name="version" maxlength="200" required></label>
    <label>Action (required) <select name="action" required>
      <option value="block">Block</option><option value="allow">Allow</option>
    </select></label>
    <label>Expires at (optional) <input name="expires_at" type="datetime-local"></label>
    <label class="wide">Reason (required) <input name="reason" maxlength="500" required></label>
    <div class="form-actions">
      <button id="submit-override" type="submit">Create override</button>
      <button id="cancel-edit" type="button" hidden>Cancel edit</button>
    </div>
    <span id="status" class="status" role="status" aria-live="polite"></span>
  </form>
  <label class="history-toggle">
    <input id="show-history" type="checkbox"> Show expired, replaced, and revoked history
  </label>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Project</th><th>Version</th><th>Action</th><th>Reason</th><th>Created (local)</th>
          <th>Expires (local)</th><th>Status</th><th>Actions</th></tr>
      </thead>
      <tbody id="overrides"></tbody>
    </table>
  </div>
  <script nonce="{{ nonce }}">
    const status = document.querySelector('#status');
    const settingsStatus = document.querySelector('#settings-status');
    const saveSettings = document.querySelector('#save-settings');
    const overrideForm = document.querySelector('#create');
    const submitOverride = document.querySelector('#submit-override');
    const cancelEdit = document.querySelector('#cancel-edit');
    const showHistory = document.querySelector('#show-history');
    const integerFormatter = new Intl.NumberFormat('en-US');
    const timestampFormatter = new Intl.DateTimeFormat(undefined, {dateStyle: 'medium', timeStyle: 'medium'});
    let editingOverride = null;
    let overrideRows = [];
    function showStatus(element, message, kind = '') {
      element.textContent = message;
      element.className = `status ${kind}`.trim();
    }
    async function requestJson(url, options = undefined) {
      let response;
      try {
        response = await fetch(url, options);
      } catch (error) {
        throw new Error(`Could not reach the administrator API: ${error.message}`);
      }
      let body = null;
      if (response.status !== 204) {
        try { body = await response.json(); } catch { body = null; }
      }
      if (!response.ok) throw new Error(body?.detail || `Request failed with HTTP ${response.status}`);
      return body;
    }
    function normalizedSettingValue(input) {
      return input.inputMode === 'numeric' ? input.value.replaceAll(',', '').replaceAll('_', '') : input.value;
    }
    function formatTimestamp(value) {
      const timestamp = new Date(value);
      return Number.isNaN(timestamp.valueOf()) ? value : timestampFormatter.format(timestamp);
    }
    function datetimeLocalValue(value) {
      if (!value) return '';
      const timestamp = new Date(value);
      if (Number.isNaN(timestamp.valueOf())) return '';
      const local = new Date(timestamp.valueOf() - timestamp.getTimezoneOffset() * 60_000);
      return local.toISOString().slice(0, 16);
    }
    function resetOverrideEditor() {
      editingOverride = null; overrideForm.reset(); submitOverride.textContent = 'Create override';
      cancelEdit.hidden = true;
    }
    async function loadSettings() {
      const {settings} = await requestJson('/admin/api/settings');
      const form = document.querySelector('#settings'); form.replaceChildren();
      for (const setting of settings) {
        const card = document.createElement('section'); card.className = 'setting';
        const label = document.createElement('label'); label.textContent = setting.label;
        label.htmlFor = `setting-${setting.key}`;
        let input;
        if (setting.kind === 'boolean') {
          input = document.createElement('select');
          for (const value of ['true', 'false']) {
            const option = document.createElement('option'); option.value = value; option.textContent = value;
            option.selected = String(setting.value) === value; input.append(option);
          }
        } else {
          input = document.createElement('input'); input.type = 'text'; input.inputMode = 'numeric';
          input.pattern = '[0-9][0-9,_]*'; input.value = integerFormatter.format(setting.value);
          input.oninput = () => {
            const value = Number(normalizedSettingValue(input));
            const valid = Number.isSafeInteger(value) && value >= setting.minimum && value <= setting.maximum;
            const minimum = integerFormatter.format(setting.minimum);
            const maximum = integerFormatter.format(setting.maximum);
            input.setCustomValidity(valid ? '' : `Enter ${minimum}–${maximum}.`);
          };
          input.onblur = () => {
            const value = Number(normalizedSettingValue(input));
            if (Number.isSafeInteger(value)) input.value = integerFormatter.format(value);
          };
        }
        input.id = `setting-${setting.key}`; input.name = setting.key; input.title = setting.description;
        input.required = true; input.dataset.initial = String(setting.value);
        const detail = document.createElement('small');
        const suffix = setting.overridden ? ' Overridden.' : '';
        const defaultValue = setting.kind === 'integer' ? integerFormatter.format(setting.default) : setting.default;
        const limits = setting.kind === 'integer'
          ? ` Allowed: ${integerFormatter.format(setting.minimum)}–${integerFormatter.format(setting.maximum)}.` : '';
        detail.textContent = `${setting.description} Default: ${defaultValue}.${limits}${suffix}`;
        const reset = document.createElement('button'); reset.type = 'button'; reset.textContent = 'Reset to default';
        reset.disabled = !setting.overridden;
        reset.onclick = async () => {
          showStatus(settingsStatus, `Resetting ${setting.label}...`);
          try {
            await requestJson(`/admin/api/settings/${setting.key}`, {method: 'DELETE'});
            showStatus(settingsStatus, `${setting.label} reset to its deployment default.`, 'success');
            await loadSettings();
          } catch (error) {
            showStatus(settingsStatus, error.message, 'error');
          }
        };
        card.append(label, input, detail, reset); form.append(card);
      }
      saveSettings.disabled = false;
    }
    saveSettings.onclick = async () => {
      const form = document.querySelector('#settings');
      if (!form.reportValidity()) {
        showStatus(settingsStatus, 'Correct the invalid setting values before saving.', 'error');
        return;
      }
      const data = Object.fromEntries(
        [...form.elements]
          .filter(input => input.name && normalizedSettingValue(input) !== input.dataset.initial)
          .map(input => [input.name, input.value])
      );
      if (Object.keys(data).length === 0) {
        showStatus(settingsStatus, 'No setting values changed.');
        return;
      }
      showStatus(settingsStatus, 'Saving settings...');
      try {
        await requestJson('/admin/api/settings', {
          method: 'PATCH', headers: {'content-type': 'application/json'}, body: JSON.stringify(data)
        });
        showStatus(settingsStatus, 'Settings saved and active for the next repository request.', 'success');
        await loadSettings();
      } catch (error) {
        showStatus(settingsStatus, error.message, 'error');
      }
    };
    function overrideState(row) {
      if (row.revoked_at) return row.revoke_reason === 'Replaced from admin UI' ? 'Replaced' : 'Revoked';
      if (row.expires_at && new Date(row.expires_at).valueOf() <= Date.now()) return 'Expired';
      return 'Active';
    }
    function beginOverrideEdit(row) {
      editingOverride = row;
      overrideForm.elements.project.value = row.project;
      overrideForm.elements.version.value = row.version;
      overrideForm.elements.action.value = row.action;
      overrideForm.elements.expires_at.value = datetimeLocalValue(row.expires_at);
      overrideForm.elements.reason.value = row.reason;
      submitOverride.textContent = 'Save replacement'; cancelEdit.hidden = false;
      showStatus(status, `Editing active override for ${row.project} ${row.version}.`);
      overrideForm.scrollIntoView({behavior: 'smooth', block: 'start'});
    }
    function renderOverrides() {
      const tbody = document.querySelector('#overrides'); tbody.replaceChildren();
      const rows = overrideRows.filter(row => showHistory.checked || overrideState(row) === 'Active');
      if (rows.length === 0) {
        const message = showHistory.checked ? 'No release overrides yet.' : 'No active release overrides.';
        const cell = document.createElement('td'); cell.colSpan = 8; cell.textContent = message;
        const row = document.createElement('tr'); row.append(cell); tbody.append(row); return;
      }
      for (const row of rows) {
        const tr = document.createElement('tr');
        for (const value of [row.project, row.version, row.action, row.reason]) {
          const td = document.createElement('td'); td.textContent = value; tr.append(td);
        }
        const created = document.createElement('td');
        const timestamp = document.createElement('time'); timestamp.dateTime = row.created_at;
        timestamp.textContent = formatTimestamp(row.created_at); timestamp.title = row.created_at;
        created.append(timestamp); tr.append(created);
        const expires = document.createElement('td');
        if (row.expires_at) {
          const timestamp = document.createElement('time'); timestamp.dateTime = row.expires_at;
          timestamp.textContent = formatTimestamp(row.expires_at); timestamp.title = row.expires_at;
          expires.append(timestamp);
        } else {
          expires.textContent = 'Never';
        }
        tr.append(expires);
        const state = overrideState(row);
        const stateCell = document.createElement('td'); stateCell.textContent = state; tr.append(stateCell);
        const action = document.createElement('td');
        action.className = 'row-actions';
        if (state === 'Active') {
          const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = 'Edit';
          edit.onclick = () => { beginOverrideEdit(row); };
          const revoke = document.createElement('button'); revoke.type = 'button'; revoke.textContent = 'Revoke';
          revoke.onclick = async () => {
            showStatus(status, `Revoking ${row.action} for ${row.project} ${row.version}...`);
            try {
              await requestJson(`/admin/api/overrides/${row.id}`, {method: 'DELETE'});
              showStatus(status, `Revoked override for ${row.project} ${row.version}.`, 'success');
              if (editingOverride?.id === row.id) resetOverrideEditor();
              await loadOverrides();
            } catch (error) {
              showStatus(status, error.message, 'error');
            }
          };
          action.append(edit, revoke);
        }
        tr.append(action); tbody.append(tr);
      }
    }
    async function loadOverrides() {
      const raw = await requestJson('/admin/api/overrides');
      const [columns, ...values] = raw;
      overrideRows = values.map(value => Object.fromEntries(columns.map((column, index) => [column, value[index]])));
      renderOverrides();
    }
    showHistory.onchange = renderOverrides;
    cancelEdit.onclick = () => { resetOverrideEditor(); showStatus(status, 'Edit cancelled.'); };
    overrideForm.onsubmit = async event => {
      event.preventDefault();
      if (!event.target.reportValidity()) {
        showStatus(status, 'Complete every required field with a valid value.', 'error');
        return;
      }
      const data = Object.fromEntries(new FormData(event.target));
      if (data.expires_at) data.expires_at = new Date(data.expires_at).toISOString();
      const replaced = editingOverride;
      showStatus(status, replaced ? 'Replacing override...' : 'Creating override...');
      try {
        const url = replaced ? `/admin/api/overrides/${replaced.id}` : '/admin/api/overrides';
        const result = await requestJson(url, {
          method: replaced ? 'PATCH' : 'POST',
          headers: {'content-type': 'application/json'},
          body: JSON.stringify(data)
        });
        const created = result.override;
        const verb = replaced ? 'Replaced with' : 'Created';
        resetOverrideEditor();
        showStatus(status, `${verb} ${created.action} for ${created.project} ${created.version}.`, 'success');
        await loadOverrides();
      } catch (error) {
        showStatus(status, error.message, 'error');
      }
    };
    loadSettings().catch(error => { showStatus(settingsStatus, error.message, 'error'); });
    loadOverrides().catch(error => { showStatus(status, error.message, 'error'); });
  </script>
</body>
</html>
"""
