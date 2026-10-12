"""Exercise private publication against real SQLite and bounded storage fakes."""

import asyncio
import base64
import hashlib
import importlib
import io
import json
import sqlite3
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from test_worker_integration import Access, FakeRequest, _edge_env
from test_worker_integration import worker_modules as worker_modules


class Statement:
    """Execute actual migration SQL behind the D1 binding interface."""

    def __init__(self, db: "Database", query: str) -> None:
        self.db, self.query = db, query
        self.values: tuple[Any, ...] = ()

    def bind(self, *values: Any) -> "Statement":
        self.values = values
        return self

    async def first(self) -> Any:
        row = self.db.connection.execute(self.query, self.values).fetchone()
        return dict(row) if row else None

    async def raw(self) -> Any:
        return [list(row) for row in self.db.connection.execute(self.query, self.values)]

    async def run(self) -> None:
        self.db.connection.execute(self.query, self.values)


class Database:
    """Provide transactional batches and production schema constraints."""

    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        for path in sorted(Path("migrations").glob("*.sql")):
            self.connection.executescript(path.read_text())
        self.fail_batch = False
        self.lose_response = False

    def prepare(self, query: str) -> Statement:
        return Statement(self, query)

    async def batch(self, statements: list[Statement]) -> None:
        self.connection.execute("BEGIN")
        try:
            for statement in statements:
                await statement.run()
            if self.fail_batch:
                raise RuntimeError("Simulated D1 failure")
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        if self.lose_response:
            raise RuntimeError("Lost commit response")


class Buffer:
    """Emulate Uint8Array without requiring Pyodide in unit tests."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.byteLength = len(data)

    def subarray(self, start: int, end: int) -> "Buffer":
        return Buffer(self.data[start:end])

    def to_bytes(self) -> bytes:
        return self.data


class Stream:
    """Supply deliberately fragmented input and track cancellation."""

    def __init__(self, data: bytes, chunk: int = 8191) -> None:
        self.data, self.chunk = data, chunk
        self.offset = 0
        self.cancelled = False

    def getReader(self) -> "Stream":
        return self

    async def read(self) -> Any:
        await asyncio.sleep(0)
        data = self.data[self.offset : self.offset + self.chunk]
        self.offset += len(data)
        return SimpleNamespace(done=not data, value=Buffer(data))

    async def cancel(self) -> None:
        self.cancelled = True

    def releaseLock(self) -> None:
        pass


class Multipart:
    """Require valid multipart ordering and sizes before object visibility."""

    def __init__(self, bucket: "Bucket", key: str) -> None:
        self.bucket, self.key = bucket, key
        self.parts: list[bytes] = []
        self.aborted = False

    async def uploadPart(self, number: int, data: bytes) -> Any:
        assert number == len(self.parts) + 1
        if self.bucket.fail_put:
            raise RuntimeError("Simulated R2 failure")
        self.parts.append(data)
        return {"partNumber": number, "etag": str(number)}

    async def complete(self, parts: list[Any]) -> None:
        assert len(parts) == len(self.parts)
        assert all(len(part) == 5 * 1024 * 1024 for part in self.parts[:-1])
        self.bucket.objects[self.key] = b"".join(self.parts)

    async def abort(self) -> None:
        self.aborted = True


class Bucket:
    """Keep private objects separate from catalog visibility."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.uploads: list[Multipart] = []
        self.fail_put = False

    async def createMultipartUpload(self, key: str) -> Multipart:
        upload = Multipart(self, key)
        self.uploads.append(upload)
        return upload

    async def delete(self, key: str) -> None:
        self.objects.pop(key, None)

    async def get(self, key: str, **options: Any) -> Any:
        if key not in self.objects:
            return None
        data = self.objects[key]
        if "range" in options:
            offset, length = options["range"]["offset"], options["range"]["length"]
            data = data[offset : offset + length]

        async def array_buffer() -> Buffer:
            return Buffer(data)

        return SimpleNamespace(body=Stream(data), size=len(data), arrayBuffer=array_buffer)


def distribution(
    name: str = "private_demo",
    version: str = "1.0",
    *,
    kind: str = "whl",
    embedded_name: str | None = None,
    extra: bytes = b"",
    changelog: bytes | None = None,
) -> tuple[str, bytes]:
    """Build a small valid distribution without executing a build backend."""
    metadata = (
        f"Metadata-Version: 2.3\nName: {embedded_name or name}\nVersion: {version}\nRequires-Python: >=3.10\n\n"
    ).encode()
    buffer = io.BytesIO()
    if kind == "tar.gz":
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo(f"{name}-{version}/PKG-INFO")
            info.size = len(metadata)
            archive.addfile(info, io.BytesIO(metadata))
            if changelog is not None:
                info = tarfile.TarInfo(f"{name}-{version}/CHANGELOG.md")
                info.size = len(changelog)
                archive.addfile(info, io.BytesIO(changelog))
        filename = f"{name}-{version}.tar.gz"
    else:
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            member = f"{name}-{version}.dist-info/METADATA" if kind == "whl" else f"{name}-{version}/PKG-INFO"
            archive.writestr(member, metadata)
            if changelog is not None and kind != "whl":
                archive.writestr(f"{name}-{version}/CHANGELOG.md", changelog)
            archive.writestr("payload", extra)
        filename = f"{name}-{version}-py3-none-any.whl" if kind == "whl" else f"{name}-{version}.zip"
    return filename, buffer.getvalue()


def upload_request(
    filename: str,
    content: bytes,
    *,
    name: str = "private_demo",
    version: str = "1.0",
    fields: dict[str, str] | None = None,
    token: str = "u" * 32,
) -> Any:
    """Encode the same multipart protocol used by publishing clients."""
    data = {
        ":action": "file_upload",
        "protocol_version": "1",
        "name": name,
        "version": version,
        "sha256_digest": hashlib.sha256(content).hexdigest(),
        **(fields or {}),
    }
    prepared = httpx.Request(
        "POST",
        "https://example.test/upload/",
        data=data,
        files={"content": (filename, content, "application/octet-stream")},
    )
    body = prepared.read()
    request = FakeRequest(
        str(prepared.url),
        method="POST",
        headers={"content-type": prepared.headers["content-type"], "authorization": f"Bearer {token}"},
    )
    request.body = Stream(body)
    return request


@pytest.fixture
def setup(worker_modules: tuple[Any, Any], monkeypatch: pytest.MonkeyPatch) -> Any:
    """Bind the real handler to real SQL and deterministic network/storage."""
    worker, index = worker_modules
    private = importlib.import_module("wheelguard.private_packages")
    db, bucket = Database(), Bucket()
    env = _edge_env(WHEELGUARD_DB=db, WHEELGUARD_ARTIFACTS=bucket, WHEELGUARD_UPLOAD_TOKEN="u" * 32)
    repository = index.CloudflareRepository(env)
    requests: list[str] = []

    async def missing(url: str, **options: Any) -> Any:
        requests.append(url)
        return SimpleNamespace(status=404)

    monkeypatch.setattr(private, "fetch", missing)
    app = worker.Default()
    app.env = env
    env.WHEELGUARD_ACCESS_AUD = "expected"
    app.ctx = SimpleNamespace(access=Access("expected"))
    return SimpleNamespace(
        app=app, repository=repository, db=db, bucket=bucket, env=env, requests=requests, private=private, worker=worker
    )


def read_request(path: str, *, method: str = "GET") -> Any:
    """Use a read-only repository credential."""
    return FakeRequest(
        f"https://example.test{path}",
        method=method,
        headers={"authorization": "Bearer " + "t" * 32, "accept": "application/vnd.pypi.simple.v1+json"},
    )


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["whl", "tar.gz", "zip"])
async def test_publish_resolve_and_download(setup: Any, kind: str) -> None:
    filename, content = distribution(kind=kind)
    response = await setup.app.fetch(upload_request(filename, content))
    assert response.status == 200, response.body
    assert setup.requests == ["https://pypi.org/simple/private-demo/"]
    listing = await setup.app.fetch(read_request("/simple/private-demo/"))
    file = json.loads(listing.body)["files"][0]
    assert file["requires-python"] == ">=3.10"
    assert file["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert listing.headers["x-wheelguard-advisories"] == "PRIVATE"
    download = await setup.app.fetch(read_request(file["url"].removeprefix("https://example.test")))
    assert download.status == 200
    assert download.body.data == content
    head = await setup.app.fetch(read_request(file["url"].removeprefix("https://example.test"), method="HEAD"))
    assert head.status == 200 and head.body is None
    root = await setup.app.fetch(read_request("/simple/"))
    assert {"name": "private-demo"} in json.loads(root.body)["projects"]


@pytest.mark.anyio
async def test_publish_records_standard_project_links(setup: Any) -> None:
    filename, content = distribution()
    response = await setup.app.fetch(
        upload_request(
            filename,
            content,
            fields={"project_urls": "Changelog, https://gitlab.example/acx/private-demo/-/blob/main/CHANGELOG.md"},
        )
    )

    assert response.status == 200
    row = setup.db.connection.execute(
        "SELECT repository_url, changelog_url FROM private_projects WHERE normalized_name = 'private-demo'"
    ).fetchone()
    assert tuple(row) == (None, "https://gitlab.example/acx/private-demo/-/blob/main/CHANGELOG.md")


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["tar.gz", "zip"])
async def test_publish_captures_bounded_sdist_changelog(setup: Any, kind: str) -> None:
    filename, content = distribution(kind=kind, changelog=b"# Changelog\n\n## 1.0\n\n- Initial release.\n")

    assert (await setup.app.fetch(upload_request(filename, content))).status == 200
    row = setup.db.connection.execute("SELECT project, version, content, format FROM private_changelogs").fetchone()
    assert tuple(row) == (
        "private-demo",
        "1.0",
        "# Changelog\n\n## 1.0\n\n- Initial release.\n",
        "markdown",
    )


@pytest.mark.anyio
async def test_identical_republish_can_backfill_project_links(setup: Any) -> None:
    filename, content = distribution()
    assert (await setup.app.fetch(upload_request(filename, content))).status == 200

    repeated = upload_request(
        filename,
        content,
        fields={"project_urls": "Repository, https://gitlab.example/acx/private-demo"},
    )
    assert (await setup.app.fetch(repeated)).status == 200
    row = setup.db.connection.execute(
        "SELECT repository_url FROM private_projects WHERE normalized_name = 'private-demo'"
    ).fetchone()
    assert row[0] == "https://gitlab.example/acx/private-demo"


@pytest.mark.anyio
async def test_collision_requires_audited_same_origin_approval(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    async def exists(*args: Any, **kwargs: Any) -> Any:
        return SimpleNamespace(status=200)

    monkeypatch.setattr(setup.private, "fetch", exists)
    filename, content = distribution()
    rejected = await setup.app.fetch(upload_request(filename, content, name="Private.Demo"))
    assert rejected.status == 409
    assert "hides all upstream releases" in rejected.body
    assert not setup.bucket.objects
    assert not setup.db.connection.execute("SELECT 1 FROM private_artifacts").fetchone()
    path = "https://example.test/admin/api/private-projects/private-demo/approve"
    foreign = FakeRequest(path, method="POST", headers={"origin": "https://evil.test"})
    assert (await setup.app.fetch(foreign)).status == 403
    setup.app.ctx.access = None
    assert (
        await setup.app.fetch(FakeRequest(path, method="POST", headers={"origin": "https://example.test"}))
    ).status == 403
    setup.app.ctx.access = Access("expected")
    assert (
        await setup.app.fetch(FakeRequest(path, method="POST", headers={"origin": "https://example.test"}))
    ).status == 200
    assert (
        await setup.app.fetch(FakeRequest(path, method="POST", headers={"origin": "https://example.test"}))
    ).status == 200
    rows = setup.db.connection.execute("SELECT actor FROM policy_audit WHERE event_type='private.collision-approved'")
    assert [row[0] for row in rows] == ["admin@example.com"]
    assert (await setup.app.fetch(upload_request(filename, content))).status == 200


@pytest.mark.anyio
@pytest.mark.parametrize("token", ["", "t" * 32, "wrong"])
async def test_read_tokens_cannot_publish(setup: Any, token: str) -> None:
    response = await setup.app.fetch(upload_request(*distribution(), token=token))
    assert response.status == 401
    assert not setup.bucket.uploads and not setup.requests


@pytest.mark.anyio
async def test_unconfigured_publishing_and_upload_token_read_access(setup: Any) -> None:
    setup.env.WHEELGUARD_UPLOAD_TOKEN = None
    assert (await setup.app.fetch(upload_request(*distribution()))).status == 503
    request = read_request("/simple/")
    request.headers["authorization"] = "Bearer " + "u" * 32
    assert (await setup.app.fetch(request)).status == 401


@pytest.mark.anyio
async def test_checksums_embedded_identity_and_size_limit(setup: Any) -> None:
    filename, content = distribution()
    bad = upload_request(filename, content, fields={"sha256_digest": "0" * 64})
    assert (await setup.app.fetch(bad)).status == 400
    assert setup.bucket.uploads[-1].aborted
    mismatch = upload_request(*distribution(embedded_name="different"))
    assert (await setup.app.fetch(mismatch)).status == 400
    assert not setup.bucket.objects
    setup.env.WHEELGUARD_MAXIMUM_ARTIFACT_BYTES = "10"
    request = upload_request(filename, content)
    assert (await setup.app.fetch(request)).status == 413
    assert request.body.cancelled
    assert not setup.db.connection.execute("SELECT 1 FROM private_projects").fetchone()


@pytest.mark.anyio
async def test_idempotent_retry_and_concurrent_conflict(setup: Any) -> None:
    filename, content = distribution()
    replies = await asyncio.gather(*(setup.app.fetch(upload_request(filename, content)) for _ in range(2)))
    assert [reply.status for reply in replies] == [200, 200]
    assert len(setup.bucket.objects) == 1
    changed_filename, changed = distribution(extra=b"different bytes")
    assert (await setup.app.fetch(upload_request(changed_filename, changed))).status == 409
    assert len(setup.bucket.objects) == 1
    assert setup.db.connection.execute("SELECT count(*) FROM policy_audit").fetchone()[0] == 1


@pytest.mark.anyio
@pytest.mark.parametrize("status", [429, 500, 301])
async def test_inconclusive_upstream_does_not_claim_name(
    setup: Any, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    async def unavailable(*args: Any, **kwargs: Any) -> Any:
        return SimpleNamespace(status=status)

    monkeypatch.setattr(setup.private, "fetch", unavailable)
    assert (await setup.app.fetch(upload_request(*distribution()))).status == 503
    assert not setup.bucket.objects
    assert not setup.db.connection.execute("SELECT 1 FROM private_projects").fetchone()


@pytest.mark.anyio
async def test_private_policy_and_old_public_urls(setup: Any) -> None:
    filename, content = distribution()
    assert (await setup.app.fetch(upload_request(filename, content))).status == 200
    setup.db.connection.execute(
        "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("a" * 64, filename, "https://files.pythonhosted.org/a", 1, "a" * 64, "private-demo", "1.0"),
    )
    old = read_request(f"/files/sha256/{'a' * 64}/{filename}")
    assert (await setup.app.fetch(old)).status == 403
    setup.db.connection.execute("""INSERT INTO policy_overrides
        (id, project, version, action, reason, created_at, created_by)
        VALUES ('block', 'private-demo', '1.0', 'block', 'test', '2020-01-01T00:00:00Z', 'admin')""")
    assert json.loads((await setup.app.fetch(read_request("/simple/private-demo/"))).body)["files"] == []
    url = f"/files/private/sha256/{hashlib.sha256(content).hexdigest()}/{filename}"
    assert (await setup.app.fetch(read_request(url))).status == 403
    setup.db.connection.execute("UPDATE policy_overrides SET action='allow'")
    assert (await setup.app.fetch(read_request(url))).status == 200
    assert (await setup.app.fetch(old)).status == 403
    setup.bucket.objects.clear()
    assert (await setup.app.fetch(read_request(url))).status == 503


@pytest.mark.anyio
async def test_storage_failure_and_ambiguous_database_commit(setup: Any) -> None:
    setup.bucket.fail_put = True
    assert (await setup.app.fetch(upload_request(*distribution()))).status == 503
    assert setup.bucket.uploads[-1].aborted
    assert not setup.db.connection.execute("SELECT 1 FROM private_projects").fetchone()
    setup.bucket.fail_put = False
    setup.db.lose_response = True
    assert (await setup.app.fetch(upload_request(*distribution()))).status == 503
    row = setup.db.connection.execute("SELECT object_key FROM private_artifacts").fetchone()
    assert row[0] in setup.bucket.objects
    setup.db.lose_response = False
    assert (await setup.app.fetch(upload_request(*distribution()))).status == 200
    assert len(setup.bucket.objects) == 1


@pytest.mark.anyio
async def test_database_failure_never_exposes_artifact(setup: Any) -> None:
    setup.db.fail_batch = True
    assert (await setup.app.fetch(upload_request(*distribution()))).status == 503
    assert not setup.db.connection.execute("SELECT 1 FROM private_artifacts").fetchone()
    assert setup.db.connection.execute("SELECT claimed_at FROM private_projects").fetchone()[0] is None


@pytest.mark.anyio
async def test_basic_auth_and_private_name_survives_upstream_outage(
    setup: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = upload_request(*distribution())
    request.headers["authorization"] = "Basic " + base64.b64encode(("__token__:" + "u" * 32).encode()).decode()
    assert (await setup.app.fetch(request)).status == 200
    setup.db.connection.execute(
        "INSERT INTO projects VALUES (?, ?, NULL, ?)",
        ("private-demo", '{"name":"private-demo","files":[{"filename":"public-9.0.tar.gz"}]}', "2020-01-01T00:00:00Z"),
    )

    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Private projects must not query upstream")

    monkeypatch.setattr(setup.private, "fetch", fail)
    assert (await setup.app.fetch(upload_request(*distribution(version="2.0"), version="2.0"))).status == 200
    listing = json.loads((await setup.app.fetch(read_request("/simple/private-demo/"))).body)
    assert listing["versions"] == ["1.0", "2.0"]
    assert len(listing["files"]) == 2
    request = read_request("/simple/private-demo/")
    request.headers["accept"] = "text/html"
    html = await setup.app.fetch(request)
    assert html.status == 200 and "data-requires-python" in html.body


@pytest.mark.anyio
async def test_large_stream_and_truncated_multipart(setup: Any) -> None:
    # Deterministic incompressible data crosses the R2 minimum part boundary.
    import random

    filename, content = distribution(extra=random.Random(42).randbytes(6 * 1024 * 1024))
    assert (await setup.app.fetch(upload_request(filename, content))).status == 200
    assert len(setup.bucket.uploads[-1].parts) == 2
    request = upload_request(*distribution(version="2.0"), version="2.0")
    request.body.data = request.body.data[:-10]
    assert (await setup.app.fetch(request)).status == 400
    assert setup.bucket.uploads[-1].aborted


@pytest.mark.anyio
async def test_distinct_upstream_collision_is_checked(setup: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    setup.env.WHEELGUARD_UPSTREAM_URL = "https://upstream.example/simple/"
    checked = []

    async def collision(url: str, **kwargs: Any) -> Any:
        checked.append(url)
        return SimpleNamespace(status=200 if "upstream.example" in url else 404)

    monkeypatch.setattr(setup.private, "fetch", collision)
    assert (await setup.app.fetch(upload_request(*distribution()))).status == 409
    assert len(checked) == 2
    row = setup.db.connection.execute("SELECT collisions, claimed_at FROM private_projects").fetchone()
    assert json.loads(row["collisions"]) == ["https://upstream.example/simple/private-demo/"]
    assert row["claimed_at"] is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "fields",
    [
        {"version": "2.0"},
        {":action": "submit"},
        {"md5_digest": "invalid"},
        {"blake2_256_digest": "invalid"},
        {"filetype": "sdist"},
        {"attestations": "[]"},
    ],
)
async def test_invalid_publish_fields_never_claim_a_name(setup: Any, fields: dict[str, str]) -> None:
    assert (await setup.app.fetch(upload_request(*distribution(), fields=fields))).status == 400
    assert not setup.db.connection.execute("SELECT 1 FROM private_projects").fetchone()
    assert not setup.bucket.objects


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["whl", "tar.gz", "zip"])
async def test_truncated_archives_never_publish(setup: Any, kind: str) -> None:
    filename, data = distribution(kind=kind)
    assert (await setup.app.fetch(upload_request(filename, data[: len(data) // 2]))).status == 400
    assert not setup.bucket.objects
    assert not setup.db.connection.execute("SELECT 1 FROM private_projects").fetchone()


@pytest.mark.anyio
async def test_oversized_zip_metadata_is_rejected(setup: Any) -> None:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("private_demo-1.0.dist-info/METADATA", b"x" * (1024 * 1024 + 1))
    response = await setup.app.fetch(upload_request("private_demo-1.0-py3-none-any.whl", data.getvalue()))
    assert response.status == 400
    assert "oversized" in response.body
    assert not setup.bucket.objects


@pytest.mark.anyio
async def test_gzip_trailing_data_is_rejected_without_reading_remainder(setup: Any) -> None:
    filename, content = distribution(kind="tar.gz")
    response = await setup.app.fetch(upload_request(filename, content + b"trailing data" * 10000))
    assert response.status == 400
    assert "gzip end marker" in response.body
    assert not setup.bucket.objects
