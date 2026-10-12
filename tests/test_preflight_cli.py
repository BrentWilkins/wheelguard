"""Test dependency-free uv lockfile preflight parsing."""

from pathlib import Path

from wheelguard.preflight_cli import _endpoint, projects_from_uv_lock


def test_uv_lock_parser_keeps_only_deduplicated_registry_packages(tmp_path: Path) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        """
version = 1

[[package]]
name = "local-project"
source = { editable = "." }

[[package]]
name = "Demo_Package"
version = "1.0"
source = { registry = "https://packages.example/simple" }

[[package]]
name = "Demo_Package"
version = "2.0"
source = { registry = "https://packages.example/simple" }

[[package]]
name = "Demo_Package"
version = "1.0"
source = { registry = "https://packages.example/simple" }
""",
        encoding="utf-8",
    )

    assert projects_from_uv_lock(lockfile) == [{"name": "Demo_Package", "versions": ["1.0", "2.0"]}]


def test_preflight_endpoint_strips_credentials_and_simple_suffix() -> None:
    endpoint, token = _endpoint("https://wheelguard:secret@packages.example/simple/")

    assert endpoint == "https://packages.example/preflight"
    assert token == "secret"
