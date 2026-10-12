"""Test dependency-free uv lockfile preflight parsing."""

from pathlib import Path

from wheelguard.preflight_cli import _endpoint, _print_result, projects_from_uv_lock


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


def test_preflight_failure_explains_package_reason_and_remediation(capsys) -> None:
    _print_result(
        {
            "status": "UNAVAILABLE",
            "projects": [
                {
                    "project": "pluggy",
                    "status": "UNAVAILABLE",
                    "advisories": "STALE",
                    "versions": ["1.6.0"],
                }
            ],
        }
    )

    captured = capsys.readouterr()
    assert captured.out == "preflight=UNAVAILABLE projects=1 unavailable=1\n"
    assert "pluggy==1.6.0: UNAVAILABLE" in captured.err
    assert "reason: a current vulnerability advisory evaluation could not be obtained" in captured.err
    assert "remediation: retry the preflight" in captured.err
    assert "Do not bypass the private index" in captured.err


def test_preflight_policy_denial_identifies_affected_version(capsys) -> None:
    _print_result(
        {
            "status": "DENIED",
            "projects": [
                {
                    "project": "demo-package",
                    "status": "POLICY_DENIED",
                    "versions": ["2.0"],
                    "policy_denied_versions": ["2.0"],
                }
            ],
        }
    )

    captured = capsys.readouterr()
    assert "demo-package==2.0: POLICY_DENIED" in captured.err
    assert "reason: the locked version is ineligible under WheelGuard release policy" in captured.err
    assert "time-bounded administrator override" in captured.err


def test_preflight_top_level_error_prints_server_detail(capsys) -> None:
    _print_result({"detail": "Advisory enforcement is disabled"})

    captured = capsys.readouterr()
    assert captured.err == "Wheelguard preflight failed: Advisory enforcement is disabled\n"
    assert captured.out == "preflight=ERROR projects=0\n"
