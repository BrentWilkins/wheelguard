from wheelguard.simple_api import (
    SIMPLE_HTML,
    SIMPLE_JSON,
    html_response_media_type,
    negotiate_content_type,
    render_project_html,
)


def test_content_negotiation() -> None:
    assert negotiate_content_type(f"{SIMPLE_HTML}, {SIMPLE_JSON}") == SIMPLE_JSON
    assert negotiate_content_type(f"{SIMPLE_JSON};q=0.1, {SIMPLE_HTML};q=0.9") == SIMPLE_HTML
    assert negotiate_content_type("image/png") is None


def test_uses_browser_html_without_changing_explicit_simple_client_type() -> None:
    assert html_response_media_type("text/html,application/xhtml+xml,*/*;q=0.8") == "text/html"
    assert html_response_media_type(f"{SIMPLE_HTML},text/html;q=0.1") == SIMPLE_HTML


def test_html_preserves_file_metadata() -> None:
    html = render_project_html(
        {
            "meta": {"api-version": "1.4"},
            "name": "demo",
            "files": [
                {
                    "filename": "demo-1.0.tar.gz",
                    "url": "https://files.example/demo-1.0.tar.gz",
                    "hashes": {"sha256": "abc"},
                    "requires-python": ">=3.12",
                    "yanked": "bad build",
                    "core-metadata": {"sha256": "def"},
                    "provenance": "https://files.example/demo.provenance",
                    "wheelguard-advisories": ["GHSA-test-0001", "PYSEC-2"],
                }
            ],
        }
    )
    assert "#sha256=abc" in html
    assert 'data-requires-python="&gt;=3.12"' in html
    assert 'data-yanked="bad build"' in html
    assert 'data-core-metadata="sha256=def"' in html
    assert 'data-provenance="https://files.example/demo.provenance"' in html
    assert 'data-wheelguard-advisories="GHSA-test-0001,PYSEC-2"' in html
