---
icon: lucide/package-check
---

# Get started

The Wheelguard index is:

```text
https://packages.example.com/simple/
```

You must be connected to the network that hosts your Wheelguard deployment. The service should use
a publicly trusted TLS certificate, so do not disable certificate verification
or add a `trusted-host` exception.

## Configure uv in `pyproject.toml`

Add this block to your project's `pyproject.toml`:

```toml
[[tool.uv.index]]
name = "wheelguard"
url = "https://packages.example.com/simple/"
default = true
```

Then manage dependencies normally:

```shell
uv add httpx
uv sync
```

`default = true` makes Wheelguard the project's default index and disables uv's
built-in PyPI default. Do not add PyPI as an extra index: doing so would create
a routine path around Wheelguard policy.

If your team receives a repository credential later, keep it out of
`pyproject.toml` and lockfiles:

=== "PowerShell"

    ```powershell
    $env:UV_INDEX_WHEELGUARD_USERNAME = "wheelguard"
    $env:UV_INDEX_WHEELGUARD_PASSWORD = "<token from your secret manager>"
    uv sync
    ```

=== "bash / WSL"

    ```shell
    export UV_INDEX_WHEELGUARD_USERNAME=wheelguard
    export UV_INDEX_WHEELGUARD_PASSWORD='<token from your secret manager>'
    uv sync
    ```

## Configure pip

pip does not read index settings from `pyproject.toml`. Configure Wheelguard in
the active virtual environment so the setting stays with that environment:

=== "Windows PowerShell"

    ```powershell
    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    py -m pip config --site set global.index-url https://packages.example.com/simple/
    py -m pip install -r requirements.txt
    ```

=== "bash / WSL"

    ```shell
    python -m venv .venv
    . .venv/bin/activate
    python -m pip config --site set global.index-url https://packages.example.com/simple/
    python -m pip install -r requirements.txt
    ```

Confirm the active setting:

```shell
python -m pip config debug
```

!!! warning "Do not use extra-index-url for PyPI"

    pip does not treat `--extra-index-url` as a strict priority fallback. It
    considers candidates across indexes, which can bypass Wheelguard and can
    enable dependency-confusion attacks. Normal configuration should contain
    only the Wheelguard index.

## Quick connection test

Use a dry run so nothing is installed:

```shell
uv pip install --dry-run --index-url https://packages.example.com/simple/ idna
```

An HTTP `401` means your environment requires a repository credential. A DNS or
connection error usually means the VPN or private network is unavailable.

If Wheelguard itself is unavailable, restore the service rather than adding a
second index that bypasses its policy.
