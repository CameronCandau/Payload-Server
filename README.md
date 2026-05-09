# payload-server

`payload-server` is a CLI for serving a local payload directory over HTTP or
SMB and generating copyable transfer targets during pentest and red-team
workflow.

It is designed to pair cleanly with `artifact-locker pull`:

```bash
artifact-locker pull
payload-server linux
payload-server windows 8000 443
```

By default it serves `~/tools/payloads`:

```text
~/tools/payloads/
├── linux/
│   └── pspy64
└── windows/
    ├── Rubeus.exe
    ├── RunasCs.exe
    ├── nc.exe
    ├── PowerView.ps1
    └── Invoke-ConPtyShell.ps1
```

## Install

Preferred:

```bash
pipx install payload-server
```

For local development:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## Usage

Use `payload-server` when you want to:

- serve a local payload directory over HTTP
- optionally expose the same directory over SMB
- save the active serving context for follow-on commands
- select a currently served file and copy its HTTP URL, SMB path, or local path

Serve Linux payloads over HTTP:

```bash
payload-server linux
```

Serve Windows payloads and write a staged ConPtyShell launcher:

```bash
payload-server windows 8000 443
```

Use SMB instead of HTTP:

```bash
payload-server windows --smb
```

Reuse the active serving context:

```bash
payload-server status
payload-server pick http
payload-server pick smb   # requires an active state started with --smb
payload-server pick local
payload-server pick ask
```

## Behavior

- Detects `tun0`, `tun1`, `wg0`, `tap0`, then `eth0` for `LHOST`
- Writes serving state to `~/.local/state/payload-server/state.json`
- Uses a fuzzy built-in HTTP server by default
- Supports `--updog` and `--plain-http` as alternate HTTP backends
- Uses `impacket-smbserver` or `smbserver.py` when `--smb` is enabled

## Optional Runtime Tools

Some features depend on tools that are discovered at runtime instead of being
hard install requirements:

- `rofi` for interactive picking
- `wl-copy`, `xclip`, or `xsel` for clipboard copy
- `tree` for compact directory previews
- `updog` for the alternate upload-capable HTTP backend
- `impacket-smbserver` or `smbserver.py` for SMB serving
- `ip` for interface and route based `LHOST` detection

If those tools are absent, the related feature fails with a direct error
message while the rest of the CLI remains usable.

## Relationship To artifact-locker

`payload-server` does not ship payloads. It serves a user-managed local
directory. The intended workflow is:

1. Curate and publish with `artifact-locker`
2. Pull the approved mirror locally with `artifact-locker pull`
3. Serve the synced directory with `payload-server`

Current `artifact-locker` builds keep the local payload tree flat
(`/windows/winpeas.exe`, `/windows/PowerView.ps1`). The fuzzy
server still understands older caches that used per-artifact UUID
subdirectories, so short paths continue to work during migration.

## Tests

```bash
python3 -m unittest discover -s tests
python3 -m compileall src tests
```
