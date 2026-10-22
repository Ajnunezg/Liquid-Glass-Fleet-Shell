#!/usr/bin/env python3
"""
Autonomous Fleet Discovery & Bootstrapper (bootstrap-fleet.py)
Designed so any user (or their AI coding agent) can run:
  python3 scripts/bootstrap-fleet.py --auto
to discover their Mac(s), SSH hosts, Tailscale mesh, cmux Cloud VMs,
start the Fleet Hub daemon, and build/install the native iOS & macOS apps.
"""
import argparse
import json
import os
import pathlib
import re
import secrets
import socket
import subprocess
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SAFE_SSH_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REMOTE_PROBE_SCRIPT = "hostname && sysctl -n machdep.cpu.brand_string hw.memsize 2>/dev/null || uname -m"


def run_argv(argv: list[str], timeout: float = 5.0) -> str:
    try:
        return subprocess.check_output(
            argv,
            timeout=timeout,
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def discover_tailscale_ip() -> str:
    for binary in ("/Applications/Tailscale.app/Contents/MacOS/Tailscale", "tailscale"):
        out = run_argv([binary, "ip", "-4"], timeout=3.0)
        if out:
            return out.splitlines()[0].strip()
    return ""


def discover_fleet() -> dict[str, Any]:
    hostname = socket.gethostname().split(".")[0]
    chip = run_argv(["sysctl", "-n", "machdep.cpu.brand_string"]) or "Apple Silicon / Host CPU"
    mem_bytes = run_argv(["sysctl", "-n", "hw.memsize"])
    ram_gb = round(int(mem_bytes) / (1024 ** 3), 1) if mem_bytes.isdigit() else 16.0
    lan_ip = run_argv(["ipconfig", "getifaddr", "en0"]) or run_argv(["ipconfig", "getifaddr", "en1"]) or "127.0.0.1"
    ts_ip = discover_tailscale_ip()

    machines: list[dict[str, Any]] = [
        {
            "id": "primary-mac",
            "name": hostname,
            "mode": "local",
            "chip": chip,
            "ram_gb": ram_gb,
            "ip": f"{lan_ip}" + (f" • {ts_ip}" if ts_ip else ""),
        }
    ]

    ssh_cfg = pathlib.Path.home() / ".ssh/config"
    if ssh_cfg.exists():
        for raw_line in ssh_cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line.lower().startswith("host ") or "*" in line or "?" in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            alias = parts[1]
            if not SAFE_SSH_ALIAS_RE.match(alias):
                continue
            probe = run_argv(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=2",
                    "--",
                    alias,
                    REMOTE_PROBE_SCRIPT,
                ],
                timeout=3.5,
            )
            if probe:
                plines = probe.splitlines()
                rname = plines[0].split(".")[0]
                rchip = plines[1] if len(plines) > 1 else "Remote Host"
                rram = round(int(plines[2]) / (1024 ** 3), 1) if len(plines) > 2 and plines[2].isdigit() else 16.0
                machines.append({
                    "id": alias,
                    "name": rname,
                    "mode": "ssh",
                    "ssh_target": alias,
                    "chip": rchip,
                    "ram_gb": rram,
                    "ip": alias,
                })

    endpoints = [{"name": "Localhost", "url": "http://127.0.0.1:7778"}]
    if ts_ip:
        endpoints.insert(0, {"name": "Tailscale Direct", "url": f"https://{ts_ip}:8443"})

    return {
        "owner_name": f"{os.environ.get('USER', 'User')}'s Fleet",
        "bind_host": "127.0.0.1",
        "hub_port": 7778,
        "machines": machines,
        "endpoints": endpoints,
    }


def ensure_private_hub_token() -> pathlib.Path:
    state_dir = pathlib.Path.home() / ".config" / "fleet-hub"
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    token_path = state_dir / "token"
    if not token_path.exists() or len(token_path.read_text(encoding="utf-8").strip()) < 32:
        fd = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(secrets.token_hex(32) + "\n")
    os.chmod(token_path, 0o600)
    return token_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover and bootstrap Fleet Hub configuration.")
    parser.add_argument("--auto", action="store_true", help="Run non-interactive discovery")
    parser.add_argument("--force", action="store_true", help="Overwrite existing fleet.config.json")
    args = parser.parse_args()

    out_path = REPO_ROOT / "fleet.config.json"
    token_path = ensure_private_hub_token()
    if out_path.exists() and not args.force:
        os.chmod(out_path, 0o600)
        print(f"✓ Preserved existing {out_path} (pass --force to overwrite); token at {token_path}")
        return

    cfg = discover_fleet()
    fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(cfg, indent=2) + "\n")
    os.chmod(out_path, 0o600)
    print(f"✓ Generated {out_path} (mode 0600, token at {token_path}) with {len(cfg['machines'])} discovered machine(s):")
    for m in cfg["machines"]:
        print(f"  • {m['name']} ({m['chip']}, {m['ram_gb']} GB RAM) [{m['ip']}]")
    print("\nNext steps:")
    print("  1. Start the Fleet Hub: python3 scripts/fleet-hub.py &")
    print("  2. Build for iPhone:    (cd ios && xcodegen generate && open AlbertoCloud.xcodeproj)")


if __name__ == "__main__":
    main()
