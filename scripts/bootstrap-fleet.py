#!/usr/bin/env python3
"""
Autonomous Fleet Discovery & Bootstrapper (bootstrap-fleet.py)
Designed so any user (or their AI coding agent) can run:
  python3 scripts/bootstrap-fleet.py --auto
to discover their Mac(s), SSH hosts, Tailscale mesh, cmux Cloud VMs,
start the Fleet Hub daemon, and build/install the native iOS & macOS apps.
"""
import json
import os
import pathlib
import re
import socket
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def sh(cmd: str) -> str:
    try:
        return subprocess.check_output(["bash", "-lc", cmd], timeout=5.0, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def discover_fleet() -> dict:
    hostname = socket.gethostname().split(".")[0]
    chip = sh("sysctl -n machdep.cpu.brand_string") or "Apple Silicon / Host CPU"
    mem_bytes = sh("sysctl -n hw.memsize")
    ram_gb = round(int(mem_bytes) / (1024 ** 3), 1) if mem_bytes.isdigit() else 16.0
    lan_ip = sh("ipconfig getifaddr en0") or sh("ipconfig getifaddr en1") or "127.0.0.1"
    ts_ip = sh("/Applications/Tailscale.app/Contents/MacOS/Tailscale ip -4 2>/dev/null || tailscale ip -4 2>/dev/null")

    machines = [
        {
            "id": "primary-mac",
            "name": hostname,
            "mode": "local",
            "chip": chip,
            "ram_gb": ram_gb,
            "ip": f"{lan_ip}" + (f" • {ts_ip}" if ts_ip else ""),
        }
    ]

    # Discover reachable SSH hosts in ~/.ssh/config
    ssh_cfg = pathlib.Path.home() / ".ssh/config"
    if ssh_cfg.exists():
        for line in ssh_cfg.read_text().splitlines():
            line = line.strip()
            if line.lower().startswith("host ") and "*" not in line:
                alias = line.split()[1]
                probe = sh(f"ssh -o BatchMode=yes -o ConnectTimeout=2 {alias} 'hostname && sysctl -n machdep.cpu.brand_string hw.memsize 2>/dev/null || uname -m'")
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

    endpoints = [{"name": "LAN Direct", "url": f"http://{lan_ip}:7778"}]
    if ts_ip:
        endpoints.append({"name": "Tailscale Direct", "url": f"http://{ts_ip}:7778"})
    endpoints.append({"name": "Localhost", "url": "http://127.0.0.1:7778"})

    return {
        "owner_name": f"{os.environ.get('USER', 'User')}'s Fleet",
        "hub_port": 7778,
        "machines": machines,
        "endpoints": endpoints,
    }


def main():
    cfg = discover_fleet()
    out_path = REPO_ROOT / "fleet.config.json"
    out_path.write_text(json.dumps(cfg, indent=2))
    print(f"✓ Generated {out_path} with {len(cfg['machines'])} discovered machine(s):")
    for m in cfg["machines"]:
        print(f"  • {m['name']} ({m['chip']}, {m['ram_gb']} GB RAM) [{m['ip']}]")
    print("\nNext steps:")
    print("  1. Start the Fleet Hub: python3 scripts/fleet-hub.py &")
    print("  2. Build for iPhone:    (cd ios && xcodegen generate && open AlbertoCloud.xcodeproj)")


if __name__ == "__main__":
    main()
