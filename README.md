# Liquid Glass Fleet Shell — Blank Starter Template

A **100% native iOS 26 / macOS Tahoe Liquid Glass Fleet & Cloud Studio** starter template with bundled **LobeHub AI Provider Logos**, live multi-machine telemetry, collapsible AI agent launchpad, and an interactive remote shell console.

## Quick Start (Give This Repo to Your AI Agent)

Clone this repo and tell **Claude Code**, **Codex**, **Antigravity**, or **Cursor**:

> **"Read `AGENTS.md` and set this up for all my machines, my Mac Dock, and my iPhone."**

Or run the one-command bootstrapper directly:

```bash
python3 scripts/bootstrap-fleet.py --auto
```

## What Gets Set Up Automatically

1. **Auto-Discovers Your Machines**:
   - Your primary Mac (chip, cores, RAM, LAN IP, Tailscale IP)
   - Any additional Macs or Linux boxes in your `~/.ssh/config`
   - Any `cmux` Cloud VMs (`cmux vm list`)
2. **Starts Your Persistent Fleet Hub (`0.0.0.0:7778` + Tailscale `:8443`)**:
   - Zero-dependency Python 3 async server running via macOS `LaunchAgent`.
3. **Installs to Your macOS Dock & USB-C/Wi-Fi iPhone**:
   - Puts **Fleet Studio.app** in your macOS Dock.
   - Auto-detects your Apple Developer Team ID and connected iPhone, builds the native SwiftUI Liquid Glass app, installs it, and launches it.
