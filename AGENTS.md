# AI Agent Bootstrap Instructions (`Liquid-Glass-Fleet-Shell`)

> **If the user tells you: "Set this up for me" or "Configure my fleet and install on my iPhone and Mac", execute the steps below autonomously end-to-end.**

## 1. Automated Fleet Discovery & Config Generation

Run the zero-dependency discovery & bootstrap script:

```bash
python3 scripts/bootstrap-fleet.py --auto
```

What `scripts/bootstrap-fleet.py --auto` does automatically:
1. **Discovers the Local Host**: Reads CPU chip (`sysctl -n machdep.cpu.brand_string`), core count, RAM GB, LAN IP (`ipconfig getifaddr en0`), and Tailscale IP (`tailscale ip -4`).
2. **Discovers SSH Peers**: Parses `~/.ssh/config` and tests passwordless SSH connectivity (`BatchMode=yes`, `ConnectTimeout=2`) to any other Macs or Linux servers the user owns, adding reachable hosts to `fleet.config.json`.
3. **Discovers `cmux` Cloud VMs**: Checks if `cmux` is installed (`cmux vm list`) and registers any running cloud VMs.
4. **Writes `fleet.config.json`**: Generates a complete, personalized `fleet.config.json` in the repo root and injects the discovered LAN & Tailscale URLs into `ios/Sources/FleetEndpoints.json`.
5. **Starts the Persistent Fleet Hub Daemon**:
   - Installs and loads `~/Library/LaunchAgents/com.liquidglass.fleet-hub.plist` on macOS (listening on `0.0.0.0:7778`), and enables Tailscale HTTPS proxy (`tailscale serve --bg --https=8443 http://127.0.0.1:7778`) if Tailscale is active.
6. **Installs the macOS Dock App**:
   - Creates `~/Applications/Fleet Studio.app`, adds it to the macOS Dock (`com.apple.dock.plist`), and restarts `Dock`.
7. **Builds & Installs the Native Liquid Glass iOS App**:
   - Detects any connected iPhone via `xcrun devicectl list devices` and detects the user's Apple Development Team ID from Keychain (`security find-identity -v -p codesigning`).
   - Runs `xcodegen generate` in `ios/`, compiles `AlbertoCloud.xcodeproj` with `-allowProvisioningUpdates`, installs the app onto the connected iPhone, and launches it.

## 2. Extending with Custom Machines or Agents

- **Add a new SSH machine**: Append an entry to `"machines"` in `fleet.config.json`:
  ```json
  {
    "id": "my-server",
    "name": "Home Lab Server",
    "mode": "ssh",
    "ssh_target": "user@100.x.y.z",
    "chip": "AMD Ryzen / Linux",
    "ram_gb": 64.0,
    "ip": "100.x.y.z"
  }
  ```
- **Add a Hub URL right inside the iPhone app**: Tap the **antenna icon (`Route`) -> `Configure Hub URL...`** in the top-right bar of the iOS app.
