# Roadmap

This roadmap expands the short list in the [README](README.md#roadmap) into phases with concrete deliverables and exit criteria. Items move between phases as we learn; the README list stays the high-level summary.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done

---

## Guiding Principles

These decide priority when two items compete:

1. **Never leave the user offline.** Network safety work ships before any feature that touches routes or DNS.
2. **Visibility before automation.** A user (or an AI via MCP) must be able to see *why* traffic went somewhere before we let anything change rules automatically.
3. **macOS only, done properly.** No cross-platform abstractions that weaken the macOS experience.
4. **Local by default.** The GUI and MCP server bind to `127.0.0.1` and require a token. Nothing is exposed to the network unless the user explicitly asks.
5. **Dry-run first.** Anything that changes config (rules, nodes, VPS setup) shows a preview and waits for confirmation.

---

## Phase 0 — Foundations

The groundwork that every MVP feature depends on. None of it is user-facing on its own.

- [ ] **Tech stack decision** — language/runtime for the daemon, CLI, and localhost GUI; record it as an ADR in `docs/adr/`
- [ ] **Core management** — download, checksum-verify, and launch a pinned mihomo version; store cores per version so rollback is possible later
- [ ] **Privileged helper** — minimal root helper for TUN, routes, and DNS changes, with a narrow, audited command surface
- [ ] **Config layout** — separate config directories, ports, and TUN device names per instance (stable vs debug never overlap)
- [ ] **CLI skeleton** — `mihomac start | stop | status | restore-network`
- [ ] **Localhost GUI shell** — bound to `127.0.0.1`, token authentication, empty dashboard
- [ ] **Debug build defaults** — mixed-port only, TUN disabled (see [CONTRIBUTING.md](CONTRIBUTING.md))

**Exit criteria:** `mihomac start` runs mihomo in port-only mode with a user-supplied config, and `mihomac stop` leaves the system unchanged.

---

## Phase 1 — MVP

Goal: a developer can use Clash Mihomac as their daily TUN client without losing localhost, intranet, or their corporate VPN, and can explain any single connection.

### 1.1 Reliable network recovery *(ships first)*

- [ ] Back up the routing table and DNS settings at startup
- [ ] Verified restore on normal exit (compare against the backup, report differences)
- [ ] Crash watchdog: helper detects main-process exit and restores the network
- [ ] Startup self-check: detect and clean leftover routes/DNS from a previous session
- [ ] Emergency recovery from the CLI (`mihomac restore-network`) and the menu bar
- [ ] Recover after sleep/wake, Wi-Fi switching, and cable plug/unplug

**Done when:** `kill -9` on the main process restores connectivity within a few seconds with no reboot, and every row of the [release compatibility checklist](CONTRIBUTING.md#release-compatibility-checklist) passes.

### 1.2 TUN mode with allowlist

- [ ] TUN enabled by default, with a one-click switch to system proxy / port-only mode
- [ ] Allowlist rules for websites (domain, suffix, keyword) and apps
- [ ] Each rule targets `DIRECT` or a specific node
- [ ] Built-in rule packs for common direct-connect services (e.g. Bilibili, Taobao)
- [ ] Default bypass for localhost, private ranges, `.local`, and Docker/OrbStack networks

### 1.3 Per-process / per-app rules

- [ ] Resolve connections to process and app bundle
- [ ] Rules by process name, path, or bundle ID
- [ ] App picker in the GUI (installed apps list)

### 1.4 Dual-NIC routing

- [ ] Choose the outbound interface by CIDR, domain, or process
- [ ] Internal DNS for internal domains (split DNS)
- [ ] Coexist with corporate VPN clients without overwriting their routes
- [ ] Interface status in the GUI (which NIC is up, which routes it owns)

### 1.5 Single-request diagnostics page

- [ ] Live connection list: app → matched rule → interface/node → destination
- [ ] Per-connection detail: DNS answer, rule-match trace, timing, bytes, errors
- [ ] "Why did this go here?" explanation in plain language
- [ ] Temporary TUN-off comparison to confirm whether the proxy is the cause

### 1.6 Basic MCP server

- [ ] Read-only tools: list connections, inspect a connection, list rules, list nodes, network status
- [ ] Rule-change proposals as dry-run diffs; applied only after user confirmation in the GUI or CLI
- [ ] Same token auth and `127.0.0.1` binding as the GUI
- [ ] Setup instructions for Claude, Cursor, and other MCP clients

**MVP exit criteria:**

- All six areas above are complete
- The release compatibility checklist passes on at least two Macs (one Apple Silicon, one Intel if available) with TUN enabled
- At least one week of daily use by maintainers with no manual network repair needed

---

## Phase 2 — Next

### 2.1 One-step VPS setup (zero to hero)

- [ ] Import nodes from mack-a script share links and QR codes
- [ ] Guided flow: enter server IPv4 address and password
- [ ] Connect over SSH, run the mack-a script (or our own installer), and import the resulting node
- [ ] Show every command before it runs; keep a full log of the session
- [ ] Encourage switching to SSH keys after first login; never store the password by default
- [ ] Post-install health check of the new node

### 2.2 Traffic visualization

- [ ] Sankey view: app → rule → interface/node → destination
- [ ] Time-range filter and per-app drill-down
- [ ] Click through to the diagnostics page for any flow

### 2.3 Node health and blocking detection

- [ ] Periodic latency and availability checks
- [ ] Detect blocking patterns (TCP reset, TLS handshake failure, DNS poisoning)
- [ ] Multi-node failover groups with configurable policy
- [ ] Health history per node

### 2.4 Community rule packs

- [ ] Rule pack format with metadata (name, version, author, description)
- [ ] Install, update, and remove packs from the GUI
- [ ] Preview a pack's effect as a diff before enabling it

### 2.5 Multi-instance and mihomo version management

- [ ] Run multiple profiles side by side (ports, directories, TUN devices isolated)
- [ ] Install, switch, and roll back mihomo versions with one click
- [ ] Per-instance logs and status

---

## Later / Ideas

Not committed. Open an issue to discuss before starting.

- Menu bar quick actions (switch profile, toggle TUN, pick node)
- Export a diagnostics bundle for bug reports (with sensitive data redacted)
- MCP write tools beyond rules (node management, profile switching), still dry-run first
- Scheduled rules (e.g. work network rules only during work hours)
- Signed and notarized releases with auto-update

## Non-Goals

- Windows, Linux, iOS, or Android clients
- A subscription marketplace or bundled proxy provider
- Exposing the GUI or MCP server beyond `127.0.0.1` by default

## Open Questions

- Tech stack for daemon, CLI, and GUI (Phase 0)
- Privileged helper installation method and update story
- How much of the mack-a script to wrap vs. replace with our own installer
- License (currently TBD)
