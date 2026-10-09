# Roadmap

Clash Mihomac is a mihomo client for macOS, built for developers and beginners: a path from zero to your own self-hosted VPN, with TUN by default and every connection visible.

The project is developed entirely with **Claude Code in the cloud**. There is no local development machine, so this file is both the roadmap and the working agreement for the agent. It is the project's single source of documentation.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done

---

## Guiding Principles

These decide priority when two items compete:

1. **Visibility before automation.** A user (or an AI via MCP) must be able to see *why* traffic went somewhere before we let anything change rules automatically.
2. **macOS only, done properly.** No cross-platform abstractions that weaken the macOS experience.
3. **Local by default.** The GUI and MCP server bind to `127.0.0.1` and require a token. Nothing is exposed to the network unless the user explicitly asks.
4. **Dry-run first.** Anything that changes config (rules, nodes, VPS setup) shows a preview and waits for confirmation.
5. **Privileged by default, defended to the maximum.** The product assumes administrator (sudo) rights from day one: the root helper is installed once at first run, and features may rely on it (packet-level visibility, routes, DNS, interface control). **Only the helper runs as root**; the daemon, CLI, GUI, and MCP server run as the logged-in user and ask the helper for anything privileged. Because root is always present, the design is built around containing it; see [Privilege Model](#privilege-model).
6. **Verifiable in the cloud.** Code is written and checked in a Linux cloud sandbox, with no macOS, no root, and no real TUN device. Every system-touching call (routes, DNS, `scutil`, `networksetup`, launchd) goes through an interface with a fake in tests, so behavior is covered by `go test` without a Mac.

---

## Development Workflow (Cloud Claude Code)

Requires Go 1.27+.

```sh
make build    # bin/mihomac and bin/mihomac-helper
make vet      # go vet ./...
make test     # unit tests
```

- **Before every commit:** `make vet`, `make test`, and a cross-compile check, `GOOS=darwin GOARCH=arm64 go build ./...` (repeat with `amd64`). The code targets macOS, so the build must stay green for it even though it can't run there.
- **Platform-specific code** lives behind small interfaces; macOS implementations are covered by fakes, not by running on a Mac.
- **Branches and commits:** branch from `main` as `feat/<name>`, `fix/<name>`, or `docs/<name>`; use Conventional Commits; keep each PR to one change. A PR states what changed, why, and how it was tested, and marks anything it could not test in the cloud.
- **Needs maintainer review:** the privileged helper (runs as root; keep its command surface minimal), GUI/MCP authentication, MCP write tools, and VPS setup over SSH. Treat these as high-risk.
- **Not testable in the cloud:** real TUN behavior, root helper installation, and coexistence with other VPNs or containers. These are checked once, by a maintainer on a real Mac, at the MVP gate (see the release checklist below). Until then, such items stay `[~]`, never `[x]`.

### Build outputs and instances

A plain `go build` or `make build` produces a **debug-channel** binary whose default instance is `debug`; `make release` builds the stable channel. `MIHOMAC_HOME` overrides the base directory (default `~/Library/Application Support/Mihomac`). Stable and debug instances never share ports, directories, or TUN device names.

| Instance | mixed-port | controller | GUI | TUN device |
|---|---|---|---|---|
| `stable` | 7990 | 9990 | 9991 | `utun1990` |
| `debug` | 17990 | 19990 | 19991 | `utun1991` |

---

## Phase 0 — Foundations

The groundwork that every MVP feature depends on. None of it is user-facing on its own.

- [x] **Tech stack decision** — Go for the daemon, CLI, and privileged helper; the GUI is static HTML/CSS/JS embedded with `embed`
- [x] **Core management** — download, checksum-verify, and launch a pinned mihomo version; store cores per version so rollback is possible later
- [~] **Privileged helper** — root helper installed by default at first run (one admin-password prompt), for TUN, routes, DNS, and traffic observation, with a narrow, audited command surface. *Protocol, allowlist, and launchd packaging done with read-only commands; `make install-helper` not yet tested as root on a Mac; mutating commands land in Phase 1*
- [x] **Config layout** — separate config directories, ports, and TUN device names per instance
- [x] **CLI skeleton** — `mihomac start | stop | status | restore-network`
- [x] **Localhost GUI shell** — bound to `127.0.0.1`, token authentication, empty dashboard

**Exit criteria:** `mihomac start` runs mihomo in port-only mode with a user-supplied config, and `mihomac stop` leaves the system unchanged. *Previously met on a Mac via `scripts/verify-phase0.sh`; that script is macOS-only (`scutil`, `ifconfig`) and cannot run in the cloud.*

---

## Phase 1 — MVP

Goal: a developer can use Clash Mihomac as their daily TUN client without losing localhost, intranet, or their corporate VPN, and can explain any single connection.

### 1.1 TUN mode with allowlist

- [ ] TUN enabled by default, with a one-click switch to system proxy / port-only mode
- [ ] Allowlist rules for websites (domain, suffix, keyword) and apps
- [ ] Each rule targets `DIRECT` or a specific node
- [ ] Built-in rule packs for common direct-connect services (e.g. Bilibili, Taobao)
- [ ] Default bypass for localhost, private ranges, `.local`, and Docker/OrbStack networks

### 1.2 Per-process / per-app rules

- [ ] Resolve connections to process and app bundle
- [ ] Rules by process name, path, or bundle ID
- [ ] App picker in the GUI (installed apps list)

### 1.3 Dual-NIC routing

- [ ] Choose the outbound interface by CIDR, domain, or process
- [ ] Internal DNS for internal domains (split DNS)
- [ ] Coexist with corporate VPN clients without overwriting their routes
- [ ] Interface status in the GUI (which NIC is up, which routes it owns)

### 1.4 Single-request diagnostics page

- [ ] Live connection list: app → matched rule → interface/node → destination
- [ ] Per-connection detail: DNS answer, rule-match trace, timing, bytes, errors
- [ ] "Why did this go here?" explanation in plain language
- [ ] Temporary TUN-off comparison to confirm whether the proxy is the cause

### 1.5 Basic MCP server

- [ ] Read-only tools: list connections, inspect a connection, list rules, list nodes, network status
- [ ] Rule-change proposals as dry-run diffs; applied only after user confirmation in the GUI or CLI
- [ ] Same token auth and `127.0.0.1` binding as the GUI
- [ ] Setup instructions for Claude, Cursor, and other MCP clients

**MVP exit criteria:**

- All five areas above are complete, with unit tests passing and the darwin cross-compile green
- A maintainer runs the release checklist below once on a real Mac with TUN enabled, and every row passes

---

## Phase 2 — Next

### 2.1 One-step VPS setup and machine management

Goal: enter only the VPS's **IPv4 address and password**; Clash Mihomac configures the server end to end, then lets you manage every machine visually.

**Automatic setup**

- [ ] Single form: IPv4 + root password (SSH port defaults to 22, editable under advanced)
- [ ] Pre-flight checks over SSH: reachability, OS and version, architecture, free ports, existing proxy services, time sync
- [ ] Install plan preview: the full list of commands and what each does; one confirmation, then fully automatic (dry-run first)
- [ ] Run the mack-a script (or our own installer) non-interactively: install the proxy core, generate credentials, open the firewall ports, enable BBR
- [ ] Import the resulting node(s) and subscription automatically, with no copy-paste
- [ ] Post-install verification: connect through the new node and confirm egress IP, latency, and DNS
- [ ] Switch to SSH key login after first success (generate a key, install it, offer to disable password login); never store the password by default
- [ ] Full session log, with passwords and keys redacted
- [ ] Safe to re-run: detect an existing install and offer repair, upgrade, or reinstall
- [ ] Import nodes from mack-a script share links and QR codes for servers set up elsewhere

**Visual machine management**

- [ ] Machine list: one card per VPS, showing name, IP, region, status (online / degraded / unreachable), and last check time
- [ ] System status per machine: CPU, memory, disk, load, uptime, network throughput, and monthly traffic against quota
- [ ] Service status per machine: proxy core running state and version, listening ports, certificate expiry
- [ ] Subscription per machine: nodes and protocols, share links and QR codes, and the subscription URL; regenerate or revoke from the GUI
- [ ] Machine actions, each previewed and confirmed: restart the proxy service, update the core, rotate credentials, reboot, re-run the health check, remove the machine
- [ ] Metrics are read over SSH on demand and on a schedule; nothing is installed on the server beyond the proxy itself unless the user opts in
- [ ] Machines and credentials stored locally only (credentials in the macOS Keychain once a native component exists)

### 2.2 Physical traffic visualization *(the signature feature)*

Goal: show traffic as it **physically happens**, not as a rule list. One view ties the hardware layer (which NIC, which `utun`) to the software layer (which process, which protocol and socket), so any flow can be explained end to end.

**Hardware layer: where bytes really travel**

- [ ] Interface inventory: every NIC and `utun` (Ethernet, Wi-Fi, Thunderbolt bridge, VPN tunnels, our own TUN device) with up/down state, addresses, and which routes each owns
- [ ] Per-interface live throughput (in/out, packets, errors, drops) and history
- [ ] Two-hop path for proxied flows: `app → utun (captured by TUN) → mihomo → physical NIC (en0 / en1 …) → destination`, with the ingress `utun`, the egress NIC, and the next-hop gateway shown for each hop
- [ ] Direct flows shown as `app → physical NIC → destination`, so proxied and direct traffic are directly comparable
- [ ] Highlight surprises: traffic leaving the wrong NIC, bypassing TUN, or going out through another VPN's `utun`
- [ ] Reconcile the two sides: bytes into our `utun` vs bytes out of the physical NIC, with the gap explained (protocol overhead, retransmits, DNS)

**Software layer: who is talking and how**

- [ ] Process attribution for every flow: PID, process name, executable path, app bundle, parent process, and code-signing identity
- [ ] Per-flow transport: **TCP** (with state: connecting, established, closing, reset) vs **UDP** (including QUIC/HTTP3 and DNS) vs ICMP/other
- [ ] Socket type and ownership: IPv4 vs IPv6, local and remote address and port, listening vs connected, and **Unix domain sockets** (local IPC, shown separately so it is not mistaken for network traffic)
- [ ] Proxied vs not: for each flow, whether it entered TUN, which rule matched, and which node or `DIRECT` it used
- [ ] Per-process roll-up: connections, bytes up/down, protocol mix, and how much of it is proxied

**The view**

- [ ] Layered Sankey: `process → protocol/socket → utun → rule → node → physical NIC → destination`, each layer a column; width is bytes
- [ ] Toggle between a hardware view (NICs and tunnels only), a software view (processes and protocols only), and the full path
- [ ] Filters: time range, process/app, protocol (TCP / UDP / Unix), interface, rule, node, proxied vs direct
- [ ] Drill-down: click a process to see its flows; click a NIC or `utun` to see everything crossing it
- [ ] Click through to the diagnostics page (1.4) for any single flow
- [ ] Live mode (streaming) and history mode (stored locally, with a retention limit)

**Data sources and verification**

- [ ] Collectors behind interfaces so the sources can be swapped: mihomo controller API (connections, rule matches), macOS socket and process tables (`libproc`, `lsof`, `netstat`), interface counters (`netstat -ib` / sysctl), and route table (`netstat -rn`)
- [ ] Spike first: with the root helper available, confirm the best source for packet-level capture and per-flow byte counts (BPF/`pktap` via libpcap, `nettop`, the NetworkStatistics framework, or a Network Extension); record the findings here before building the UI. Capture runs only in the helper; the unprivileged daemon receives parsed summaries, never raw packets
- [ ] Join logic (connection ↔ process ↔ interface) is pure code tested in the cloud against recorded fixtures; live collection is verified once on a real Mac at the MVP gate
- [ ] Everything stays local; no traffic data leaves the machine

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

## Release Checklist (manual, on a Mac, with TUN enabled)

| Area | What to verify |
|---|---|
| localhost | Dev servers, HMR, and local databases work normally |
| Intranet | Internal IPs are reachable; internal domains resolve via internal DNS |
| Containers | Docker / OrbStack containers communicate both ways; image pulls succeed |
| mDNS | `.local` resolution and AirDrop device discovery work |
| VPN | Coexists with corporate VPN clients without overwriting each other's routes |
| Dev tools | git, npm, pip, brew, and AI tools such as Claude and Cursor work normally |

## Privilege Model

Decision: **only the helper runs as root.** Root is always available, so the work is to keep it small, authenticated, and auditable. Everything that faces the network or the browser stays unprivileged.

- [ ] **Split by privilege.** The helper is the only root process. The daemon, CLI, localhost GUI, and MCP server run as the logged-in user and ask the helper for everything privileged. Never run the web GUI or MCP server as root.
- [ ] **One install, one prompt.** The helper is installed as a launchd daemon on first run with one admin prompt; later privileged actions need no further prompt. Upgrade and uninstall use the same flow.
- [ ] **Root-owned install tree.** Helper binary, launchd plist, and mihomo cores live in root-owned, non-user-writable locations, so a user-level compromise cannot swap them.
- [ ] **Strict caller authentication.** The helper's Unix socket has a fixed path, checks the peer's UID and PID via `LOCAL_PEERCRED`, and verifies the caller's code signature in release builds. Anything else is refused.
- [ ] **Allowlist, not shell.** The helper exposes a fixed set of typed commands with validated arguments. No arbitrary command execution, no user-supplied paths or shell strings, and no command that can read or write arbitrary files.
- [ ] **Least capability inside root.** Each command touches only what it names (specific routes, DNS entries, our own `utun`, our own mihomo process). The helper refuses to modify objects it did not create unless the command explicitly allows it.
- [ ] **Hardened mihomo.** Launched by the helper with a fixed binary path whose checksum is verified before each start and a config the helper validates. Evaluate dropping mihomo to an unprivileged user and passing only the TUN file descriptor.
- [ ] **Untrusted input is data.** Subscriptions, share links, rule packs, and MCP requests are parsed strictly with size and depth limits, and never executed or used to build paths. Anything that reaches the helper is re-validated there, regardless of what the caller already checked.
- [ ] **Audit log.** Every privileged command is logged with caller, arguments, and result to a root-owned append-only log; the GUI can display it.
- [ ] **Rate limits and fail closed.** Unknown, malformed, or too-frequent requests are rejected and logged; on any authentication doubt the helper does nothing.
- [ ] **Capture data stays minimal.** Packet capture is opt-in per session, bounded in time and size, and never written to disk unredacted.
- [ ] **Tested without root.** The command parser, allowlist, argument validation, and peer-check logic are unit-tested in the cloud with hostile inputs (including fuzz tests); real root behavior is verified on a Mac at the MVP gate.

## Security

Report vulnerabilities privately via GitHub private vulnerability reporting, not public issues. In scope: GUI/MCP auth and `127.0.0.1` binding, MCP changes applied without confirmation, privileged helper escalation (caller spoofing, command or argument injection, tampering with root-owned files), VPS credential exposure, and installing mihomo without checksum verification. Out of scope: bugs in mihomo or the mack-a script (report upstream). Only the latest `main` is supported until the first stable release.

Agent rule: never commit secrets, tokens, or real server credentials; examples use placeholders only.

## Non-Goals

- Windows, Linux, iOS, or Android clients
- A subscription marketplace or bundled proxy provider
- Exposing the GUI or MCP server beyond `127.0.0.1` by default

## Open Questions

- Privileged helper update story and how to bind it to a signed app (SMAppService vs. plain launchd daemon)
- How much of the mack-a script to wrap vs. replace with our own installer
- License (currently TBD)
