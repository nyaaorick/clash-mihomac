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
- **Needs maintainer review:** the privileged helper (runs as root; keep its command surface minimal, including the read-only `sockets` command), GUI/MCP authentication, MCP write tools, VPS setup over SSH (it logs in to remote machines as root), and anything that downloads and applies third-party data (rule packs, share links, pinned release checksums). Treat these as high-risk.
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
- [~] **Privileged helper** — root helper installed by default at first run (one admin-password prompt), for TUN, routes, DNS, and traffic observation, with a narrow, audited command surface. *Protocol, allowlist, and launchd packaging done. Commands: `ping`, `status`, `network-snapshot`, `sockets` (read-only), `tun-start`, `tun-reload`, `tun-stop`, `sysproxy-set`, `sysproxy-clear`, `restore-network`. `make install-helper` not yet tested as root on a Mac*
- [x] **Config layout** — separate config directories, ports, and TUN device names per instance
- [x] **CLI skeleton** — `mihomac start | stop | status | restore-network`
- [x] **Localhost GUI shell** — bound to `127.0.0.1`, token authentication, empty dashboard

**Exit criteria:** `mihomac start` runs mihomo in port-only mode with a user-supplied config, and `mihomac stop` leaves the system unchanged. *Previously met on a Mac via `scripts/verify-phase0.sh`; that script is macOS-only (`scutil`, `ifconfig`) and cannot run in the cloud.*

---

## Phase 1 — MVP

Goal: a developer can use Clash Mihomac as their daily TUN client without losing localhost, intranet, or their corporate VPN, and can explain any single connection.

Everything below is implemented and covered by `go test`. Items that depend on real TUN, routes, or other VPNs on a Mac stay `[~]` until the release checklist has been run once by a maintainer.

### 1.1 TUN mode with allowlist

- [~] TUN enabled by default, with a one-click switch to system proxy / port-only mode *(`mihomac mode`, GUI Overview; the stable instance defaults to TUN)*
- [x] Allowlist rules for websites (domain, suffix, keyword) and apps
- [x] Each rule targets `DIRECT` or a specific node
- [x] Built-in rule packs for common direct-connect services (e.g. Bilibili, Taobao)
- [~] Default bypass for localhost, private ranges, `.local`, and Docker/OrbStack networks *(the list is in `internal/rules/packs.go`; real coexistence is a release-checklist row)*

### 1.2 Per-process / per-app rules

- [~] Resolve connections to process and app bundle *(mihomo's `find-process-mode: always`, plus the socket table; needs a Mac)*
- [~] Rules by process name, path, or bundle ID *(name, path, and `.app` bundle are compiled and tested; matching happens in mihomo on a Mac. Matching by bundle ID itself isn't supported: use the app's path)*
- [~] App picker in the GUI (installed apps list) *(lists `/Applications` and friends; macOS only)*

### 1.3 Dual-NIC routing

- [~] Choose the outbound interface by CIDR, domain, or process *(`iface:<name>` targets)*
- [~] Internal DNS for internal domains (split DNS) *(`internal_dns` in rules.yaml, and automatic per-interface DHCP DNS for domains sent out an interface)*
- [~] Coexist with corporate VPN clients without overwriting their routes *(`strict-route` off, own TUN address and device per instance, leftover-route cleanup; real check at the MVP gate)*
- [x] Interface status in the GUI (which NIC is up, which routes it owns)

### 1.4 Single-request diagnostics page

- [x] Live connection list: app → matched rule → interface/node → destination
- [~] Per-connection detail: DNS answer, rule-match trace, timing, bytes, errors *(rule-match trace, timing, bytes, errors, and related core log lines are shown; the resolved address is shown but not the DNS server's raw answer)*
- [x] "Why did this go here?" explanation in plain language
- [x] Temporary TUN-off comparison to confirm whether the proxy is the cause *(direct vs proxied probe)*

### 1.5 Basic MCP server

- [x] Read-only tools: list connections, inspect a connection, list rules, list nodes, network status *(plus interfaces, node health, and traffic summary)*
- [x] Rule-change proposals as dry-run diffs; applied only after user confirmation in the GUI or CLI
- [x] Same token auth and `127.0.0.1` binding as the GUI *(a separate read-and-propose-only token)*
- [x] Setup instructions for Claude, Cursor, and other MCP clients *(`mihomac mcp --setup`, below)*

#### MCP setup

```sh
mihomac start                 # the MCP server talks to a running instance
mihomac mcp --setup           # prints the exact commands for your install
claude mcp add mihomac-stable -- /path/to/mihomac mcp --instance stable
```

For Claude Desktop, Cursor, and other clients, add the JSON that `mihomac mcp --setup` prints to the client's MCP config (Claude Desktop: `claude_desktop_config.json`; Cursor: `~/.cursor/mcp.json`). The snippet holds no secrets: the server reads its own token from disk. An assistant can read everything, create dry-run proposals, and run a probe, but it can't apply a change, read logs, or touch servers.

**MVP exit criteria:**

- All five areas above are complete, with unit tests passing and the darwin cross-compile green
- A maintainer runs the release checklist below once on a real Mac with TUN enabled, and every row passes

---

## Phase 2 — Next

All of Phase 2 is written and tested against fakes and recorded fixtures. Anything that needs a real Mac, a real server, or real traffic is `[~]`.

### 2.1 One-step VPS setup and machine management

Goal: enter only the VPS's **IPv4 address and password**; Clash Mihomac configures the server end to end, then lets you manage every machine visually. CLI: `mihomac vps`; GUI: the Servers tab. Needs maintainer review (SSH, root on a remote machine).

**Automatic setup**

- [x] Single form: IPv4 + root password (SSH port defaults to 22, editable under advanced)
- [x] Pre-flight checks over SSH: reachability, OS and version, architecture, free ports, existing proxy services, time sync *(plus root, systemd, memory, disk, BBR, firewall, package manager; one read-only script)*
- [x] Install plan preview: the full list of commands and what each does; one confirmation, then fully automatic (dry-run first) *(the preview is kept in memory under an id and running takes only that id, so what ran is exactly what was shown)*
- [~] Run the mack-a script (or our own installer) non-interactively: install the proxy core, generate credentials, open the firewall ports, enable BBR *(our own installer: sing-box with VLESS + Reality. The mack-a script is menu-driven and can't be run safely unattended; see Open Questions. Never run against a real server yet, and the sing-box release checksums are **unpinned**: setup refuses to download anything without a checksum, so a maintainer must pin them in `internal/vps/plan.go` or pass `--sha256`)*
- [x] Import the resulting node(s) and subscription automatically, with no copy-paste *(imported nodes live in `nodes.yaml`, apart from your config file)*
- [~] Post-install verification: connect through the new node and confirm egress IP, latency, and DNS *(latency is mihomo's end-to-end delay test through the node; the egress IP and the DNS check are what the server reports about itself, not a client-side fetch through the node)*
- [~] Switch to SSH key login after first success (generate a key, install it, offer to disable password login); never store the password by default *(done and proven on a fresh connection before the key is saved; turning off password login is a separate confirmed action. Tested against an in-process SSH server, not a real sshd)*
- [x] Full session log, with passwords and keys redacted *(shown live and saved under `vps/logs/`, mode 0600)*
- [~] Safe to re-run: detect an existing install and offer repair, upgrade, or reinstall *(plans for all four modes; upgrade rolls the binary back if the service doesn't start)*
- [x] Import nodes from mack-a script share links and QR codes for servers set up elsewhere *(vless, vmess, trojan, ss, hysteria2; text, subscriptions, and PNG/JPEG QR images)*

**Visual machine management**

- [~] Machine list: one card per VPS, showing name, IP, region, status (online / degraded / unreachable), and last check time *(region is a free-text field with no UI to set it yet)*
- [x] System status per machine: CPU, memory, disk, load, uptime, network throughput, and monthly traffic against quota *(traffic is accumulated from the kernel's counters across reboots, against a quota you set)*
- [x] Service status per machine: proxy core running state and version, listening ports, certificate expiry *(certificate expiry applies to nodes whose config names a certificate; Reality nodes have none)*
- [~] Subscription per machine: nodes and protocols, share links and QR codes, and the subscription URL; regenerate or revoke from the GUI *(share link, QR code, and base64 subscription text are shown; "regenerate or revoke" is rotating the credentials. There is no hosted subscription URL: that would mean serving something from the server or exposing the GUI)*
- [x] Machine actions, each previewed and confirmed: restart the proxy service, update the core, rotate credentials, reboot, re-run the health check, remove the machine
- [x] Metrics are read over SSH on demand and on a schedule; nothing is installed on the server beyond the proxy itself unless the user opts in
- [~] Machines and credentials stored locally only (credentials in the macOS Keychain once a native component exists) *(machines.json and the SSH key, both mode 0600, under the Mihomac data directory)*

### 2.2 Physical traffic visualization *(the signature feature)*

Goal: show traffic as it **physically happens**, not as a rule list. One view ties the hardware layer (which NIC, which `utun`) to the software layer (which process, which protocol and socket), so any flow can be explained end to end. CLI: `mihomac traffic`; GUI: the Traffic tab; MCP: `traffic_summary`.

**Hardware layer: where bytes really travel**

- [~] Interface inventory: every NIC and `utun` (Ethernet, Wi-Fi, Thunderbolt bridge, VPN tunnels, our own TUN device) with up/down state, addresses, and which routes each owns
- [~] Per-interface live throughput (in/out, packets, errors, drops) and history *(live rates over a window; one hour of counters is kept in memory, no longer history)*
- [~] Two-hop path for proxied flows: `app → utun (captured by TUN) → mihomo → physical NIC (en0 / en1 …) → destination`, with the ingress `utun`, the egress NIC, and the next-hop gateway shown for each hop *(the egress NIC and gateway come from the route table, looking past our own TUN's routes)*
- [~] Direct flows shown as `app → physical NIC → destination`, so proxied and direct traffic are directly comparable
- [~] Highlight surprises: traffic leaving the wrong NIC, bypassing TUN, or going out through another VPN's `utun` *(three checks, each tested with fixtures; a bypass has to persist across two polls before it is reported)*
- [~] Reconcile the two sides: bytes into our `utun` vs bytes out of the physical NIC, with the gap explained *(the explanation lists the known causes with the numbers we have; it doesn't measure retransmits or protocol overhead separately)*

**Software layer: who is talking and how**

- [~] Process attribution for every flow: PID, process name, executable path, app bundle, parent process, and code-signing identity *(from mihomo, `lsof`, `ps`, `codesign`, `plutil`; cached; run through the helper to see root-owned processes)*
- [~] Per-flow transport: **TCP** (with state: connecting, established, closing, reset) vs **UDP** (including QUIC/HTTP3 and DNS) vs ICMP/other *(QUIC and DNS are recognized by port)*
- [~] Socket type and ownership: IPv4 vs IPv6, local and remote address and port, listening vs connected, and **Unix domain sockets** (local IPC, shown separately so it is not mistaken for network traffic)
- [~] Proxied vs not: for each flow, whether it entered TUN, which rule matched, and which node or `DIRECT` it used
- [x] Per-process roll-up: connections, bytes up/down, protocol mix, and how much of it is proxied

**The view**

- [x] Layered Sankey: `process → protocol/socket → utun → rule → node → physical NIC → destination`, each layer a column; width is bytes *(small boxes group into "other (n)")*
- [x] Toggle between a hardware view (NICs and tunnels only), a software view (processes and protocols only), and the full path
- [x] Filters: time range, process/app, protocol (TCP / UDP / Unix), interface, rule, node, proxied vs direct
- [x] Drill-down: click a process to see its flows; click a NIC or `utun` to see everything crossing it
- [x] Click through to the diagnostics page (1.4) for any single flow
- [x] Live mode (streaming) and history mode (stored locally, with a retention limit) *(24 hours, 50,000 flows)*

**Data sources and verification**

- [x] Collectors behind interfaces so the sources can be swapped: mihomo controller API (connections, rule matches), macOS socket and process tables (`lsof`, `ps`), interface counters (`netstat -ibd`), and route table (`netstat -rn`)
- [ ] Spike first: with the root helper available, confirm the best source for packet-level capture and per-flow byte counts (BPF/`pktap` via libpcap, `nettop`, the NetworkStatistics framework, or a Network Extension); record the findings here before building the UI. Capture runs only in the helper; the unprivileged daemon receives parsed summaries, never raw packets *(not done: it needs a Mac and root. See "Traffic view: what is and isn't measured" below for what was built instead and what the spike has to decide)*
- [x] Join logic (connection ↔ process ↔ interface) is pure code tested in the cloud against recorded fixtures; live collection is verified once on a real Mac at the MVP gate
- [x] Everything stays local; no traffic data leaves the machine

#### Traffic view: what is and isn't measured

Built without a spike, from sources that exist on every Mac:

- **Per-flow bytes** come from mihomo's connection list, so they exist for flows that entered TUN or the proxy port. Flows seen only in the socket table (traffic that bypassed TUN, local IPC) have no byte counts and draw as hairlines.
- **Interface counters** (`netstat -ibd`) give true bytes per NIC and per `utun`, which is what the reconciliation uses.
- **Attribution** uses mihomo's own process lookup plus `lsof` (through the helper's read-only `sockets` command, which hides other users' processes) and `ps`.

The spike still has to answer: how to get per-flow bytes for traffic that never touches mihomo (candidates: `nettop -P -L`, the private NetworkStatistics framework, a `pktap` capture in the helper, or a Network Extension), what each costs in privilege and stability across macOS releases, and whether packet capture is worth it at all given what interface counters plus the socket table already show. Record the answer here before any capture code is written.

### 2.3 Node health and blocking detection

- [x] Periodic latency and availability checks *(every two minutes, mihomo's delay test through each node in your config and each imported node)*
- [~] Detect blocking patterns (TCP reset, TLS handshake failure, DNS poisoning) *(only a failing node is examined, stage by stage: DNS against a DNS-over-HTTPS resolver, then TCP, then a TLS handshake. Tested with fakes; real censorship behavior is unverified)*
- [x] Multi-node failover groups with configurable policy *(`mihomac groups`: fallback, url-test with tolerance, load-balance with strategy; compiled into mihomo proxy-groups, which does the switching)*
- [x] Health history per node *(a week, 500 checks per node, kept locally)*

### 2.4 Community rule packs

- [x] Rule pack format with metadata (name, version, author, description) *(strict YAML; targets limited to DIRECT, REJECT, or an `@placeholder` you map to your own node; size and rule-count limits)*
- [x] Install, update, and remove packs from the GUI *(and `mihomac packs`; https URLs are fetched without touching private addresses)*
- [x] Preview a pack's effect as a diff before enabling it *(lists every rule and flags ones overridden by higher-precedence rules)*

### 2.5 Multi-instance and mihomo version management

- [~] Run multiple profiles side by side (ports, directories, TUN devices isolated) *(`mihomac profile add` makes p1..p50; each slot's ports, TUN device, and TUN address derive from its number, so the helper never trusts a user-writable file. Not yet run side by side on a Mac)*
- [x] Install, switch, and roll back mihomo versions with one click *(`mihomac core use|rollback|remove`, per instance; only versions with a pinned checksum, or one you pass, can be installed)*
- [x] Per-instance logs and status *(`mihomac logs`, `mihomac profile list`, and the Network tab)*

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
- VPS installer: Phase 2.1 shipped our own sing-box (VLESS + Reality) installer instead of wrapping the mack-a script, because that script is an interactive menu and can't be driven safely and non-interactively. Should we also offer other protocols (Hysteria2, Trojan), or keep one well-tested path?
- The sing-box release checksums in `internal/vps/plan.go` are unpinned. A maintainer needs to copy the SHA-256 of each `linux-amd64` and `linux-arm64` asset from the release page and pin them (the same way `internal/core/core.go` pins mihomo)
- Traffic view: which source gives per-flow bytes for traffic that never enters mihomo (see "Traffic view: what is and isn't measured")
- Keychain storage for SSH keys once there is a native component
- License (currently TBD)
