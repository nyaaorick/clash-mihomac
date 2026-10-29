# Roadmap

Clash Mihomac is a macOS companion for [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev): Verge runs mihomo, TUN, and the system proxy; Clash Mihomac sits next to it and adds what Verge doesn't have, with every connection visible: a "why did this go here?" diagnostics page, rules by app and by network interface, a physical traffic view, one-step VPS setup and machine management, node health checks, and an MCP server so an AI assistant can read all of it.

The project is developed with **Claude Code on a Mac that has Clash Verge Rev installed**, so every change is run against the real thing before it is called done. This file is both the roadmap and the working agreement for the agent. It is the project's single source of documentation.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` done

---

## How it fits with Clash Verge

Clash Mihomac used to be a full client with its own mihomo core, root helper, and TUN device. That was rewritten in October 2026 into a companion: nothing privileged, nothing that opens a listener other than the localhost GUI, and no second core fighting Verge's for the same routes.

- **Finding the core.** Verge writes the config it hands mihomo to `clash-verge.yaml` in its data directory (`~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev`). That file names the controller (by default a Unix socket under `$TMPDIR`; the TCP controller is off unless the user turns it on in Verge) and the secret. The daemon re-reads it whenever it changes and reconnects on its own when Verge restarts.
- **Reading.** Connections, rules, proxies, delay tests, and the log stream all come from mihomo's controller API, the same as any dashboard. Process attribution comes from mihomo (`find-process-mode: always`, which Verge sets) plus `lsof` as the user.
- **Writing rules.** Verge has no API for "apply my profile again", and it rebuilds its config from the profile plus the global Merge and Script profiles on every apply. So Clash Mihomac writes its rules, imported nodes, interface-bound outbounds, and failover groups into Verge's **global Merge profile** (`profiles/Merge.yaml`, the `prepend-rules`, `append-proxies`, and `append-proxy-groups` keys; other keys in that file are kept) and, at the same time, hot-loads the resulting config into the running core over the controller (`PUT /configs` with the full config). The core has the rules at once; Verge's next apply, whenever it happens, produces the same result from the Merge file. If the core rejects the config, the Merge file is put back and the user sees the error, because Verge would reject it too. If the core isn't reachable, the Merge file waits for Verge to start, and the GUI offers to restart Verge.
- **Opening the GUI from Verge.** Verge's Settings → Web UI list takes any URL. `mihomac webui --install` adds the dashboard's address (with its token) while Verge is closed; Verge opens it in the browser.

What this costs, compared with the old design: a user's **Script profile** that replaces `config.rules` wholesale runs after the merge and removes these rules on Verge's next apply (the GUI notices and offers to load them again); per-domain DNS policy for interface-bound rules (`nameserver-policy`) is only hot-loaded, not written to the Merge file, because Verge's merge replaces the `dns` key wholesale; and there is no root helper, so the socket table hides other users' processes.

---

## Guiding Principles

These decide priority when two items compete:

1. **Visibility before automation.** A user (or an AI via MCP) must be able to see *why* traffic went somewhere before we let anything change rules automatically.
2. **macOS only, done properly.** No cross-platform abstractions that weaken the macOS experience.
3. **Local by default.** The GUI and MCP server bind to `127.0.0.1` and require a token. Nothing is exposed to the network unless the user explicitly asks.
4. **Dry-run first.** Anything that changes config (rules, nodes, VPS setup) shows a preview and waits for confirmation.
5. **Verge owns the system.** Clash Mihomac never runs as root, never starts a core, and never touches routes, DNS, or proxy settings. The only files it writes outside its own directory are Verge's Merge profile and, on request, the Web UI list in Verge's settings.
6. **Fakes for the units, the real Mac for the whole.** Verge's files, the controller, and the commands that quit, relaunch, and install Verge are behind interfaces with fakes, so `go test` covers the logic anywhere. On top of that, every change that touches Verge is run against the installed Clash Verge on this Mac: start it, connect, add a rule, watch it land. Nothing is marked done on fakes alone.

---

## Development Workflow

Requires Go 1.27+.

```sh
make build    # bin/mihomac (debug channel)
make vet      # go vet ./...
make test     # unit tests
make darwin   # cross-compile check for arm64 and amd64
```

- **Before every commit:** `make vet`, `make test`, `make darwin`, and a run on this Mac of whatever the change touches (`./launch.command` or `bin/mihomac up`, then the GUI or CLI). Record what was verified, with the Verge version, in the PR.
- **Platform-specific code** lives behind small interfaces with fakes for unit tests, and is exercised for real on the Mac.
- **Branches and commits:** branch from `main` as `feat/<name>`, `fix/<name>`, or `docs/<name>`; use Conventional Commits; keep each PR to one change. A PR states what changed, why, and how it was tested on the Mac.
- **Needs maintainer review:** anything that writes into Verge's directory (the Merge profile, the Web UI list), the hot-load path (`PUT /configs`), GUI/MCP authentication, MCP write tools, VPS setup over SSH (it logs in to remote machines as root), and anything that downloads and applies third-party data (rule packs, share links, pinned release checksums). Treat these as high-risk.
- **`[x]` means verified on the Mac.** An item that only passes its unit tests stays `[~]` until it has been run against the installed Clash Verge; the note next to it says when and against which Verge version.

### Build outputs and data

`./launch.command` is the one-click start: it builds if needed and runs `mihomac up`, which installs Clash Verge Rev when missing (latest GitHub release, code signature and Gatekeeper checked before copying), starts it, starts the daemon, and opens the GUI. A plain `go build` or `make build` produces a **debug-channel** binary; `make release` builds the stable channel. The two channels keep separate data directories and GUI ports so a development build never touches the stable one's state. `MIHOMAC_HOME` overrides the data directory, `MIHOMAC_VERGE_DIR` the Verge directory.

| Channel | data directory | GUI |
|---|---|---|
| `stable` | `~/Library/Application Support/Mihomac/stable` | 9991 |
| `debug` | `~/Library/Application Support/Mihomac/debug` | 19991 |

Both talk to the same Clash Verge.

### As an island4mac plugin

`mihomac island` runs Clash Mihomac as a plugin of [island4mac](https://github.com/nyaaorick/island4mac): the daemon, dashboard and MCP server run in that one process, and the island's "Clash" tab shows the core, its mode (three switches), the rules and whether they are loaded, the nodes with delay and health, and warnings, with buttons for the dashboard, a node check and a Verge restart. `cmd/mihomac/island.go` speaks the plugin protocol (JSON lines on stdin and stdout, documented in island4mac's `spec/docs/04-plugin-protocol.md`); `renderIsland` is pure and tested.

- This module lives in the plugins repo (island4mac-plugins, as `mihomac/`) beside the Swift plugins, and its CI builds and publishes it the same way: `island-plugin build --all` sees the `go.mod`, builds `./cmd/mihomac` for arm64 and amd64, joins them with lipo, signs ad hoc, and asks the program for its plugin.json with `mihomac --describe` (`describePlugin` in `cmd/mihomac/island.go`, where `pluginVersion` is bumped with each change that ships). `island-plugin dev` installs it into the app and rebuilds on every change; `island-plugin build` writes `build/mihomac/` and `build/mihomac.zip` for Settings > Plugins > Install from File. Under the island the program runs as the stable channel (dashboard on 9991) unless `MIHOMAC_CHANNEL=debug`.
- The data directory is the one the island gives the plugin (`ISLAND_DATA_DIR`, kept across plugin updates). The first time it runs, it moves what a standalone install kept in `~/Library/Application Support/Mihomac/<channel>` into it (everything but the state file and logs). After that, point the CLI at it: `MIHOMAC_HOME="$HOME/Library/Application Support/island4mac/PluginData/mihomac" mihomac rules`.
- It uses the stable channel's GUI port (9991). A standalone `mihomac start` holding that port shows in the tab as the reason the plugin isn't running; `mihomac stop` frees it.
- It needs no privileges and asks the island for none. Bump `pluginVersion` in `cmd/mihomac/island.go` with each change that ships.

---

## Phase 0 — Foundations

- [x] **Tech stack decision** — Go for the daemon and CLI; the GUI is static HTML/CSS/JS embedded with `embed`
- [x] **Verge integration** — locate Verge's data directory, read its runtime config for the controller and secret, reach the controller over its Unix socket, re-read on change *(verified on this Mac 2026-10-22 against Clash Verge 2.5.8 / mihomo v1.19.32: connected over the service's socket, live connections with process names seen through TUN. Note: in service mode the socket is `/var/run/clash-verge-service/users/<uid>/verge-mihomo.sock`, not the `$TMPDIR` path the runtime config names; the daemon tries both)*
- [x] **Rule delivery** — rules, imported nodes, and groups written to Verge's global Merge profile and hot-loaded into the running core, with rollback when the core rejects them *(verified on this Mac 2026-10-22 against Clash Verge 2.5.8 / mihomo v1.19.32: `DOMAIN,example.com,DIRECT` appeared first in `GET /rules` and in Merge.yaml; in rule mode a connection to example.com went DIRECT via en0 with the diagnostics page naming the rule)*
- [x] **Verge restart** — quit through AppleScript, wait, relaunch; the GUI offers it when the Merge file is ahead of the core *(verified on this Mac 2026-10-22 against Clash Verge 2.5.8 / mihomo v1.19.32: `POST /api/verge/restart` relaunched Verge and the daemon reconnected in 3 s)*
- [x] **Rules survive Verge rebuilding its config** — when Verge comes back without the user's rules (this Mac's Script profile assigns `config.rules`), the daemon hot-loads them again on its own; a user with no rules, packs, groups, or imported nodes is never touched *(verified on this Mac 2026-10-22 against Clash Verge 2.5.8 / mihomo v1.19.32)*
- [x] **Verge detection and install** — find the installed app (path, version, root service) or install the latest release from GitHub after checking its Apple signature and Gatekeeper assessment; `mihomac verge`, `mihomac up` *(verified on this Mac 2026-10-22 against Clash Verge 2.5.8 / mihomo v1.19.32: detection on every start; the installer run for real with `--into` a scratch directory: 78 MB download, mount, codesign and spctl pass, copy, unmount, 20 s)*
- [x] **Localhost GUI shell** — bound to `127.0.0.1`, token authentication

**Exit criteria:** with Clash Verge running, `mihomac start` connects to its core and the GUI shows live connections; a rule added in the GUI shows up in `GET /rules` of Verge's core and in `profiles/Merge.yaml`; `mihomac stop` leaves Verge running. *Met on this Mac on 2026-10-22.*

---

## Phase 1 — MVP

Goal: a developer can use Clash Mihomac as their daily TUN client without losing localhost, intranet, or their corporate VPN, and can explain any single connection.

Everything below is implemented and covered by `go test`. Items that depend on real TUN, routes, or other VPNs on a Mac stay `[~]` until the release checklist has been run once by a maintainer.

### 1.1 Rules on top of Verge's profile

- [x] Rules go ahead of the profile's own, in every profile, through Verge's global Merge profile *(TUN and the system proxy are Verge's settings; the Overview shows what Verge is running)*
- [x] Mode switch (rule / global / direct) from the Overview and `mihomac verge mode`, with a warning on the Overview and Rules tabs whenever the core isn't in rule mode, since rules route nothing otherwise *(verified 2026-10-22 by clicking in the GUI: the core switched at once and a rule hot-load kept the switched mode. Verge keeps its own mode setting, so its next config rebuild brings that back; the daemon reads the live mode from the core every two seconds rather than trusting the runtime file)*
- [x] Allowlist rules for websites (domain, suffix, keyword) and apps
- [x] Each rule targets `DIRECT`, `REJECT`, or a proxy or group from the running Verge profile *(checked against Verge's runtime config before anything is written; a target that only exists in another profile is refused)*
- [x] Built-in rule packs for common direct-connect services (e.g. Bilibili, Taobao)
- [~] Default bypass for localhost, private ranges, `.local`, and Docker/OrbStack networks *(the list is in `internal/rules/packs.go`, prepended ahead of the profile's rules; real coexistence is a release-checklist row)*

### 1.2 Per-process / per-app rules

- [x] Resolve connections to process and app bundle *(mihomo's `find-process-mode: always`, which Verge sets, plus the socket table. Verified 2026-10-22: `Google Chrome Helper`, `curl`, `nc` attributed with paths through Verge's TUN)*
- [~] Rules by process name, path, or bundle ID *(name, path, and `.app` bundle are compiled and tested; matching happens in mihomo on a Mac. Matching by bundle ID itself isn't supported: use the app's path)*
- [~] App picker in the GUI (installed apps list) *(lists `/Applications` and friends; macOS only)*

### 1.3 Dual-NIC routing

- [~] Choose the outbound interface by CIDR, domain, or process *(`iface:<name>` targets)*
- [~] Internal DNS for internal domains (split DNS) *(`internal_dns` in rules.yaml, and automatic per-interface DHCP DNS for domains sent out an interface. The DNS policy is only hot-loaded into the running core, not written to the Merge file, so it is lost when Verge rebuilds its config until the GUI's "load rules" button is used; see How it fits with Clash Verge)*
- [~] Coexist with corporate VPN clients without overwriting their routes *(Verge's TUN settings decide this now; the traffic view reports flows that leave through another VPN's `utun`. Real check at the MVP gate)*
- [x] Interface status in the GUI (which NIC is up, which routes it owns)

### 1.4 Single-request diagnostics page

- [x] Live connection list: app → matched rule → interface/node → destination *(connections are polled once a second from the controller; one that opens and closes between two polls is missed. Switching to mihomo's streaming `/connections` endpoint is a follow-up)*
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
mihomac start                 # the MCP server talks to the running daemon
mihomac mcp --setup           # prints the exact commands for your install
claude mcp add mihomac -- /path/to/mihomac mcp
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
- [x] Import the resulting node(s) and subscription automatically, with no copy-paste *(imported nodes live in `nodes.yaml` and are appended to Verge's config through the Merge profile, so they are available in every Verge profile)*
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

- [~] Process attribution for every flow: PID, process name, executable path, app bundle, parent process, and code-signing identity *(from mihomo, `lsof`, `ps`, `codesign`, `plutil`; cached. `lsof` runs as the user, so sockets of root-owned processes, Verge's own mihomo among them, are attributed by mihomo only)*
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

- [x] Collectors behind interfaces so the sources can be swapped: Verge's mihomo controller (connections, rule matches), macOS socket and process tables (`lsof`, `ps`), interface counters (`netstat -ibd`), and route table (`netstat -rn`)
- [ ] Spike first: confirm the best unprivileged source for per-flow byte counts of traffic that never enters mihomo (`nettop -P -L`, the NetworkStatistics framework, or a Network Extension); record the findings here before building anything. There is no root helper any more, so packet capture would need its own privileged component and is probably not worth it *(not done: it needs a Mac. See "Traffic view: what is and isn't measured" below for what was built instead)*
- [x] Join logic (connection ↔ process ↔ interface) is pure code tested against recorded fixtures; live collection runs on this Mac on every start
- [x] Everything stays local; no traffic data leaves the machine

#### Traffic view: what is and isn't measured

Built without a spike, from sources that exist on every Mac:

- **Per-flow bytes** come from mihomo's connection list, so they exist for flows that entered TUN or the proxy port. Flows seen only in the socket table (traffic that bypassed TUN, local IPC) have no byte counts and draw as hairlines.
- **Interface counters** (`netstat -ibd`) give true bytes per NIC and per `utun`, which is what the reconciliation uses.
- **Attribution** uses mihomo's own process lookup plus `lsof` (as the user, so other users' processes are hidden) and `ps`.

The spike still has to answer: how to get per-flow bytes for traffic that never touches mihomo (candidates: `nettop -P -L`, the private NetworkStatistics framework, or a Network Extension), what each costs in privilege and stability across macOS releases, and whether it is worth it at all given what interface counters plus the socket table already show. Record the answer here before any capture code is written.

### 2.3 Node health and blocking detection

- [x] Periodic latency and availability checks *(every two minutes, mihomo's delay test through each node in the running Verge profile and each imported node)*
- [~] Detect blocking patterns (TCP reset, TLS handshake failure, DNS poisoning) *(only a failing node is examined, stage by stage: DNS against a DNS-over-HTTPS resolver, then TCP, then a TLS handshake. Tested with fakes; real censorship behavior is unverified)*
- [x] Multi-node failover groups with configurable policy *(`mihomac groups`: fallback, url-test with tolerance, load-balance with strategy; compiled into mihomo proxy-groups, which does the switching)*
- [x] Health history per node *(a week, 500 checks per node, kept locally)*

### 2.4 Community rule packs

- [x] Rule pack format with metadata (name, version, author, description) *(strict YAML; targets limited to DIRECT, REJECT, or an `@placeholder` you map to your own node; size and rule-count limits)*
- [x] Install, update, and remove packs from the GUI *(and `mihomac packs`; https URLs are fetched without touching private addresses)*
- [x] Preview a pack's effect as a diff before enabling it *(lists every rule and flags ones overridden by higher-precedence rules)*

### 2.5 Living with Verge

- [x] One daemon per build channel, both against the same Clash Verge; no instances, profiles, or core versions of our own *(Verge manages the core and its profiles)*
- [x] Logs: the daemon's own and Verge's `latest.log` *(`mihomac logs`, and the Network tab)*
- [x] Open the GUI from Verge's Settings → Web UI *(`mihomac up` and `./launch.command` add the plain address on their own whenever they are the ones starting Verge, since Verge only reads that list at start and rewrites the file later; `mihomac webui --install` does it by hand while Verge is closed. The Overview shows whether the entry is there. Verified 2026-10-23 against Verge 2.5.8: the entry was written, Verge kept it across hours of running, and the plain address opens the dashboard in a browser that logged in once with the token (a year-long cookie). A browser without the cookie gets a page explaining how to log in, not a bare 401. Verge opens Web UI entries in the default browser, not inside its own window)*
- [x] Detect the installed app and install it when missing; one-click start with `./launch.command` *(verified 2026-10-22, see Phase 0)*
- [ ] Survive Verge upgrades: detect a changed file layout (runtime config, profile index, socket path) and say so in the GUI instead of failing quietly

## Later / Ideas

Not committed. Open an issue to discuss before starting.

- Menu bar quick actions (pick node, open the diagnostics page for the newest surprise)
- Ship as a Clash Verge Rev fork with this daemon as a Tauri sidecar, so the pages live inside Verge's window and rule changes can call Verge's own apply instead of restarting it (see the companion-vs-fork notes above)
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
| Verge | A rule added in the GUI is in `GET /rules` at once, survives a Verge restart (through the Merge file), and switching Verge profiles keeps it |
| Dev tools | git, npm, pip, brew, and AI tools such as Claude and Cursor work normally |

## Privilege Model

Decision: **nothing runs as root.** Clash Verge already has a root service for TUN; Clash Mihomac never needs one. The daemon, CLI, localhost GUI, and MCP server run as the logged-in user.

- [x] **No privileged component.** The former root helper, its launchd packaging, and the core manager were removed in the October 2026 rewrite.
- [x] **Writes into Verge's directory are few and named.** The global Merge profile (three keys, other keys kept) and, only on `mihomac webui --install` while Verge is closed, the `web_ui_list` entry in `verge.yaml`. That entry carries no token (the file is world-readable); the browser is logged in by opening the token URL once, with a cookie that lasts a year. Nothing else in Verge's directory is written, and `clash-verge.yaml` is never written (Verge regenerates it).
- [x] **The hot-load path can't brick Verge.** A config the core rejects (a 400-class reply other than auth or routing errors) is rolled back in the Merge file before the error is shown, and a failed rollback is reported too; a config the core accepts is one Verge will accept too, because it was built the same way. The installer only accepts an app signed by Clash Verge Rev's Apple team (`JPH3Z7PPBB`) that passes Gatekeeper, and swaps it in only after the copy is complete.
- [x] **Untrusted input is data.** Subscriptions, share links, rule packs, Verge's files, and MCP requests are parsed strictly with size and depth limits, and never executed or used to build paths outside the directories named above.
- [x] **Tested without a Mac.** Verge's file formats are covered by recorded fixtures, the controller by a fake over TCP and over a Unix socket, and the restart sequence by a fake command runner.

## Security

Report vulnerabilities privately via GitHub private vulnerability reporting, not public issues. In scope: GUI/MCP auth and `127.0.0.1` binding, MCP changes applied without confirmation, anything that lets a rule, pack, share link, or MCP request write outside the Merge profile or load a config into Verge's core without the user's action, and VPS credential exposure. Out of scope: bugs in mihomo, Clash Verge Rev, or the mack-a script (report upstream). Only the latest `main` is supported until the first stable release.

Agent rule: never commit secrets, tokens, or real server credentials; examples use placeholders only.

## Non-Goals

- Windows, Linux, iOS, or Android clients
- A subscription marketplace or bundled proxy provider
- Exposing the GUI or MCP server beyond `127.0.0.1` by default

## Open Questions

- Verge has no IPC for "re-apply"; restarting it is the only way to make it rebuild its config. Is there a less disruptive trigger (a deep link, touching the profile index) in current Verge releases? Check each release.
- A user's global Script profile that assigns `config.rules` removes the Merge rules on every Verge apply. The daemon now hot-loads them again when it notices, so the gap is a few seconds after each Verge restart. Should it also warn about the script, or write its rules as a script of its own?
- The DNS policy for interface-bound rules can't go through the Merge file (Verge replaces `dns` wholesale). Options: a Script profile of our own, or asking Verge upstream for `append-nameserver-policy`.
- Should the diagnostics "why" page and per-app rules be offered upstream to Clash Verge Rev as a PR, leaving Clash Mihomac with the parts Verge wouldn't take (VPS, MCP, traffic view)?
- VPS installer: Phase 2.1 shipped our own sing-box (VLESS + Reality) installer instead of wrapping the mack-a script, because that script is an interactive menu and can't be driven safely and non-interactively. Should we also offer other protocols (Hysteria2, Trojan), or keep one well-tested path?
- The sing-box release checksums in `internal/vps/plan.go` are unpinned. A maintainer needs to copy the SHA-256 of each `linux-amd64` and `linux-arm64` asset from the release page and pin them
- Traffic view: which source gives per-flow bytes for traffic that never enters mihomo (see "Traffic view: what is and isn't measured")
- The first health round after a hot reload can see a transient 404 from the delay endpoint while mihomo rebuilds its proxies (seen 2026-10-22); should health checks pause for a moment after every reload?
- From the 2026-10-22 code review, not done yet: the Merge file is read, re-serialized, and written back, so an edit made in Verge's Merge editor in the same instant is lost (an mtime check before the rename, or a Merge profile of our own, would fix it); the core's log stream isn't restarted when the controller endpoint changes until it drops on its own; a stale Unix socket left by a crashed core wins over a live TCP controller when both are configured.
- Keychain storage for SSH keys once there is a native component
- License (currently TBD; a fork of Clash Verge Rev would have to be GPL-3.0, a companion doesn't)
