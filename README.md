# Clash Mihomac

> A mihomo client for macOS that takes you from zero to your own self-hosted VPN — built for developers and beginners alike.
> TUN by default. Every connection visible.

*Pronounced "mi-ho-mac" — mihomo + mac.*

---

## Why Clash Mihomac?

Existing Clash clients are built around subscription providers, hide what your traffic is actually doing, and get in the way when you need to work on an internal network. Clash Mihomac takes a different approach:

- **Your own VPS, not someone else's subscription** — guided setup from a blank server to a working VPN
- **See everything** — where each connection comes from, which rule it matched, and where it ends up
- **Developer-friendly** — intranet and internet side by side, without breaking localhost, Docker, or your corporate VPN
- **AI-ready** — built-in MCP support so AI assistants can inspect and help manage your network
- **macOS only** — one platform, done properly

## Who It's For

- **Everyday users going from zero to hero**: set up your own VPS as a personal VPN from scratch, no prior experience needed (compatible with mack-a script share links / QR codes)
- **Developers who work across networks**: Ethernet for proxied internet, Wi-Fi for the internal development network, both at the same time
- **Anyone who wants visibility and control**: see exactly where every connection goes, and let AI (via MCP) help diagnose and manage it

## Features

1. **Minimal localhost GUI** — a lightweight local web page, bound to `127.0.0.1` only and protected by token authentication
2. **MCP support** — AI can query connections, diagnose requests, and propose rule changes (dry-run first, applied only after you confirm)
3. **Dual-NIC routing** — choose the outbound interface by CIDR, domain, or process
4. **End-to-end traffic visualization** — app → rule → interface/node → destination, with per-request diagnostics
5. **TUN by default + allowlist** — rules for both websites and apps (direct or via a specific node), with built-in rule packs for services like Bilibili and Taobao
6. **Self-hosted node management** — health checks, blocking detection, and multi-node failover
7. **Multi-instance / multi-core** — run multiple profiles side by side; manage mihomo versions with one-click rollback
8. **Reliable on macOS** — automatic route recovery after sleep/wake and network changes

## Choosing a Mode

TUN is the default, but it isn't always the right choice:

| Scenario | Recommended mode | Why |
|---|---|---|
| Daily use with unified routing for all apps | **TUN** | Captures every process, including CLI tools that ignore the system proxy |
| Per-app routing (e.g. Bilibili direct) | **TUN** | Only TUN can reliably identify processes |
| Proxied internet + intranet development | **TUN** | Requires control over routes and outbound interfaces |
| Developing or debugging a proxy tool | **System proxy / port-only** | Frequently restarted processes shouldn't carry all system traffic |
| Corporate VPN must stay on and conflicts badly | **System proxy** | Avoids two TUN devices competing for the default route |
| Only one terminal or script needs a proxy | **Environment variables** (`https_proxy`) | Smallest possible blast radius |
| Checking whether the proxy is causing a problem | **Temporarily disable TUN** | A quick side-by-side comparison isolates the cause |

**Rule of thumb:** use TUN when you need full-system capture and fine-grained routing; use system proxy or port-only mode when you need something that can restart freely with minimal impact.

## Network Safety

TUN mode modifies system routes and DNS. If a client crashes or is force-quit, those changes can be left behind — and you end up offline *because* the proxy was closed. Clash Mihomac treats this as a core requirement, not an edge case:

- **Backup** of the original routing table and DNS settings at startup
- **Verified restore** on normal exit
- **Crash fallback** — a lightweight helper watches the main process and restores the network if it disappears
- **Startup self-check** — leftover routes or DNS from a previous session are cleaned up before launch
- **Emergency recovery** — `mihomac restore-network` from the CLI, or one click in the menu bar, no reboot required

---

## For Contributors: Developing Under Clash

Clash Mihomac is developed on machines that run Clash at all times, so **building it is also its first round of compatibility testing**.

### Keep your own connection separate

- **Never use the instance you're developing as your own network egress.** Restarting a debug daemon will cut off your connection, including AI tools and package managers.
- Use a **stable instance** (a release build, or another client such as Clash Verge) for everyday connectivity, and run the debug build separately:
  - Debug builds expose only mixed-port (HTTP/SOCKS) by default, **with TUN disabled**
  - Ports, config directories, and TUN device names never overlap with the stable instance
- Enable TUN on a debug build only when testing TUN features, and disable TUN on the stable instance first so the two don't fight over routes.

### Release compatibility checklist

Verify every item with TUN enabled before each release:

| Area | What to verify |
|---|---|
| localhost | Dev servers, HMR, and local databases work normally |
| Intranet | Internal IPs are reachable; internal domains resolve via internal DNS |
| Containers | Docker / OrbStack containers communicate both ways; image pulls succeed |
| mDNS | `.local` resolution and AirDrop device discovery work |
| VPN | Coexists with corporate VPN clients without overwriting each other's routes |
| Network changes | Recovers after sleep/wake, Wi-Fi switching, and cable plug/unplug |
| Dev tools | git, npm, pip, brew, and AI tools such as Claude and Cursor work normally |
| Shutdown | Routes and DNS are fully restored after both normal exit and force-quit |

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide, and [SECURITY.md](SECURITY.md) to report vulnerabilities.

## Roadmap

Summary below; see [ROADMAP.md](ROADMAP.md) for phases, deliverables, and exit criteria.

**MVP**

- [ ] TUN mode with allowlist
- [ ] Dual-NIC routing
- [ ] Per-process / per-app rules
- [ ] Single-request diagnostics page
- [ ] Basic MCP server
- [ ] Reliable network recovery

**Next**

- [ ] One-step VPS setup (zero to hero): enter your server's IPv4 address and password, and Clash Mihomac runs the mack-a script (or its own) over SSH to install, configure, and import a working VPN node in one go
- [ ] Traffic visualization (Sankey view)
- [ ] Node health and blocking detection
- [ ] Community rule packs
- [ ] Multi-instance and mihomo version management

## License

TBD
