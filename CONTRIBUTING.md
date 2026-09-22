# Contributing to Clash Mihomac

Thanks for your interest! This guide covers how to set up a safe development environment, what we expect from changes, and how releases are checked.

See [ROADMAP.md](ROADMAP.md) for what's planned and where help is most useful.

---

## Before You Start

- **Check the roadmap and open issues** to avoid duplicate work.
- **Open an issue first** for anything larger than a small fix, especially changes to routing, DNS, TUN, or the privileged helper.
- Clash Mihomac supports **macOS only**. Please don't submit cross-platform abstractions.

## Developing Under Clash

Clash Mihomac is developed on machines that run Clash at all times, so **building it is also its first round of compatibility testing**.

### Keep your own connection separate

- **Never use the instance you're developing as your own network egress.** Restarting a debug daemon will cut off your connection, including AI tools and package managers.
- Use a **stable instance** (a release build, or another client such as Clash Verge) for everyday connectivity, and run the debug build separately:
  - Debug builds expose only mixed-port (HTTP/SOCKS) by default, **with TUN disabled**
  - Ports, config directories, and TUN device names never overlap with the stable instance
- Enable TUN on a debug build only when testing TUN features, and **disable TUN on the stable instance first** so the two don't fight over routes.

### If you lose connectivity

1. Run `mihomac restore-network` (or use the menu bar's recovery action).
2. If that isn't available yet, stop the debug daemon and check for leftover routes and DNS:
   ```sh
   netstat -rn -f inet        # look for routes via utun devices you don't expect
   scutil --dns               # look for resolvers pointing at the debug instance
   ```
3. File an issue with what you saw. A network left broken after exit is a **release-blocking bug**.

## Making Changes

### Branches and commits

- Branch from `main`: `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Keep each pull request focused on one change

### Pull requests

Your PR description should include:

- **What** changed and **why**
- **How you tested it**, including whether TUN was enabled
- Which rows of the [release compatibility checklist](#release-compatibility-checklist) your change could affect
- Screenshots for GUI changes

### Changes that need extra care

These areas can leave users offline or expose their traffic. PRs touching them need a maintainer review and a manual test with TUN enabled:

| Area | Why |
|---|---|
| Routes, DNS, TUN setup/teardown | Mistakes leave the user offline after exit |
| Privileged helper | Runs as root; keep its command surface minimal |
| Localhost GUI / MCP auth | Must stay bound to `127.0.0.1` with token auth |
| MCP write tools | Must stay dry-run first, applied only after confirmation |
| VPS setup over SSH | Handles server credentials; show commands before running them |

## Release Compatibility Checklist

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

## Reporting Security Issues

Please don't open public issues for security problems. See [SECURITY.md](SECURITY.md).
