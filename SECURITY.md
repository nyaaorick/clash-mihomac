# Security Policy

Clash Mihomac runs a privileged helper, changes system routes and DNS, exposes a local GUI and MCP server, and can connect to your VPS over SSH. We take issues in any of these areas seriously.

## Reporting a Vulnerability

**Please do not open a public issue.** Instead, report privately via GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository.

Include:

- A description of the issue and its impact
- Steps to reproduce
- The Clash Mihomac and mihomo versions, and your macOS version

We aim to acknowledge reports within a few days and will keep you updated until a fix is released.

## In Scope

- **Localhost GUI and MCP server** — authentication bypass, binding to anything other than `127.0.0.1` without consent, cross-site requests from a browser page (CSRF, DNS rebinding)
- **MCP tools** — any way to apply a config change without user confirmation
- **Privileged helper** — privilege escalation, arbitrary command execution, unauthenticated access to the helper
- **Network safety** — traffic leaking outside the configured route, or routes/DNS left in an unsafe state
- **VPS setup** — credential exposure (passwords, SSH keys) in logs, files, or memory longer than necessary; running commands the user did not see
- **Core management** — installing a mihomo binary without verifying its checksum

## Out of Scope

- Vulnerabilities in mihomo itself — please report those [upstream](https://github.com/MetaCubeX/mihomo)
- Vulnerabilities in the mack-a install script — please report those to its maintainers
- Attacks that require an already-compromised user account or root access

## Supported Versions

Until the first stable release, only the latest build on `main` is supported.
