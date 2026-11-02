# PortScope

**A Windows-first networking workbench for your local machine.**

Monitor ports and processes, inspect connections, run ICMP Ping and continuous Traceroute/MTR, troubleshoot DNS, and explore a live network atlas—all in a local browser dashboard.

[![Release](https://img.shields.io/github/v/release/jrrub2/PortScope?include_prereleases)](https://github.com/jrrub2/PortScope/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](<LICENSE>)

[Download](https://github.com/jrrub2/PortScope/releases) · [Getting started](#getting-started) · [Features](#features) · [Platform support](#platform-support) · [Report an issue](https://github.com/jrrub2/PortScope/issues)

![PortScope overview with synthetic demo services](<screenshots/overview.png>)

> Screenshots show the real application with **synthetic demo data**, not a real device or network. Hostnames, process IDs, addresses, route measurements, and map locations are illustrative.

## Features

- **Ports & processes** — live listener inventory, HTTP service identification, process details, search, filters, favorites, and watchlists. On Windows, an explicit red confirmation can force-stop an eligible listener's owning process.
- **Connections** — TCP/UDP socket inventory, local/remote endpoints, process ownership, and interface information.
- **Ping / Traceroute** — ICMP Ping and MTR-style continuous monitoring with independently scheduled per-TTL probes, loss/latency statistics, sparklines, selected-hop charts, and optional reverse-DNS names beside hop IPs.
- **DNS tools** — record queries, custom resolvers, resolver comparison, reverse lookups, and optional browser DNS observations.
- **Network atlas** — offline-first map, live connection destinations, manual locations, and consent-only GeoIP/online basemap.
- **Health & history** — local endpoint checks, session analytics, activity logs, snapshots, comparisons, and JSON/CSV exports.
- **A focused workspace** — dark/light themes, keyboard navigation, responsive layouts, and readable multi-hop pagination. Built with React, [shadcn/ui](https://ui.shadcn.com/), [mapcn](https://www.mapcn.dev/), MapLibre, and Recharts.

## Getting started

### Windows: portable app (recommended)

1. Open [Releases](https://github.com/jrrub2/PortScope/releases) and download **PortScope-2.2.2-windows-x64.zip**.
2. Extract the **entire ZIP** to a folder. Do not run it from the ZIP preview.
3. Double-click **PortScope.exe**. Your browser opens the local dashboard automatically.
4. Keep its console window open while monitoring. Press **Ctrl+C** or close that console to stop PortScope and its workers.

**No Node.js installation, batch file, or administrator access is required.** The ZIP includes the Node runtime and application resources; keep its folders beside the executable. This is an **unsigned portable preview**, not an installer or a single self-contained binary. Windows may show an unsigned-app warning; verify the release source and SHA-256 before deciding to run it. Do not disable security protections.

Requirements: Windows x64, .NET Framework 4.8, and Windows PowerShell 5.1 for ICMP diagnostics. Windows 11 is locally tested; Windows 10 is a compatibility target, not an independently verified release.

Optional console usage:

```powershell
.\PortScope.exe --help
.\PortScope.exe --port 5000 --open
```

### Run from source

Install [Node.js](https://nodejs.org/) **22.12+** (24 LTS recommended), then:

```sh
git clone https://github.com/jrrub2/PortScope.git
cd PortScope
node server.js --open
```

The prebuilt dashboard is included; **no dependency installation or frontend build is needed to run it**. The backend uses only Node built-ins. The default address is `http://127.0.0.1:4599`; if busy, PortScope prints the next available local port. Use the printed URL.

```sh
node server.js --help
node server.js --port 5000 --interval 2000
```

For force-stop or installation controls, use the **private control link** printed in the console (opened automatically with `--open`). Its fragment authorizes only that browser tab; do not share the link. Opening the plain dashboard address still allows monitoring. After a manual server restart, use its newly printed private link again.

Stop with **Ctrl+C**. After manually updating source, restart the backend and refresh the browser; a page refresh alone does not update a running server. The supported portable updater performs its own restart.

### Updates from GitHub

Settings checks the public [GitHub Releases](https://github.com/jrrub2/PortScope/releases) feed—no separate hosting or account is needed. Automatic notifications check when the dashboard opens and every six hours while visible; turn them off in Settings for offline use. Downloads and installation **never start automatically**. Preview releases are labeled.

One-click installation requires the updated **Windows x64 portable launcher**. It verifies the release asset's GitHub SHA-256 digest, stages the package, preserves a rollback backup, and restarts on the same local port. Browser data stays in place; in-memory diagnostics and history end on restart. Success is shown only after the native transaction commits. If interrupted, retain the update session and backup; the launcher prints the journal path and refuses to boot partially swapped files until they are manually recovered. Unsigned releases still trust the GitHub publisher; a checksum is not a publisher signature.

Older portable launchers (including 2.2.1), source checkouts, and unsupported layouts use the manual release link. They are not overwritten or reset by the updater. Installing a release with the new launcher once enables subsequent one-click updates.

## Screenshots

### Continuous Traceroute / MTR

![Selected-hop latency history using synthetic MTR replies](<screenshots/traceroute.png>)

Each TTL keeps probing the same destination independently until Stop. A silent hop does not block healthy hops. Timeouts appear as gaps, not fake zero-latency replies. Focus mode keeps Stop, hop pagination, and charts reachable without shrinking the text.

### Network atlas

![Offline network atlas with manually assigned synthetic locations](<screenshots/atlas.png>)

The base map works locally. Demo locations are manually assigned; connection arcs are inventory references, **not measured packet routes**. A localhost/private address does not reveal a geographic location.

## Platform support

PortScope is a **Windows-first preview**, not a claim of feature parity across operating systems.

| Capability | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Local listeners / process details | Available; Windows 11 tested | Experimental: `lsof` or `ss`, `ps` | Experimental: `lsof`, `ps`; executable path may be unavailable |
| Connections / live atlas destinations | Available | Experimental; requires `ss` / iproute2 | Not available on stock macOS |
| ICMP Ping / Traceroute / MTR | Available; PowerShell 5.1 / .NET required | Not supported | Not supported |
| TCP connect, TLS, DNS, HTTP checks | Available | Portable Node implementation; native OS verification pending | Portable Node implementation; native OS verification pending |
| Portable executable | Windows x64 | Not provided | Not provided |

Linux/macOS must use the source entry point. Process visibility depends on OS permissions. Restricted PowerShell policies can prevent native ICMP; do not run elevated by default.

## Privacy & security

- **Local server only:** binds to `127.0.0.1`, validates Host/Origin/Fetch Metadata, and does not expose a LAN dashboard. No cloud account or automatic telemetry.
- **Guarded process control:** monitoring is read-only, but Windows port details can force-stop an eligible process after explicit red confirmation. This can lose unsaved work and affect all ports owned by that process; child processes may also exit. PortScope revalidates process identity and listener ownership and refuses protected, service, other-user, or application-ancestor processes. It does not modify the firewall or reconfigure services.
- **Network traffic:** update notifications contact the fixed public GitHub Releases feed by default; disable automatic checks in Settings if desired. Run sends probes to your chosen target; Resolve names queries the host's DNS resolvers for hop PTR records. GeoIP, the online basemap, and the browser DNS observer require explicit opt-in and disclose their providers. The offline atlas does not require external requests.
- **Your device stays yours:** the sidebar displays your machine hostname, not a developer account. Live data can include process names, paths, local/remote addresses, and service titles. Review screenshots and exports before sharing them.
- **Local storage:** favorites, settings, snapshots, health definitions, and manual map locations stay in browser storage. Backend history is bounded and held in memory, not a cloud database.
- **Public assets are separate:** repository screenshots are generated from isolated fixtures. Historical machine captures, QA reports, local environment files, and personal archives are excluded from publication.

Optional providers are **ipwho.is** (GeoIP), **CARTO/OpenStreetMap** (online map), and **dnscheck.tools/addr.tools** (browser DNS observations). These services can see requests you explicitly enable; availability and provider terms apply.

### Measurement limits

PortScope is not a packet capture tool. Polling can miss short-lived sockets. Wildcard binding is not proof of internet exposure, GeoIP is approximate, and ICMP response loss is not necessarily forwarding loss. Intermediate-hop timings can include scheduling overhead; no timing parity with WinMTR is claimed. Continuous jobs stop when their owning view is stopped, paused, closed, or disconnected beyond the lease grace period.

## Development

The backend is CommonJS; the frontend is React/TypeScript, Vite, and Tailwind. Use the pinned pnpm version from the [package manifest](<package.json>) and the [lockfile](<pnpm-lock.yaml>).

```sh
pnpm install --frozen-lockfile
pnpm build
node server.js --open
```

For frontend changes, run `pnpm dev:web` alongside the same backend, then refresh. Do not start a second frontend application server.

```sh
pnpm test                         # Framework-free frontend self-checks
node tools/update-notices.mjs --check
```

Build a Windows portable release with 64-bit Windows PowerShell 5.1 and a supported local Windows x64 Node runtime:

```powershell
powershell -NoProfile -File tools/package-windows.ps1
```

The packager copies only runtime files, includes application/dependency/Node licenses, and emits a ZIP plus SHA-256 under `dist/`. It downloads the exact Node-version license when no local license is supplied. Executables and generated archives belong in [Releases](https://github.com/jrrub2/PortScope/releases), not Git history.

## Contributing

Issues and focused pull requests are welcome. Include the PortScope version, operating system, steps to reproduce, and a **redacted** example. Never attach real network exports, credentials, or process command lines without reviewing them. Preserve loopback-only defaults, consent boundaries, accessibility, and bounded background jobs.

## License

[MIT](<LICENSE>). Bundled UI components and dependencies retain their own licenses in the [third-party notices](<web/THIRD-PARTY-NOTICES.txt>). Natural Earth geometry is public domain. Portable releases also include the Node runtime license and its bundled dependency notices.
