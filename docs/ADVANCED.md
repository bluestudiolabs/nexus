# NEXUS — Personal Infrastructure Command Center

**3.0 clean developer preview** · Local-first · Configurable · Self-hosted

NEXUS is a personal dashboard for Linux hosts, computers, network devices and optional service integrations. It is designed to work without a cloud account. This repository is a clean-start edition, not an in-place upgrade for existing installations.

## Features

- Multi-computer Overview, configurable widgets, dashboard profiles and themes.
- Host CPU, memory, disk and network metrics; optional host collector and SMART information.
- Computer enrollment with one-time codes, HTTPS telemetry and persistent history.
- Historical comparisons, logical network map, console connectivity, alerts, rules and inventory.
- Owner authentication, optional TOTP and recovery codes; data filtering on the server.
- Native Windows agent source (x64 development build), Linux user agent and local lifecycle utility.
- Optional Uptime Kuma and weather; no default external monitoring or pre-registered devices.

## Start from zero

Requirements: Linux host, Python 3.11+, OpenSSL, Docker Engine with Compose v2 and a normal user authorized to access Docker. Docker access itself is privileged; use a dedicated trusted administrator account. The user-systemd collector additionally requires a working user systemd session. No physical disk layout or router brand is assumed.

From the extracted repository directory:

```bash
python3 manage.py setup
```

The setup prompts for the server IPv4 address and a unique owner password (minimum 14 characters). Default is loopback only. It creates a fresh private CA, TLS server certificate, password hash, random Compose project name and isolated `.nexus/` runtime. It then builds and starts the container. It does not install Docker or change host firewall rules. For explicit LAN setup, use your own private address, CIDR and interface:

```bash
# EXAMPLE ONLY: replace these values with your own local network.
python3 manage.py setup --address 10.20.30.10 --port 3010 --lan 10.20.30.0/24 --interface eth0
```

Use `--prepare-only` to generate and inspect the configuration without starting Docker; subsequently `python3 manage.py repair` builds/starts it. Use a different available port for a parallel test. Never overwrite an existing production checkout.

The installer prints the URL and public CA fingerprint. Verify the fingerprint via a trusted channel before trusting the public CA `.nexus/ca/ca.crt` in the client browser/OS or agent. Never distribute `.nexus/ca/ca.key`, TLS private key, password hash, DB or backups. No TLS verification bypass. The certificate is issued for the configured IPv4 address only. Keep the address stable; certificate reissue/renewal is currently manual and not automated. The default server certificate lasts 397 days. For a LAN deployment, verify host/router firewall rules and Docker published-port filtering; do not expose NEXUS to the public Internet. The installer does not claim to enforce perimeter security.

Log in at the printed URL. Overview starts with an empty device registry and generic widgets. Use Devices → Register computer → pairing code. Select Appearance to customize themes; upload a background if desired (wallpaper is browser-local). Use Privacy & 2FA to enable the authenticator. Save recovery codes offline.

### Optional integrations

Edit `.nexus/config.env` (local only) and run `python3 manage.py repair` to apply container environment changes. `KUMA_URL` and `KUMA_SLUG` are empty by default; configure only a trusted status-page endpoint. Weather requires explicit opt-in in Security and user-supplied coordinates. No preset personal service endpoints. Workspace shortcut links are browser-local; see Workspace shortcut editor. System storage measures the filesystem containing `.nexus/meter`; additional storage is unconfigured in this edition. Disk I/O enumerates visible block devices. Unsupported metrics appear unavailable.

To enable optional host snapshots, run `python3 manage.py collect` or `python3 manage.py collector-enable` (user systemd timer; runs while user manager is active). `collector-disable` removes the timer. Host commands are fixed, and the collector can only read information its local user can access; SMART, ARP and some system logs may require additional OS permissions. Do not grant the web container root, host Docker socket or broad extra privileges. For ARP discovery, set `NEXUS_DISCOVERY=1` only with an explicitly authorized IPv4 subnet of /20 or smaller and its interface; set `NEXUS_GATEWAY` if desired. Alternatively supply `--discovery --lan ... --interface ...` at setup. `NEXUS_SMART_DEVICES` and `NEXUS_SERVICES` accept space-separated local identifiers; leave them empty for no collection. Internet ping is off unless `NEXUS_INTERNET_PROBE=1`. Discovery does not authorize devices.

## Agents

**Windows:** the container build compiles the native x64 executable from `agents/windows`. Download from Devices, enter the configured HTTPS origin and one-time code, and optionally select the verified CA. Windows autostart is per-user sign-in, not pre-login service. The build is unsigned and may be blocked by Smart App Control. Do not bypass Windows protections. See [signing and release process](RELEASE.md). FPS, extra sensors and Windows runtime/installation testing remain open.

**Linux:** download the Linux ZIP, extract, then `bash setup-linux.sh install` as normal user; follow the origin/CA/code prompts. To uninstall: `bash setup-linux.sh uninstall`. Local uninstall does not remove server history or revoke a server token automatically; revoke the device in NEXUS too.

## Lifecycle / Einstein mode

```bash
python3 manage.py status
python3 manage.py doctor
python3 manage.py backup
python3 manage.py stop
python3 manage.py start
python3 manage.py repair
python3 manage.py uninstall --dry-run
python3 manage.py uninstall --keep-data
python3 manage.py uninstall --purge
```

Purge requests explicit confirmation and deletes only the managed runtime directory and this installation's Compose resources. Source checkout, external backups, Docker Engine, unrelated services and remote agents remain. The backup is private and includes CA keys and authentication data; protect it and do not commit it. Restore automation, safe version migration and browser-triggered privileged uninstall are not provided by this edition. The browser uninstall route is deliberately disabled. No shared host systemd units are modified.

## Development

```bash
python3 -m unittest discover -v
for f in *.js; do node --check "$f"; done
(cd agents/windows && go test ./...)
(cd agents/windows && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-H windowsgui -s -w' -o ../../NEXUS-Agent-Setup-x64.exe .)
```

`ui_test.py` is an optional Chromium/Playwright smoke test with synthetic API fixtures (requires Python Playwright and its Chromium, installed with `playwright install chromium`; set `NEXUS_CHROMIUM` to use a different Chromium binary). GitHub Actions runs backend and transport tests, JS syntax checks, a Windows cross-build and Docker build. Its executable artifact is explicitly unsigned and not a public release. Docker deployment, Windows UI, real hardware and signing still require validation.

## Project layout

- `secure.py`, `core.py`, `server.py`: authenticated API, identity/history and host telemetry.
- `dashboard.py`, `features.py`: preferences, rules, privacy and TOTP.
- `index.html`, `*.js`, `dashboard.css`: dashboard and interaction.
- `collector.py`, `manage.py`, `compose.yaml`, `Dockerfile`: deployment and optional host telemetry.
- `agents/windows/`: native Go source; `agent-linux.py`, `setup-linux.sh`: Linux agent.
- `test_*.py`, `ui_test.py`, `.github/workflows/`: regression tests and CI.

Read [security](../SECURITY.md), [contributing](../CONTRIBUTING.md) and [release checklist](RELEASE.md) before publishing. NEXUS is released under the [MIT License](../LICENSE). Report security vulnerabilities privately through GitHub private vulnerability reporting (repository **Security** tab → **Report a vulnerability**), not in public issues.
