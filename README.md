# ENSAT: Enterprise Network Security Assessment Toolkit

ENSAT is a defensive security assessment platform for **authorized environments**. One command or one click runs
discovery, service enumeration, misconfiguration checks, CVE correlation (NVD + FIRST EPSS + CISA KEV), contextual risk
scoring, remediation tracking and executive/technical reporting. All results appear in a multi-page Streamlit dashboard.

> **Authorization.** Only assess systems you own or have written permission to test. ENSAT enforces a scope file,
> records who authorized each scan, and uses only non-intrusive techniques: Nmap `safe` scripts and plain GET/OPTIONS
> web requests. It never runs exploits, brute-forces or fuzzes.

```text
ensat assess 192.168.56.0/24
  -> discover hosts -> enumerate services -> security checks (network / TLS / web)
  -> CPE -> NVD CVEs -> EPSS + KEV -> contextual risk -> SQLite -> PDF/CSV/JSON -> dashboard
```

## Features

| Area | What ENSAT does |
|---|---|
| **Asset discovery** | Live hosts, IPs, MAC address + vendor, hostnames (forward/reverse), OS fingerprint, persistent asset inventory, detection of new or unrecognised assets |
| **Enumeration** | TCP (connect or SYN) and common UDP ports, service/version detection, banner grabbing, HTTP/HTTPS enumeration, TLS certificate collection, DNS recursion check |
| **Vulnerability assessment** | CPE extraction (Nmap and HTTP headers), CPE 2.2 to 2.3 conversion with vendor aliases, NVD CVE lookup verified against NVD version ranges, CVSS v4.0/v3.x/v2, CWE, EPSS probability and percentile, CISA KEV status, public-exploit references, de-duplication |
| **Risk engine** | CVSS or rule base score adjusted for KEV, EPSS, exploit availability, internet exposure, asset criticality and business impact. Every adjustment is listed, and results are prioritised Critical to Low |
| **Security checks** | SMB/SMBv1/SMB signing, FTP and anonymous FTP, Telnet, r-services, RDP, VNC, databases (MySQL, MSSQL, PostgreSQL, Oracle, MongoDB, Redis, Elasticsearch, Memcached), Docker/Kubernetes/WinRM/IPMI/SNMP management ports, unauthenticated Redis/MongoDB, weak SSH algorithms, default web pages |
| **TLS checks** | Expired, expiring, not-yet-valid or self-signed certificates, weak keys, SHA-1/MD5 signatures, hostname mismatch, TLS 1.0/1.1 support, weak cipher grade |
| **Web checks (passive)** | HTTPS enforcement, HSTS, CSP, clickjacking protection, other security headers, version disclosure, cookie flags, directory listing, risky HTTP methods, exposed `.git`/`.env`/server-status/.DS_Store, technology fingerprinting, OWASP Top 10 mapping |
| **Vulnerability management** | Each finding has CVE, asset, service, CVSS, EPSS, severity, evidence, impact, recommendation and status. Statuses: `OPEN -> IN_PROGRESS -> REMEDIATED -> VERIFIED` (plus `ACCEPTED_RISK`, `FALSE_POSITIVE`). History, assignee and notes are kept. Re-scans **verify fixes automatically** and **reopen** issues that come back |
| **Scan comparison** | Before/after severity counts, a weighted risk index, "Risk reduced by N%", and lists of resolved, new and persisting findings plus new or missing assets and services |
| **Reporting** | Executive PDF (rating, headline, KPIs, chart, change since last scan, top risks, strategic recommendations). Technical PDF (scope, authorization, methodology, Nmap arguments, asset and service inventory, full finding details). CSV and JSON |
| **Dashboard** | Overview KPIs and trend, browser-based scans with live progress, vulnerability triage (filter, search, sort, bulk status updates), editable asset inventory, service inventory, CVE search, history and comparison, report downloads, settings and scope editor |
| **Engineering** | Modular packages, input validation (no option injection into Nmap), scope enforcement, rotating logs, `.env` configuration, SQLite with WAL, 87 unit, integration and dashboard tests, GitHub Actions CI, Docker |

## Quick start

### 1. Install

Install Python 3.10+ and [Nmap](https://nmap.org/download.html). On Windows, tick "Add to PATH" in the Nmap installer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env           # macOS/Linux: cp .env.example .env
copy scope.example.txt scope.txt # then list ONLY systems you are authorized to assess
```

You can also run `pip install -e .`, which adds a global `ensat` command.

Get a free NVD API key at <https://nvd.nist.gov/developers/request-an-api-key> and put it in `.env`. ENSAT works
without one, but CVE lookups are limited to 5 requests per 30 seconds.

### 2. Run an assessment

```bash
python -m ensat assess 127.0.0.1                         # localhost is always in scope
python -m ensat assess 192.168.56.0/24 --profile quick   # must be listed in scope.txt
python -m ensat assess 10.0.0.5 --authorized --note "ENG-42"   # outside scope.txt: explicit confirmation is recorded
```

Profiles:

| Profile | Ports | Extras |
|---|---|---|
| `quick` | Top 100 | Light version detection |
| `standard` | Top 1000 | Version detection and safe NSE scripts |
| `full` | All 65535 | Extended safe scripts (cipher grading, SSH algorithms) |

Add `--os` and `--udp` for OS detection and UDP. Both need an elevated terminal (Administrator or root), as do
MAC/vendor discovery and SYN scanning.

### 3. Open the dashboard

```bash
python -m ensat dashboard         # or: streamlit run ensat/dashboard/app.py
```

Then go to <http://localhost:8501>.

### 4. Track remediation and compare

```bash
python -m ensat findings                        # current open issues, in priority order
python -m ensat status IN_PROGRESS 3f2a9c1b --note "CHG-1234"
python -m ensat status REMEDIATED 3f2a9c1b
python -m ensat assess 192.168.56.10            # the re-scan marks fixed issues VERIFIED
python -m ensat compare                         # "Risk reduced by 68%"
python -m ensat report --type all               # executive + technical PDF, CSV, JSON
```

## CLI reference

| Command | Purpose |
|---|---|
| `assess <targets>` (alias `scan`) | Full pipeline. Options: `--profile`, `--ports`, `--os`, `--udp`, `--no-ping`, `--no-scripts`, `--no-tls`, `--no-web`, `--no-cve`, `--authorized`, `--note`, `--report executive\|technical\|both\|none` |
| `history` | List scans |
| `findings` | Current issues. Filters: `--severity`, `--status`, `--kev`, `--all`, `--scan-id` |
| `status <STATUS> <id...>` | Change remediation status (`--note`) |
| `compare [--before N --after M]` | Compare two scans (default: latest vs. previous scan of the same target) |
| `report [--scan-id N] --type executive\|technical\|csv\|json\|all` | Generate reports (`export` is an alias defaulting to JSON) |
| `assets [address --criticality --impact --exposure --owner --tags --known]` | Inventory and business context. Open findings are re-scored immediately |
| `cve <CVE-ID or keyword>` | NVD lookup with EPSS and KEV |
| `intel-update` | Refresh the CISA KEV catalog |
| `dashboard [--port]` | Launch the Streamlit UI |

## How risk is calculated

```text
risk = base (CVSS 4.0 > 3.x > 2.0, or the ENSAT rule score for configuration findings)
     + 1.5 if in CISA KEV          (and floored at 9.0 when CVSS >= 7, else 7.0)
     + 0.5 if a public exploit is referenced (non-KEV)
     + 1.0 if EPSS >= 50%  | +0.5 if EPSS >= 10% | -0.5 if EPSS < 1%
     + 1.0 if the asset is internet-exposed (public IP, or set manually)
     + 1.0 / +0.5 / 0 / -1.0 for asset criticality critical / high / medium / low
     + 0.5 / 0 / -0.5 for business impact high / medium / low
clamped to 0.1-10.  Critical >= 9.0, High >= 7.0, Medium >= 4.0, Low > 0, Info = 0
```

For example, CVSS 9.8 + KEV + EPSS 92% + internet-facing + critical asset scores **10.0, Critical**. The dashboard and
the technical report show the factors behind each score.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full diagram and data model.

```text
ensat/
  cli.py          argparse + Rich CLI
  pipeline.py     one-command orchestration with progress callbacks
  validation.py   target/port validation, scope + authorization
  scanner.py      Nmap command builder, streaming XML + live progress
  parser.py       Nmap XML -> models (MAC, OS, scripts, multi-run merge)
  checks/         network.py (exposure + NSE), tls.py, web.py
  intel/          cpe.py, nvd.py, feeds.py (EPSS, KEV), cache.py
  risk.py         contextual risk engine
  db.py           SQLite: scans, assets, services, findings, issues, status history
  compare.py      before/after comparison
  reporting/      executive + technical PDF, CSV, JSON
  dashboard/      Streamlit app (9 pages)
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest                 # 87 tests: unit, local TLS/web servers, pipeline, CLI, every dashboard page
pytest -m integration  # real Nmap scan of a throwaway localhost server
ruff check ensat tests
```

The NVD, EPSS and KEV clients are tested against recorded-format responses, so tests never touch the internet.

## Docker

```bash
docker compose up --build    # dashboard on :8501; Linux host networking lets Nmap reach your LAN
docker compose run --rm ensat python -m ensat assess 192.168.56.10
```

## Accuracy notes and limitations

- **CVE matching depends on Nmap's version detection.** Linux distributions often backport security fixes without
  changing the upstream version string (for example, `OpenSSH 7.4p1 Debian 10+deb9u7`), so version-based matching can
  report CVEs that are already patched. Validate them against vendor advisories and use `FALSE_POSITIVE` where
  appropriate.
- **Some features need an elevated terminal.** OS detection, UDP, SYN scanning and MAC/vendor discovery need
  Administrator/root. MAC addresses are only visible for hosts on the same layer-2 network.
- **The web checks are a starting point, not an application security test.** They are passive and limited to the site
  root and a few well-known paths. They do not replace a full application test.
- **Default databases changed in V2.** V2 stores data in `data/ensat.db` with a new schema. V1's `scans/ensat.db` is
  not migrated.

## License

MIT
