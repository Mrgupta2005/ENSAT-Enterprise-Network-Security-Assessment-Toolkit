"""SQLite persistence: scans, asset inventory, services, findings and remediation tracking.

Two layers of finding data are kept:

* ``findings`` - an immutable snapshot of what each scan saw.
* ``issues``   - one row per unique problem (keyed by fingerprint) carrying the
  remediation status, so status survives across scans and duplicates collapse.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .models import CLOSED_STATUSES, SEVERITIES, STATUSES, Finding, Host, ScanOptions
from .risk import AssetContext, asset_risk, is_internet_facing

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL, profile TEXT, options_json TEXT, scope_key TEXT,
  started_at TEXT NOT NULL, finished_at TEXT, duration_seconds REAL,
  status TEXT NOT NULL, error TEXT,
  operator TEXT, authorized_by TEXT, authorization_note TEXT, out_of_scope INTEGER DEFAULT 0,
  nmap_args TEXT, nmap_version TEXT, privileged INTEGER DEFAULT 0, warnings_json TEXT,
  hosts_up INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT NOT NULL UNIQUE, hostname TEXT, mac TEXT, vendor TEXT, os_name TEXT,
  first_seen TEXT, last_seen TEXT, first_scan_id INTEGER, last_scan_id INTEGER,
  criticality TEXT DEFAULT 'medium', business_impact TEXT DEFAULT 'medium',
  exposure TEXT DEFAULT 'auto', owner TEXT DEFAULT '', tags TEXT DEFAULT '', notes TEXT DEFAULT '',
  known INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id), asset_id INTEGER REFERENCES assets(id),
  address TEXT NOT NULL, hostname TEXT, hostnames TEXT, status TEXT, mac TEXT, vendor TEXT,
  os_name TEXT, os_accuracy INTEGER, is_new INTEGER DEFAULT 0, scripts_json TEXT
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id), scan_host_id INTEGER REFERENCES scan_hosts(id),
  address TEXT, port INTEGER, protocol TEXT, state TEXT, service TEXT, product TEXT, version TEXT,
  extrainfo TEXT, tunnel TEXT, cpes TEXT, banner TEXT, reason TEXT, scripts_json TEXT,
  tls_json TEXT, web_json TEXT
);
CREATE TABLE IF NOT EXISTS issues (
  fingerprint TEXT PRIMARY KEY,
  address TEXT, port INTEGER, protocol TEXT, check_id TEXT, cve TEXT, title TEXT,
  status TEXT NOT NULL DEFAULT 'OPEN', assignee TEXT DEFAULT '', notes TEXT DEFAULT '',
  first_seen_scan INTEGER, last_seen_scan INTEGER, first_seen_at TEXT, last_seen_at TEXT, status_changed_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id), fingerprint TEXT NOT NULL,
  host TEXT, port INTEGER, protocol TEXT, service TEXT, check_id TEXT, category TEXT, title TEXT,
  base_score REAL, risk_score REAL, severity TEXT, evidence TEXT, impact TEXT, recommendation TEXT,
  cve TEXT, cvss_version TEXT, cvss_vector TEXT, cvss3 REAL, cvss4 REAL, cwe TEXT,
  epss REAL, epss_percentile REAL, kev INTEGER DEFAULT 0, exploit_available INTEGER DEFAULT 0,
  owasp TEXT, references_json TEXT, risk_factors_json TEXT
);
CREATE TABLE IF NOT EXISTS status_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint TEXT NOT NULL, old_status TEXT, new_status TEXT NOT NULL,
  changed_at TEXT NOT NULL, changed_by TEXT, note TEXT
);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS ix_findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS ix_services_scan ON services(scan_id);
CREATE INDEX IF NOT EXISTS ix_hosts_scan ON scan_hosts(scan_id);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as c:
            c.executescript(SCHEMA)
            c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            pass
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _all(self, sql: str, params: Iterable = ()) -> list[dict]:
        with self.connect() as c:
            return [dict(r) for r in c.execute(sql, tuple(params)).fetchall()]

    def _one(self, sql: str, params: Iterable = ()) -> Optional[dict]:
        rows = self._all(sql, params)
        return rows[0] if rows else None

    # ------------------------------------------------------------ scans --
    @staticmethod
    def scope_key(opts: ScanOptions) -> str:
        return f"{opts.profile}|{opts.ports or ''}|{int(opts.udp)}|{int(opts.nse_scripts)}|{int(opts.web_checks)}|{int(opts.tls_checks)}"

    def create_scan(self, opts: ScanOptions, operator: str, out_of_scope: bool) -> int:
        opts_dict = {k: v for k, v in vars(opts).items()}
        with self.connect() as c:
            cur = c.execute(
                "INSERT INTO scans(target, profile, options_json, scope_key, started_at, status, operator, authorized_by, "
                "authorization_note, out_of_scope) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (opts.target, opts.profile, json.dumps(opts_dict), self.scope_key(opts), now_iso(), "running", operator,
                 opts.authorized_by, opts.authorization_note, int(out_of_scope)))
            return cur.lastrowid

    def fail_scan(self, scan_id: int, error: str, duration: float | None = None) -> None:
        with self.connect() as c:
            c.execute("UPDATE scans SET status='failed', error=?, finished_at=?, duration_seconds=? WHERE id=?",
                      (error[:2000], now_iso(), duration, scan_id))

    def list_scans(self, limit: int = 500) -> list[dict]:
        return self._all("""SELECT s.*,
              (SELECT count(*) FROM findings f WHERE f.scan_id=s.id AND f.severity='Critical') AS critical,
              (SELECT count(*) FROM findings f WHERE f.scan_id=s.id AND f.severity='High') AS high,
              (SELECT count(*) FROM findings f WHERE f.scan_id=s.id AND f.severity='Medium') AS medium,
              (SELECT count(*) FROM findings f WHERE f.scan_id=s.id AND f.severity='Low') AS low,
              (SELECT count(*) FROM findings f WHERE f.scan_id=s.id) AS findings,
              (SELECT count(*) FROM services v WHERE v.scan_id=s.id) AS services
            FROM scans s ORDER BY s.id DESC LIMIT ?""", (limit,))

    def get_scan(self, scan_id: int) -> Optional[dict]:
        row = self._one("SELECT * FROM scans WHERE id=?", (scan_id,))
        if row:
            row["warnings"] = json.loads(row.get("warnings_json") or "[]")
            row["options"] = json.loads(row.get("options_json") or "{}")
        return row

    def latest_scan(self, target: str | None = None) -> Optional[dict]:
        if target:
            row = self._one("SELECT id FROM scans WHERE status='completed' AND target=? ORDER BY id DESC LIMIT 1", (target,))
        else:
            row = self._one("SELECT id FROM scans WHERE status='completed' ORDER BY id DESC LIMIT 1")
        return self.get_scan(row["id"]) if row else None

    def previous_scan(self, scan_id: int) -> Optional[dict]:
        cur = self.get_scan(scan_id)
        if not cur:
            return None
        row = self._one("SELECT id FROM scans WHERE status='completed' AND target=? AND id<? ORDER BY id DESC LIMIT 1",
                        (cur["target"], scan_id))
        return self.get_scan(row["id"]) if row else None

    # ----------------------------------------------------------- assets --
    def upsert_assets(self, scan_id: int, hosts: list[Host]) -> dict[str, dict]:
        """Record live hosts in the asset inventory. Returns {address: asset row incl. 'is_new'}."""
        out: dict[str, dict] = {}
        ts = now_iso()
        with self.connect() as c:
            for h in hosts:
                if h.status != "up":
                    continue
                row = c.execute("SELECT * FROM assets WHERE address=?", (h.address,)).fetchone()
                if row is None:
                    c.execute("""INSERT INTO assets(address, hostname, mac, vendor, os_name, first_seen, last_seen, first_scan_id, last_scan_id)
                                 VALUES (?,?,?,?,?,?,?,?,?)""", (h.address, h.hostname, h.mac, h.vendor, h.os_name, ts, ts, scan_id, scan_id))
                    is_new = True
                else:
                    c.execute("""UPDATE assets SET hostname=COALESCE(NULLIF(?,''),hostname), mac=COALESCE(NULLIF(?,''),mac),
                                 vendor=COALESCE(NULLIF(?,''),vendor), os_name=COALESCE(NULLIF(?,''),os_name),
                                 last_seen=?, last_scan_id=? WHERE address=?""",
                              (h.hostname, h.mac, h.vendor, h.os_name, ts, scan_id, h.address))
                    is_new = False
                asset = dict(c.execute("SELECT * FROM assets WHERE address=?", (h.address,)).fetchone())
                asset["is_new"] = is_new
                out[h.address] = asset
        return out

    @staticmethod
    def context_for(asset: dict) -> AssetContext:
        exposure = asset.get("exposure") or "auto"
        internet = is_internet_facing(asset["address"]) if exposure == "auto" else exposure == "internet"
        return AssetContext(asset.get("criticality") or "medium", asset.get("business_impact") or "medium", internet)

    def asset_contexts(self, addresses: Iterable[str] | None = None) -> dict[str, AssetContext]:
        rows = self._all("SELECT * FROM assets")
        wanted = set(addresses) if addresses is not None else None
        return {r["address"]: self.context_for(r) for r in rows if wanted is None or r["address"] in wanted}

    def update_asset(self, address: str, **fields) -> None:
        allowed = {"criticality", "business_impact", "exposure", "owner", "tags", "notes", "known"}
        fields = {k: v for k, v in fields.items() if k in allowed}
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        with self.connect() as c:
            c.execute(f"UPDATE assets SET {sets} WHERE address=?", (*fields.values(), address))

    def assets(self) -> list[dict]:
        rows = self._all("""SELECT a.*,
              (SELECT count(*) FROM services v JOIN scan_hosts h ON v.scan_host_id=h.id
                 WHERE h.asset_id=a.id AND v.scan_id=a.last_scan_id) AS open_services
            FROM assets a ORDER BY a.address""")
        open_by_host: dict[str, list[dict]] = {}
        for f in self.current_findings(include_closed=False):
            open_by_host.setdefault(f["host"], []).append(f)
        for r in rows:
            fs = open_by_host.get(r["address"], [])
            r["risk_score"] = asset_risk([f["risk_score"] for f in fs])
            for s in SEVERITIES[:4]:
                r[s.lower()] = sum(1 for f in fs if f["severity"] == s)
            r["open_findings"] = len(fs)
            r["internet_exposed"] = self.context_for(r).internet_exposed
        return rows

    # -------------------------------------------------------- save scan --
    def complete_scan(self, scan_id: int, hosts: list[Host], findings: list[Finding], assets: dict[str, dict], *,
                      duration: float, nmap_args: str, nmap_version: str, privileged: bool, warnings: list[str],
                      tls_info: dict | None = None, web_info: dict | None = None, operator: str = "") -> dict:
        tls_info, web_info = tls_info or {}, web_info or {}
        ts = now_iso()
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in findings:               # de-duplicate within the scan
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique.append(f)
        transitions = {"new": 0, "reopened": 0, "verified": 0}
        with self.connect() as c:
            for h in hosts:
                asset = assets.get(h.address)
                cur = c.execute("""INSERT INTO scan_hosts(scan_id, asset_id, address, hostname, hostnames, status, mac, vendor,
                                   os_name, os_accuracy, is_new, scripts_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                                (scan_id, asset["id"] if asset else None, h.address, h.hostname, ", ".join(h.hostnames), h.status,
                                 h.mac, h.vendor, h.os_name, h.os_accuracy, int(bool(asset and asset["is_new"])), json.dumps(h.scripts)))
                hid = cur.lastrowid
                for s in h.open_services:
                    key = f"{h.address}:{s.port}/{s.protocol}"
                    c.execute("""INSERT INTO services(scan_id, scan_host_id, address, port, protocol, state, service, product, version,
                                 extrainfo, tunnel, cpes, banner, reason, scripts_json, tls_json, web_json)
                                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                              (scan_id, hid, h.address, s.port, s.protocol, s.state, s.service, s.product, s.version, s.extrainfo,
                               s.tunnel, " ".join(s.cpes), s.banner[:2000], s.reason, json.dumps(s.scripts),
                               json.dumps(tls_info.get(key), default=str) if key in tls_info else None,
                               json.dumps(web_info.get(key)) if key in web_info else None))
            for f in unique:
                fp = f.fingerprint
                c.execute("""INSERT INTO findings(scan_id, fingerprint, host, port, protocol, service, check_id, category, title,
                             base_score, risk_score, severity, evidence, impact, recommendation, cve, cvss_version, cvss_vector,
                             cvss3, cvss4, cwe, epss, epss_percentile, kev, exploit_available, owasp, references_json, risk_factors_json)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (scan_id, fp, f.host, f.port, f.protocol, f.service, f.check_id, f.category, f.title, f.base_score,
                           f.risk_score, f.severity, f.evidence, f.impact, f.recommendation, f.cve, f.cvss_version, f.cvss_vector,
                           f.cvss3, f.cvss4, f.cwe, f.epss, f.epss_percentile, int(f.kev), int(f.exploit_available), f.owasp,
                           json.dumps(f.references), json.dumps(f.risk_factors)))
                issue = c.execute("SELECT status FROM issues WHERE fingerprint=?", (fp,)).fetchone()
                if issue is None:
                    c.execute("""INSERT INTO issues(fingerprint, address, port, protocol, check_id, cve, title, status,
                                 first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, status_changed_at)
                                 VALUES (?,?,?,?,?,?,?,'OPEN',?,?,?,?,?)""",
                              (fp, f.host, f.port, f.protocol, f.check_id, f.cve, f.title, scan_id, scan_id, ts, ts, ts))
                    c.execute("INSERT INTO status_history(fingerprint, old_status, new_status, changed_at, changed_by, note) VALUES (?,?,?,?,?,?)",
                              (fp, None, "OPEN", ts, "ensat", f"First detected in scan #{scan_id}"))
                    transitions["new"] += 1
                else:
                    c.execute("UPDATE issues SET last_seen_scan=?, last_seen_at=?, title=? WHERE fingerprint=?", (scan_id, ts, f.title, fp))
                    if issue["status"] in ("REMEDIATED", "VERIFIED"):
                        self._set_status(c, fp, issue["status"], "OPEN", "ensat", f"Re-detected in scan #{scan_id}; reopened", ts)
                        transitions["reopened"] += 1

            # Verification: an issue marked REMEDIATED that this scan could have observed but did not.
            scope = c.execute("SELECT scope_key FROM scans WHERE id=?", (scan_id,)).fetchone()["scope_key"]
            live = {h.address for h in hosts if h.status == "up"}
            open_ports = {(h.address, s.port, s.protocol) for h in hosts for s in h.open_services}
            for row in c.execute("""SELECT i.fingerprint, i.address, i.port, i.protocol, s.scope_key FROM issues i
                                    JOIN scans s ON s.id=i.last_seen_scan WHERE i.status='REMEDIATED'""").fetchall():
                if row["fingerprint"] in seen or row["address"] not in live:
                    continue
                if (row["address"], row["port"], row["protocol"]) in open_ports or row["scope_key"] == scope:
                    self._set_status(c, row["fingerprint"], "REMEDIATED", "VERIFIED", "ensat",
                                     f"Not detected in verification scan #{scan_id}", ts)
                    transitions["verified"] += 1

            c.execute("""UPDATE scans SET status='completed', finished_at=?, duration_seconds=?, nmap_args=?, nmap_version=?,
                         privileged=?, warnings_json=?, hosts_up=? WHERE id=?""",
                      (ts, duration, nmap_args, nmap_version, int(privileged), json.dumps(warnings),
                       sum(1 for h in hosts if h.status == "up"), scan_id))
        return transitions

    # --------------------------------------------------------- findings --
    _FINDING_COLS = "f.*, i.status, i.assignee, i.notes, i.first_seen_at, i.last_seen_at, i.first_seen_scan, i.last_seen_scan"

    @staticmethod
    def _decode(rows: list[dict]) -> list[dict]:
        for r in rows:
            r["references"] = json.loads(r.pop("references_json", None) or "[]")
            r["risk_factors"] = json.loads(r.pop("risk_factors_json", None) or "[]")
            r["kev"] = bool(r.get("kev"))
            r["exploit_available"] = bool(r.get("exploit_available"))
        return rows

    def scan_findings(self, scan_id: int) -> list[dict]:
        return self._decode(self._all(f"""SELECT {self._FINDING_COLS} FROM findings f JOIN issues i ON i.fingerprint=f.fingerprint
                                          WHERE f.scan_id=? ORDER BY f.risk_score DESC, f.host, f.port""", (scan_id,)))

    def current_findings(self, include_closed: bool = True) -> list[dict]:
        """Latest observation of every unique issue (the vulnerability-management view)."""
        rows = self._decode(self._all(f"""SELECT {self._FINDING_COLS} FROM findings f JOIN issues i ON i.fingerprint=f.fingerprint
                     WHERE f.id = (SELECT max(id) FROM findings WHERE fingerprint=f.fingerprint)
                     ORDER BY f.risk_score DESC, f.host, f.port"""))
        if not include_closed:
            rows = [r for r in rows if r["status"] not in CLOSED_STATUSES]
        return rows

    def finding_history(self, fingerprint: str) -> list[dict]:
        return self._all("SELECT * FROM status_history WHERE fingerprint=? ORDER BY id", (fingerprint,))

    @staticmethod
    def _set_status(c, fp, old, new, by, note, ts=None):
        ts = ts or now_iso()
        c.execute("UPDATE issues SET status=?, status_changed_at=? WHERE fingerprint=?", (new, ts, fp))
        c.execute("INSERT INTO status_history(fingerprint, old_status, new_status, changed_at, changed_by, note) VALUES (?,?,?,?,?,?)",
                  (fp, old, new, ts, by, note))

    def update_status(self, fingerprints: Iterable[str], status: str, by: str = "", note: str = "") -> int:
        status = status.upper()
        if status not in STATUSES:
            raise ValueError(f"Unknown status '{status}'. Choose from: {', '.join(STATUSES)}")
        n = 0
        with self.connect() as c:
            for fp in fingerprints:
                row = c.execute("SELECT status FROM issues WHERE fingerprint=?", (fp,)).fetchone()
                if row and row["status"] != status:
                    self._set_status(c, fp, row["status"], status, by, note)
                    n += 1
        return n

    def update_issue(self, fingerprint: str, assignee: str | None = None, notes: str | None = None) -> None:
        with self.connect() as c:
            if assignee is not None:
                c.execute("UPDATE issues SET assignee=? WHERE fingerprint=?", (assignee, fingerprint))
            if notes is not None:
                c.execute("UPDATE issues SET notes=? WHERE fingerprint=?", (notes, fingerprint))

    def resolve_fingerprint(self, ref: str) -> Optional[str]:
        """Accept a fingerprint, a fingerprint prefix, or a numeric finding id."""
        if ref.isdigit():
            row = self._one("SELECT fingerprint FROM findings WHERE id=?", (int(ref),))
            return row["fingerprint"] if row else None
        rows = self._all("SELECT fingerprint FROM issues WHERE fingerprint LIKE ?", (ref + "%",))
        return rows[0]["fingerprint"] if len(rows) == 1 else None

    def rescore_open(self) -> int:
        """Re-apply the risk engine to open findings after asset context (criticality, exposure...) changes."""
        from .risk import score_finding
        contexts = self.asset_contexts()
        keep = set(Finding.__dataclass_fields__) - {"risk_score", "severity", "risk_factors"}
        updated = 0
        with self.connect() as c:
            for r in self.current_findings(include_closed=False):
                f = Finding(**{k: r[k] for k in keep if k in r})
                score_finding(f, contexts.get(f.host) or AssetContext(internet_exposed=is_internet_facing(f.host)))
                if f.risk_score != r["risk_score"] or f.severity != r["severity"]:
                    c.execute("UPDATE findings SET risk_score=?, severity=?, risk_factors_json=? WHERE id=?",
                              (f.risk_score, f.severity, json.dumps(f.risk_factors), r["id"]))
                    updated += 1
        return updated

    # ---------------------------------------------------------- services --
    def scan_services(self, scan_id: int) -> list[dict]:
        rows = self._all("""SELECT v.*, h.hostname, h.os_name FROM services v JOIN scan_hosts h ON h.id=v.scan_host_id
                            WHERE v.scan_id=? ORDER BY v.address, v.protocol, v.port""", (scan_id,))
        for r in rows:
            r["tls"] = json.loads(r.pop("tls_json") or "null")
            r["web"] = json.loads(r.pop("web_json") or "null")
            r["scripts"] = json.loads(r.pop("scripts_json") or "{}")
        return rows

    def scan_hosts(self, scan_id: int) -> list[dict]:
        return self._all("SELECT * FROM scan_hosts WHERE scan_id=? ORDER BY id", (scan_id,))

    def service_inventory(self) -> list[dict]:
        """Services as last seen on each asset."""
        rows = self._all("""SELECT v.*, h.hostname FROM services v JOIN scan_hosts h ON h.id=v.scan_host_id
                            JOIN assets a ON a.id=h.asset_id WHERE v.scan_id=a.last_scan_id ORDER BY v.address, v.port""")
        for r in rows:
            r["tls"] = json.loads(r.pop("tls_json") or "null")
            r["web"] = json.loads(r.pop("web_json") or "null")
            r.pop("scripts_json", None)
        return rows

    # ------------------------------------------------------------ stats --
    def severity_counts(self, scan_id: int) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for r in self._all("SELECT severity, count(*) AS n FROM findings WHERE scan_id=? GROUP BY severity", (scan_id,)):
            counts[r["severity"]] = r["n"]
        return counts

    def status_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in STATUSES}
        for r in self._all("SELECT status, count(*) AS n FROM issues GROUP BY status"):
            counts[r["status"]] = r["n"]
        return counts
