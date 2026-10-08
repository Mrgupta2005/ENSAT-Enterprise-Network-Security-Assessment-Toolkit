"""Nmap integration.

ENSAT builds a fixed, validated argument list (never a shell string) and
streams Nmap's XML from stdout so it can report live progress. Only NSE
scripts from Nmap's ``safe`` category are used; nothing intrusive or
exploit-oriented is ever run.
"""
from __future__ import annotations

import logging
import os
import queue
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import ScanOptions
from .validation import parse_targets, validate_ports

log = logging.getLogger("ensat.scanner")

ProgressFn = Callable[[str, float], None]

# All of these are in Nmap's "safe" script category.
SAFE_SCRIPTS_STANDARD = [
    "banner", "http-title", "http-server-header", "ssl-cert", "ftp-anon",
    "smb2-security-mode", "smb-protocols", "dns-recursion", "redis-info",
]
SAFE_SCRIPTS_FULL = SAFE_SCRIPTS_STANDARD + ["ssl-enum-ciphers", "ssh2-enum-algos", "mongodb-info"]
UDP_PORTS = "53,67,69,123,137,161,500,623,1900,5353"

PROFILES = {
    "quick":    {"ports": ["--top-ports", "100"], "timing": "-T4", "version": ["--version-light"], "scripts": []},
    "standard": {"ports": ["--top-ports", "1000"], "timing": "-T4", "version": [], "scripts": SAFE_SCRIPTS_STANDARD},
    "full":     {"ports": ["-p-"], "timing": "-T4", "version": ["--version-all"], "scripts": SAFE_SCRIPTS_FULL},
}

PROGRESS_RE = re.compile(r'<taskprogress task="([^"]+)"[^>]*percent="([\d.]+)"')


class NmapError(RuntimeError):
    pass


@dataclass
class ScanRun:
    xml_documents: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    privileged: bool = False
    nmap_version: str = ""


def ensure_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapError("Nmap was not found on PATH. Install it from https://nmap.org/download.html and reopen your terminal.")
    return path


def nmap_version() -> str:
    try:
        out = subprocess.run([ensure_nmap(), "--version"], capture_output=True, text=True, timeout=15).stdout
        m = re.search(r"Nmap version ([\w.]+)", out)
        return m.group(1) if m else ""
    except (NmapError, OSError, subprocess.SubprocessError):
        return ""


def is_privileged() -> bool:
    """Raw-socket features (SYN scan, OS detection, UDP, MAC addresses) need root/Administrator."""
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def build_commands(opts: ScanOptions, privileged: bool) -> tuple[list[list[str]], list[str]]:
    """Return the Nmap argument lists for these options plus any capability warnings."""
    nmap = ensure_nmap()
    targets = parse_targets(opts.target)
    ports = validate_ports(opts.ports)
    profile = PROFILES.get(opts.profile, PROFILES["standard"])
    warnings: list[str] = []

    skip_discovery = opts.skip_discovery
    if skip_discovery is None:
        skip_discovery = all(t.is_single_host for t in targets)

    base = [nmap, "-oX", "-", "--stats-every", "3s", "--reason", profile["timing"]]
    if skip_discovery:
        base.append("-Pn")

    tcp = list(base)
    tcp.append("-sS" if privileged else "-sT")
    tcp += ["-p", ports] if ports else profile["ports"]
    if opts.service_detection:
        tcp += ["-sV", *profile["version"]]
    if opts.nse_scripts and profile["scripts"]:
        tcp += ["--script", ",".join(profile["scripts"])]
    if opts.os_detection:
        if privileged:
            tcp += ["-O", "--osscan-limit"]
        else:
            warnings.append("OS detection needs root/Administrator; skipped. Re-run ENSAT from an elevated terminal to enable it.")
    if not privileged:
        warnings.append("Running unprivileged: using TCP connect scan; MAC/vendor data is only available with root/Administrator.")
    tcp += [t.raw for t in targets]
    commands = [tcp]

    if opts.udp:
        if privileged:
            udp = list(base) + ["-sU", "-p", UDP_PORTS]
            if opts.service_detection:
                udp += ["-sV", "--version-light"]
            udp += [t.raw for t in targets]
            commands.append(udp)
        else:
            warnings.append("UDP scanning needs root/Administrator; skipped.")
    return commands, warnings


def _run_one(cmd: list[str], timeout: int, progress: Optional[ProgressFn], label: str, start: float, span: float) -> str:
    log.info("Running: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace", bufsize=1)
    lines: queue.Queue[Optional[str]] = queue.Queue()
    err_chunks: list[str] = []

    def pump_out():
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    def pump_err():
        err_chunks.append(proc.stderr.read())

    threading.Thread(target=pump_out, daemon=True).start()
    t_err = threading.Thread(target=pump_err, daemon=True)
    t_err.start()

    deadline = time.monotonic() + timeout
    out: list[str] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            proc.wait()
            raise NmapError(f"Nmap timed out after {timeout}s. Narrow the scope or raise the timeout.")
        try:
            line = lines.get(timeout=min(remaining, 0.5))
        except queue.Empty:
            continue
        if line is None:
            break
        out.append(line)
        if progress:
            m = PROGRESS_RE.search(line)
            if m:
                pct = float(m.group(2)) / 100.0
                progress(f"{label}: {m.group(1)} {m.group(2)}%", start + span * pct)
    proc.wait()
    t_err.join(timeout=5)
    stderr = "".join(err_chunks).strip()
    xml = "".join(out)
    if proc.returncode != 0 or "<nmaprun" not in xml:
        raise NmapError(stderr or f"Nmap exited with code {proc.returncode}")
    if stderr:
        log.warning("nmap stderr: %s", stderr)
    return xml


def run_scan(opts: ScanOptions, progress: Optional[ProgressFn] = None) -> ScanRun:
    privileged = is_privileged()
    commands, warnings = build_commands(opts, privileged)
    run = ScanRun(commands=[" ".join(c[1:]) for c in commands], warnings=warnings, privileged=privileged, nmap_version=nmap_version())
    span = 1.0 / len(commands)
    for i, cmd in enumerate(commands):
        label = "UDP scan" if "-sU" in cmd else "TCP scan"
        if progress:
            progress(f"{label}: starting", i * span)
        run.xml_documents.append(_run_one(cmd, opts.timeout, progress, label, i * span, span))
    return run
