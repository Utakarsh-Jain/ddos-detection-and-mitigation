"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           DDoS AI AGENT — MITIGATION HANDLER MODULE                         ║
║  SRM Institute of Science and Technology | Dept. Networking & Communications ║
║  Students : Utkarsh Jaiswal  (RA2311030010011)                               ║
║             Utakarsh Jain    (RA2311030010054)                               ║
║  Guide    : Dr. Karthikeyan H, Assistant Professor                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Module  : mitigation_handler.py
Purpose : Real-time automated mitigation — block malicious IPs / ports when
          the detection model triggers an alert.

Supported Actions
─────────────────
  1. BLOCK_IP      — Add source IP to in-memory blocklist + iptables rule
  2. RATE_LIMIT_IP — Apply tc/iptables rate-limit on burst traffic
  3. PORT_BLOCK    — Block a specific destination port for an IP
  4. LOG_ALERT     — Log the event with full metadata (always executed)

NOTE: iptables commands require root privileges.
      In simulation / test mode (DRY_RUN=True) they are only printed.
"""

import os
import time
import logging
import subprocess
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/mitigation.log"),
    ],
)
log = logging.getLogger("MitigationHandler")


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

DRY_RUN         = True    # Set False on a real Linux host with root
BLOCK_DURATION  = 300     # seconds an IP stays blocked (5 minutes)
MAX_BLOCKED_IPS = 10_000  # memory cap on blocklist
ALERT_THRESHOLD = 3       # consecutive detections before hard block
RATE_LIMIT_KBPS = 512     # kb/s rate-limit before full block


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatRecord:
    ip          : str
    port        : Optional[int]
    confidence  : float
    action      : str
    timestamp   : datetime = field(default_factory=datetime.utcnow)
    expires_at  : Optional[datetime] = None
    unblocked   : bool = False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class MitigationHandler:
    """
    Thread-safe mitigation engine.

    Usage
    ─────
        handler = MitigationHandler()
        handler.handle_alert(src_ip="192.168.1.100",
                             dst_port=80,
                             confidence=0.97,
                             model_name="XGBoost")
    """

    def __init__(self, dry_run: bool = DRY_RUN):
        self.dry_run       = dry_run
        self._lock         = threading.Lock()

        # { ip: ThreatRecord }
        self._blocked_ips  : dict[str, ThreatRecord] = {}

        # { ip: deque of detection timestamps } — for consecutive-hit tracking
        self._alert_history: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=ALERT_THRESHOLD)
        )

        # statistics
        self._stats = {
            "total_alerts"   : 0,
            "ips_blocked"    : 0,
            "ips_unblocked"  : 0,
            "ports_blocked"  : 0,
        }

        # start background cleanup thread
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()
        log.info(f"MitigationHandler initialised  [DRY_RUN={dry_run}]")

    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────

    def handle_alert(self,
                     src_ip     : str,
                     dst_port   : Optional[int] = None,
                     confidence : float = 1.0,
                     model_name : str = "Unknown"):
        """
        Entry point called by agent_core.py on every positive detection.

        Decision tree
        ─────────────
          confidence ≥ 0.95  →  immediate hard block
          confidence ≥ 0.80  →  rate-limit; hard block after ALERT_THRESHOLD hits
          confidence ≥ 0.60  →  log only
        """
        with self._lock:
            self._stats["total_alerts"] += 1
            self._log_alert(src_ip, dst_port, confidence, model_name)

            # ── Already hard-blocked? Refresh expiry ─────────────────────
            if src_ip in self._blocked_ips and not self._blocked_ips[src_ip].unblocked:
                record = self._blocked_ips[src_ip]
                record.expires_at = datetime.utcnow() + timedelta(seconds=BLOCK_DURATION)
                log.info(f"[RENEW]  {src_ip} — block timer refreshed.")
                return

            # ── Track alert history ───────────────────────────────────────
            self._alert_history[src_ip].append(datetime.utcnow())
            consecutive_hits = len(self._alert_history[src_ip])

            # ── Mitigation decision ───────────────────────────────────────
            if confidence >= 0.95 or consecutive_hits >= ALERT_THRESHOLD:
                self._block_ip(src_ip, dst_port, confidence)
                if dst_port:
                    self._block_port(src_ip, dst_port)

            elif confidence >= 0.80:
                self._rate_limit_ip(src_ip, confidence)

            else:
                log.info(f"[LOG-ONLY] {src_ip}  conf={confidence:.2f} — monitoring.")

    def unblock_ip(self, ip: str):
        """Manually unblock an IP before its timer expires."""
        with self._lock:
            self._unblock_ip(ip)

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def get_blocklist(self) -> list[str]:
        with self._lock:
            return [ip for ip, r in self._blocked_ips.items() if not r.unblocked]

    # ─────────────────────────────────────────────────────────────────────────
    # INTERNAL ACTIONS
    # ─────────────────────────────────────────────────────────────────────────

    def _block_ip(self, ip: str, port: Optional[int], confidence: float):
        cmd = f"iptables -I INPUT -s {ip} -j DROP"
        self._run_cmd(cmd, label=f"BLOCK_IP  {ip}")

        record = ThreatRecord(
            ip         = ip,
            port       = port,
            confidence = confidence,
            action     = "BLOCK_IP",
            expires_at = datetime.utcnow() + timedelta(seconds=BLOCK_DURATION),
        )
        self._blocked_ips[ip] = record
        self._stats["ips_blocked"] += 1
        log.warning(f"[BLOCKED]  {ip}  conf={confidence:.2f}  "
                    f"expires_in={BLOCK_DURATION}s")

    def _rate_limit_ip(self, ip: str, confidence: float):
        """
        Use iptables hashlimit to cap bandwidth from a suspicious IP.
        Falls back to a log entry in dry-run mode.
        """
        cmd = (f"iptables -I INPUT -s {ip} -m hashlimit "
               f"--hashlimit-above {RATE_LIMIT_KBPS}kb/s "
               f"--hashlimit-mode srcip --hashlimit-name ddos_limit "
               f"-j DROP")
        self._run_cmd(cmd, label=f"RATE_LIMIT {ip}")
        log.warning(f"[RATE-LIMIT]  {ip}  conf={confidence:.2f}  "
                    f"limit={RATE_LIMIT_KBPS}kbps")

    def _block_port(self, ip: str, port: int):
        cmd = f"iptables -I INPUT -s {ip} --dport {port} -j DROP"
        self._run_cmd(cmd, label=f"BLOCK_PORT {ip}:{port}")
        self._stats["ports_blocked"] += 1
        log.warning(f"[PORT-BLOCK]  {ip}:{port}")

    def _unblock_ip(self, ip: str):
        if ip not in self._blocked_ips:
            return
        cmd = f"iptables -D INPUT -s {ip} -j DROP"
        self._run_cmd(cmd, label=f"UNBLOCK_IP {ip}")
        self._blocked_ips[ip].unblocked = True
        self._stats["ips_unblocked"] += 1
        log.info(f"[UNBLOCKED]  {ip}")

    def _log_alert(self, ip: str, port: Optional[int],
                   confidence: float, model: str):
        entry = (f"[ALERT]  src={ip}  dst_port={port}  "
                 f"confidence={confidence:.4f}  model={model}  "
                 f"time={datetime.utcnow().isoformat()}")
        log.info(entry)

        # Append to CSV-style alert log for later analysis
        with open("logs/alerts.csv", "a") as f:
            f.write(f"{datetime.utcnow().isoformat()},{ip},{port},"
                    f"{confidence:.4f},{model}\n")

    # ─────────────────────────────────────────────────────────────────────────
    # SYSTEM COMMAND RUNNER
    # ─────────────────────────────────────────────────────────────────────────

    def _run_cmd(self, cmd: str, label: str):
        if self.dry_run:
            log.info(f"[DRY-RUN] Would execute: {cmd}")
            return
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                log.error(f"[CMD FAILED] {label}: {result.stderr.strip()}")
            else:
                log.info(f"[CMD OK] {label}")
        except Exception as e:
            log.error(f"[CMD ERROR] {label}: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # CLEANUP THREAD — auto-unblocks expired IPs every 60 seconds
    # ─────────────────────────────────────────────────────────────────────────

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            now = datetime.utcnow()
            with self._lock:
                expired = [
                    ip for ip, r in self._blocked_ips.items()
                    if r.expires_at and now >= r.expires_at and not r.unblocked
                ]
                for ip in expired:
                    log.info(f"[EXPIRE]  Auto-unblocking {ip}")
                    self._unblock_ip(ip)


# ─────────────────────────────────────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    handler = MitigationHandler(dry_run=True)

    print("\n-- Simulating alert stream --")
    handler.handle_alert("10.0.0.1",  dst_port=80,   confidence=0.55, model_name="XGBoost")
    handler.handle_alert("10.0.0.2",  dst_port=443,  confidence=0.82, model_name="RandomForest")
    handler.handle_alert("10.0.0.3",  dst_port=8080, confidence=0.97, model_name="XGBoost")
    # Trigger consecutive-hit block
    for _ in range(ALERT_THRESHOLD):
        handler.handle_alert("10.0.0.4", dst_port=22, confidence=0.81, model_name="XGBoost")

    print("\n-- Current blocklist --")
    print(handler.get_blocklist())
    print("\n-- Stats --")
    print(handler.get_stats())
