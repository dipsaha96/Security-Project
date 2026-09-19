#!/usr/bin/env python3
"""
ICMP Smurf Attack — Real-Time Detection & Monitoring System

Monitors for:
  1. Unusual volume of ICMP Echo Replies without matching Echo Requests
  2. Many source IPs converging on one destination (destination concentration)
  3. Sudden ICMP traffic spikes above baseline thresholds

Runs on the victim host and provides real-time alerting.

Usage:
    python3 monitor.py                          # default thresholds
    python3 monitor.py --threshold 10 --window 5
    python3 monitor.py --interface eth0 --log /captures/alerts.log
"""

import argparse
import sys
import time
import signal
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, ICMP, conf
except ImportError:
    print("ERROR: Scapy is not installed. Run: pip install scapy")
    sys.exit(1)


# ── ANSI colors for console alerts ─────────────────────────────────────────
class Colors:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


class SmurfDetector:
    """
    Real-time ICMP traffic analyzer for Smurf attack detection.

    Detection strategy
    - Track inbound Echo Replies vs outbound Echo Requests
    - Alert if reply count >> request count (unsolicited replies)
    - Alert if many unique source IPs send replies to us
    - Alert if ICMP rate exceeds threshold within time window
    """

    def __init__(self, threshold_replies, threshold_sources, window_seconds,
                 log_file=None):
        self.threshold_replies = threshold_replies     # max replies/window
        self.threshold_sources = threshold_sources     # max unique sources/window
        self.window_seconds = window_seconds

        # Sliding window data
        self.reply_timestamps = deque()                # timestamps of Echo Replies
        self.request_timestamps = deque()              # timestamps of Echo Requests (sent by us)
        self.reply_sources = defaultdict(int)           # source IP → count in window
        self.reply_source_times = deque()              # (timestamp, src_ip)

        # Counters
        self.total_replies = 0
        self.total_requests = 0
        self.total_alerts = 0

        # Logging
        self.log_file = None
        if log_file:
            self.log_file = open(log_file, "a")

        # State
        self.attack_detected = False
        self.start_time = datetime.now()

    def _prune_window(self, now):
        """Remove entries older than the sliding window."""
        cutoff = now - self.window_seconds

        while self.reply_timestamps and self.reply_timestamps[0] < cutoff:
            self.reply_timestamps.popleft()

        while self.request_timestamps and self.request_timestamps[0] < cutoff:
            self.request_timestamps.popleft()

        while self.reply_source_times and self.reply_source_times[0][0] < cutoff:
            ts, src = self.reply_source_times.popleft()
            self.reply_sources[src] -= 1
            if self.reply_sources[src] <= 0:
                del self.reply_sources[src]

    def _log(self, msg):
        """Write to log file if configured."""
        if self.log_file:
            self.log_file.write(f"{datetime.now().isoformat()} {msg}\n")
            self.log_file.flush()

    def _alert(self, level, msg):
        """Print a color-coded alert to console."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if level == "CRITICAL":
            prefix = f"{Colors.RED}{Colors.BOLD}🚨 CRITICAL"
        elif level == "WARNING":
            prefix = f"{Colors.YELLOW}{Colors.BOLD}⚠️  WARNING"
        else:
            prefix = f"{Colors.CYAN}ℹ️  INFO"

        full_msg = f"  {prefix}{Colors.RESET} [{ts}] {msg}"
        print(full_msg)
        self._log(f"[{level}] {msg}")
        self.total_alerts += 1

    def process_packet(self, pkt):
        """Analyze each captured ICMP packet."""
        if not pkt.haslayer(ICMP) or not pkt.haslayer(IP):
            return

        now = time.time()
        self._prune_window(now)

        icmp_type = pkt[ICMP].type
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # ── Echo Request (Type 8) — sent by us ──
        if icmp_type == 8:
            self.request_timestamps.append(now)
            self.total_requests += 1

        # ── Echo Reply (Type 0) — received by us ──
        elif icmp_type == 0:
            self.reply_timestamps.append(now)
            self.reply_source_times.append((now, src_ip))
            self.reply_sources[src_ip] += 1
            self.total_replies += 1

            replies_in_window = len(self.reply_timestamps)
            requests_in_window = len(self.request_timestamps)
            unique_sources = len(self.reply_sources)

            # ── Detection Rule 1: Unsolicited replies ──
            # Many replies without corresponding requests
            if replies_in_window > self.threshold_replies and requests_in_window == 0:
                self._alert(
                    "CRITICAL",
                    f"SMURF DETECTED — {replies_in_window} unsolicited Echo Replies "
                    f"from {unique_sources} sources in {self.window_seconds}s window "
                    f"(0 outbound requests)"
                )
                self.attack_detected = True

            # ── Detection Rule 2: Excessive reply rate ──
            elif replies_in_window > self.threshold_replies:
                ratio = replies_in_window / max(requests_in_window, 1)
                self._alert(
                    "WARNING",
                    f"High ICMP reply rate — {replies_in_window} replies vs "
                    f"{requests_in_window} requests (ratio: {ratio:.1f}x) "
                    f"in {self.window_seconds}s window"
                )

            # ── Detection Rule 3: Many unique sources (destination concentration) ──
            if unique_sources >= self.threshold_sources:
                sources_list = ", ".join(sorted(self.reply_sources.keys())[:10])
                self._alert(
                    "CRITICAL",
                    f"REFLECTION PATTERN — {unique_sources} unique sources sending "
                    f"Echo Replies: [{sources_list}]"
                )
                self.attack_detected = True

            # ── Normal log line ──
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            status = f"{Colors.RED}▲ ATTACK{Colors.RESET}" if self.attack_detected else f"{Colors.GREEN}● NORMAL{Colors.RESET}"
            print(
                f"  {status} [{ts}] "
                f"Echo Reply from {src_ip:>15s} → {dst_ip:<15s}  "
                f"[window: {replies_in_window} replies, "
                f"{unique_sources} sources]"
            )

    def print_summary(self):
        """Print final monitoring summary."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print()
        print("=" * 70)
        print("  MONITORING SUMMARY")
        print("=" * 70)
        print(f"  Duration          : {elapsed:.1f}s")
        print(f"  Echo Requests (out): {self.total_requests}")
        print(f"  Echo Replies  (in) : {self.total_replies}")
        print(f"  Alerts triggered   : {self.total_alerts}")
        if self.total_requests > 0:
            print(f"  Amplification ratio: {self.total_replies / self.total_requests:.1f}x")
        elif self.total_replies > 0:
            print(f"  Amplification ratio: ∞ (no outbound requests!)")
        print(f"  Attack detected    : {'YES ⚠️' if self.attack_detected else 'NO ✓'}")
        print("=" * 70)

        if self.log_file:
            self.log_file.close()


def main():
    parser = argparse.ArgumentParser(
        description="ICMP Smurf Attack Detection & Monitoring System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--interface", "-i", default="any",
        help="Network interface to monitor (default: any)"
    )
    parser.add_argument(
        "--threshold", "-t", type=int, default=10,
        help="Alert if more than N Echo Replies in the time window (default: 10)"
    )
    parser.add_argument(
        "--sources-threshold", "-s", type=int, default=3,
        help="Alert if replies come from N+ unique sources (default: 3)"
    )
    parser.add_argument(
        "--window", "-w", type=int, default=5,
        help="Sliding time window in seconds (default: 5)"
    )
    parser.add_argument(
        "--log", "-l", default=None,
        help="Path to write alert log file"
    )
    parser.add_argument(
        "--duration", "-d", type=int, default=0,
        help="Monitor for N seconds (0 = indefinite, default: 0)"
    )

    args = parser.parse_args()

    detector = SmurfDetector(
        threshold_replies=args.threshold,
        threshold_sources=args.sources_threshold,
        window_seconds=args.window,
        log_file=args.log
    )

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        detector.print_summary()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    print("=" * 70)
    print("  ICMP SMURF ATTACK — DETECTION MONITOR")
    print("=" * 70)
    print(f"  Interface       : {args.interface}")
    print(f"  Reply threshold : {args.threshold} replies / {args.window}s")
    print(f"  Source threshold : {args.sources_threshold} unique sources")
    print(f"  Duration        : {'indefinite' if args.duration == 0 else f'{args.duration}s'}")
    print(f"  Log file        : {args.log or 'none'}")
    print("=" * 70)
    print()
    print("  Listening for ICMP traffic...")
    print()

    # Start sniffing
    sniff_kwargs = {
        "iface": args.interface if args.interface != "any" else None,
        "filter": "icmp",
        "prn": detector.process_packet,
        "store": False,
    }

    if args.duration > 0:
        sniff_kwargs["timeout"] = args.duration

    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        print("ERROR: Permission denied. Run with sudo or as root.")
        sys.exit(1)

    detector.print_summary()


if __name__ == "__main__":
    main()
