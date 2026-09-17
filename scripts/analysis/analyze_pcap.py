#!/usr/bin/env python3
"""
=============================================================================
ICMP Smurf Attack — Packet Capture Analysis
=============================================================================
Parses .pcap files captured during the experiment and produces:
  - Packet count tables (sent vs. received, per scenario)
  - Unique source IP enumeration
  - Amplification factor: observed vs. theoretical N
  - Timing analysis: inter-arrival times, burst detection
  - Defense comparison: before/after metrics

Designed for use with captures from the isolated Docker lab.

Usage:
    python3 analyze_pcap.py /captures/attack_*.pcap
    python3 analyze_pcap.py --compare /captures/baseline.pcap /captures/attack.pcap
    python3 analyze_pcap.py /captures/attack.pcap --expected-hosts 6
=============================================================================
"""

import argparse
import os
import sys
from collections import defaultdict, Counter
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, ICMP
except ImportError:
    print("ERROR: Scapy is not installed. Run: pip install scapy")
    sys.exit(1)


def analyze_pcap(filepath, expected_hosts=6):
    """Analyze a single .pcap file and return metrics."""

    if not os.path.exists(filepath):
        print(f"  ERROR: File not found: {filepath}")
        return None

    print(f"\n{'=' * 70}")
    print(f"  ANALYZING: {os.path.basename(filepath)}")
    print(f"{'=' * 70}")

    # An empty or header-only pcap is a valid result (e.g. a defense that
    # blocked all reflected traffic, so nothing reached the victim). rdpcap
    # raises "No data could be read!" on such files, so treat that as 0 packets
    # rather than crashing the whole analysis run.
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"  (no packets captured — empty capture: {e})")
        packets = []

    # ── Classify packets ──
    echo_requests = []    # Type 8
    echo_replies = []     # Type 0
    other_icmp = []

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp_type = pkt[ICMP].type
            if icmp_type == 8:
                echo_requests.append(pkt)
            elif icmp_type == 0:
                echo_replies.append(pkt)
            else:
                other_icmp.append(pkt)

    # ── Source and destination analysis ──
    reply_sources = Counter()
    reply_dests = Counter()
    request_sources = Counter()
    request_dests = Counter()

    for pkt in echo_replies:
        reply_sources[pkt[IP].src] += 1
        reply_dests[pkt[IP].dst] += 1

    for pkt in echo_requests:
        request_sources[pkt[IP].src] += 1
        request_dests[pkt[IP].dst] += 1

    # ── Timing analysis ──
    timestamps = []
    for pkt in echo_replies:
        timestamps.append(float(pkt.time))

    inter_arrival = []
    if len(timestamps) > 1:
        timestamps.sort()
        for i in range(1, len(timestamps)):
            inter_arrival.append(timestamps[i] - timestamps[i - 1])

    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0

    # ── Amplification factor ──
    num_requests = len(echo_requests)
    num_replies = len(echo_replies)
    unique_reply_sources = len(reply_sources)

    if num_requests > 0:
        observed_amplification = num_replies / num_requests
    else:
        observed_amplification = float('inf') if num_replies > 0 else 0

    theoretical_amplification = expected_hosts

    # ── Print results ──
    print(f"\n  --- Packet Counts ---")
    print(f"  Total packets       : {len(packets)}")
    print(f"  Echo Requests (T=8) : {num_requests}")
    print(f"  Echo Replies  (T=0) : {num_replies}")
    print(f"  Other ICMP          : {len(other_icmp)}")

    print(f"\n  --- Echo Request Sources ---")
    for src, count in request_sources.most_common():
        print(f"    {src:>18s} : {count} packets")

    print(f"\n  --- Echo Request Destinations ---")
    for dst, count in request_dests.most_common():
        broadcast = " ← BROADCAST" if dst.endswith(".255") or dst.endswith(".0") else ""
        print(f"    {dst:>18s} : {count} packets{broadcast}")

    print(f"\n  --- Echo Reply Sources (Amplifier Hosts) ---")
    for src, count in reply_sources.most_common():
        print(f"    {src:>18s} : {count} replies")
    print(f"    {'TOTAL':>18s} : {num_replies} replies from {unique_reply_sources} unique sources")

    print(f"\n  --- Echo Reply Destinations (Victims) ---")
    for dst, count in reply_dests.most_common():
        print(f"    {dst:>18s} : {count} replies received")

    print(f"\n  --- Amplification Analysis ---")
    print(f"  Requests sent              : {num_requests}")
    print(f"  Replies received           : {num_replies}")
    print(f"  Unique amplifier sources   : {unique_reply_sources}")
    print(f"  Observed amplification     : {observed_amplification:.1f}x")
    print(f"  Theoretical amplification  : {theoretical_amplification}x (N={expected_hosts})")
    if observed_amplification != float('inf') and theoretical_amplification > 0:
        efficiency = (observed_amplification / theoretical_amplification) * 100
        print(f"  Amplification efficiency   : {efficiency:.1f}%")

    print(f"\n  --- Timing ---")
    print(f"  Capture duration           : {duration:.3f}s")
    if inter_arrival:
        avg_iat = sum(inter_arrival) / len(inter_arrival)
        min_iat = min(inter_arrival)
        max_iat = max(inter_arrival)
        print(f"  Reply inter-arrival (avg)  : {avg_iat * 1000:.2f}ms")
        print(f"  Reply inter-arrival (min)  : {min_iat * 1000:.2f}ms")
        print(f"  Reply inter-arrival (max)  : {max_iat * 1000:.2f}ms")
        if duration > 0:
            print(f"  Reply rate                 : {num_replies / duration:.1f} pkt/s")

    print(f"\n{'=' * 70}")

    return {
        "file": filepath,
        "total_packets": len(packets),
        "echo_requests": num_requests,
        "echo_replies": num_replies,
        "unique_reply_sources": unique_reply_sources,
        "reply_sources": dict(reply_sources),
        "observed_amplification": observed_amplification,
        "theoretical_amplification": theoretical_amplification,
        "duration": duration,
        "inter_arrival_avg": sum(inter_arrival) / len(inter_arrival) if inter_arrival else 0,
    }


def compare_captures(results_list):
    """Print a comparison table across multiple captures."""
    if len(results_list) < 2:
        return

    print(f"\n{'=' * 70}")
    print(f"  COMPARISON TABLE")
    print(f"{'=' * 70}")

    # Header
    header = f"  {'Metric':<30s}"
    for r in results_list:
        label = os.path.basename(r["file"])[:15]
        header += f" | {label:>15s}"
    print(header)
    print(f"  {'-' * 30}" + ("-+-" + "-" * 15) * len(results_list))

    # Rows
    metrics = [
        ("Echo Requests", "echo_requests"),
        ("Echo Replies", "echo_replies"),
        ("Unique Sources", "unique_reply_sources"),
        ("Amplification (obs.)", "observed_amplification"),
        ("Duration (s)", "duration"),
    ]

    for label, key in metrics:
        row = f"  {label:<30s}"
        for r in results_list:
            val = r[key]
            if isinstance(val, float):
                if val == float('inf'):
                    row += f" | {'∞':>15s}"
                else:
                    row += f" | {val:>15.1f}"
            else:
                row += f" | {val:>15d}"
        print(row)

    print(f"{'=' * 70}")


def main():
    parser = argparse.ArgumentParser(
        description="ICMP Smurf Attack — Packet Capture Analyzer"
    )
    parser.add_argument(
        "pcap_files", nargs="+",
        help="One or more .pcap files to analyze"
    )
    parser.add_argument(
        "--expected-hosts", "-n", type=int, default=6,
        help="Expected number of amplifier hosts for theoretical calculation (default: 6)"
    )
    parser.add_argument(
        "--compare", "-c", action="store_true",
        help="Print comparison table across all provided captures"
    )

    args = parser.parse_args()

    results = []
    for f in args.pcap_files:
        result = analyze_pcap(f, expected_hosts=args.expected_hosts)
        if result:
            results.append(result)

    if args.compare and len(results) >= 2:
        compare_captures(results)


if __name__ == "__main__":
    main()
