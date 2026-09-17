#!/usr/bin/env python3
"""
=============================================================================
ICMP Smurf Attack — Visualization / Plotting Tool
=============================================================================
Generates charts from .pcap capture files:

  1. Reply Timeline  — packet arrivals over time at the victim
  2. Source Bar Chart — replies per amplifier host
  3. Amplification    — observed vs. theoretical amplification factor
  4. Defense Compare  — before/after defense bar chart

Saves output as PNG files to /results/.

Usage:
    python3 plot_results.py /captures/attack.pcap
    python3 plot_results.py /captures/baseline.pcap /captures/attack.pcap \
                            /captures/defense_broadcast.pcap --compare
=============================================================================
"""

import argparse
import os
import sys
from collections import Counter

try:
    from scapy.all import rdpcap, IP, ICMP
except ImportError:
    print("ERROR: Scapy required. Run: pip install scapy")
    sys.exit(1)

try:
    import matplotlib
    matplotlib.use("Agg")   # non-interactive backend for containers
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    print("ERROR: matplotlib required. Run: pip install matplotlib")
    sys.exit(1)


# ── Style ──────────────────────────────────────────────────────────────────
COLORS = {
    "request":  "#2196F3",   # blue
    "reply":    "#F44336",   # red
    "defense":  "#4CAF50",   # green
    "neutral":  "#607D8B",   # gray
    "accent":   "#FF9800",   # orange
}


def extract_data(filepath):
    """Extract ICMP data from a pcap file."""
    # Empty/header-only captures (e.g. a defense that blocked all traffic) make
    # rdpcap raise "No data could be read!"; treat those as zero packets.
    try:
        packets = rdpcap(filepath)
    except Exception:
        packets = []

    requests = []
    replies = []

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            entry = {
                "time": float(pkt.time),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "type": pkt[ICMP].type,
                "size": len(pkt),
            }
            if pkt[ICMP].type == 8:
                requests.append(entry)
            elif pkt[ICMP].type == 0:
                replies.append(entry)

    return requests, replies


def plot_reply_timeline(replies, output_path, title="Echo Reply Timeline at Victim"):
    """Plot arrival times of Echo Replies at the victim."""
    if not replies:
        print("  No replies to plot.")
        return

    t0 = replies[0]["time"]
    times = [r["time"] - t0 for r in replies]
    sources = [r["src"] for r in replies]
    unique_sources = sorted(set(sources))

    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    # Color each source differently
    # plt.cm.get_cmap was removed in matplotlib 3.9+; plt.get_cmap(name, lut)
    # is the supported replacement and works across current versions.
    cmap = plt.get_cmap("tab10", len(unique_sources))
    src_color = {src: cmap(i) for i, src in enumerate(unique_sources)}

    for i, (t, src) in enumerate(zip(times, sources)):
        ax.scatter(t, 1, color=src_color[src], s=30, alpha=0.8, zorder=5)

    # Create a timeline strip for each source
    for idx, src in enumerate(unique_sources):
        src_times = [t for t, s in zip(times, sources) if s == src]
        y_pos = idx + 1
        ax.scatter(src_times, [y_pos] * len(src_times),
                   color=src_color[src], s=40, alpha=0.9,
                   label=src, zorder=5)

    ax.set_xlabel("Time (seconds since first reply)", color="white", fontsize=11)
    ax.set_ylabel("Amplifier Host", color="white", fontsize=11)
    ax.set_title(title, color="white", fontsize=14, fontweight="bold", pad=15)
    ax.set_yticks(range(1, len(unique_sources) + 1))
    ax.set_yticklabels(unique_sources, color="white", fontsize=9)
    ax.tick_params(axis="x", colors="white")
    ax.grid(True, alpha=0.2, color="white")
    ax.legend(loc="upper right", fontsize=8, facecolor="#16213e",
              edgecolor="white", labelcolor="white")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✓ Saved: {output_path}")


def plot_source_distribution(replies, output_path,
                             title="Echo Replies per Amplifier Host"):
    """Bar chart of reply count per source IP."""
    if not replies:
        return

    source_counts = Counter(r["src"] for r in replies)
    sources = sorted(source_counts.keys())
    counts = [source_counts[s] for s in sources]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    bars = ax.bar(sources, counts, color=COLORS["reply"], alpha=0.85,
                  edgecolor="white", linewidth=0.5)

    # Add count labels on bars
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                str(count), ha="center", va="bottom", color="white",
                fontsize=10, fontweight="bold")

    ax.set_xlabel("Amplifier Host IP", color="white", fontsize=11)
    ax.set_ylabel("Number of Echo Replies", color="white", fontsize=11)
    ax.set_title(title, color="white", fontsize=14, fontweight="bold", pad=15)
    ax.tick_params(axis="both", colors="white")
    ax.grid(True, axis="y", alpha=0.2, color="white")

    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✓ Saved: {output_path}")


def plot_amplification(requests, replies, expected_hosts, output_path):
    """Bar chart comparing observed vs. theoretical amplification."""
    num_req = len(requests)
    num_rep = len(replies)

    observed = num_rep / num_req if num_req > 0 else 0
    theoretical = expected_hosts

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#16213e")

    categories = ["Theoretical\n(N hosts)", "Observed"]
    values = [theoretical, observed]
    colors = [COLORS["neutral"], COLORS["reply"]]

    bars = ax.bar(categories, values, color=colors, alpha=0.85,
                  edgecolor="white", linewidth=0.5, width=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                f"{val:.1f}x", ha="center", va="bottom", color="white",
                fontsize=14, fontweight="bold")

    ax.set_ylabel("Amplification Factor", color="white", fontsize=11)
    ax.set_title("Amplification: Observed vs. Theoretical",
                 color="white", fontsize=14, fontweight="bold", pad=15)
    ax.tick_params(axis="both", colors="white")
    ax.grid(True, axis="y", alpha=0.2, color="white")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✓ Saved: {output_path}")


def plot_defense_comparison(pcap_files, labels, expected_hosts, output_path):
    """Bar chart comparing reply counts across scenarios (baseline/attack/defense)."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor("#1a1a2e")

    reply_counts = []
    source_counts = []

    for f in pcap_files:
        _, replies = extract_data(f)
        reply_counts.append(len(replies))
        source_counts.append(len(set(r["src"] for r in replies)))

    # Chart 1: Reply counts
    ax1.set_facecolor("#16213e")
    bar_colors = [COLORS["request"], COLORS["reply"]] + \
                 [COLORS["defense"]] * (len(labels) - 2)
    bar_colors = bar_colors[:len(labels)]

    bars1 = ax1.bar(labels, reply_counts, color=bar_colors, alpha=0.85,
                    edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars1, reply_counts):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                 str(val), ha="center", va="bottom", color="white",
                 fontsize=10, fontweight="bold")
    ax1.set_ylabel("Echo Replies Received", color="white", fontsize=11)
    ax1.set_title("Total Replies per Scenario", color="white",
                  fontsize=13, fontweight="bold", pad=15)
    ax1.tick_params(axis="both", colors="white")
    ax1.grid(True, axis="y", alpha=0.2, color="white")

    # Chart 2: Unique source counts
    ax2.set_facecolor("#16213e")
    bars2 = ax2.bar(labels, source_counts, color=bar_colors, alpha=0.85,
                    edgecolor="white", linewidth=0.5)
    for bar, val in zip(bars2, source_counts):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                 str(val), ha="center", va="bottom", color="white",
                 fontsize=10, fontweight="bold")
    ax2.set_ylabel("Unique Reply Sources", color="white", fontsize=11)
    ax2.set_title("Amplifier Host Participation", color="white",
                  fontsize=13, fontweight="bold", pad=15)
    ax2.tick_params(axis="both", colors="white")
    ax2.grid(True, axis="y", alpha=0.2, color="white")

    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✓ Saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="ICMP Smurf Attack — Visualization / Plotting Tool"
    )
    parser.add_argument(
        "pcap_files", nargs="+",
        help="One or more .pcap files to visualize"
    )
    parser.add_argument(
        "--expected-hosts", "-n", type=int, default=6,
        help="Expected number of amplifier hosts (default: 6)"
    )
    parser.add_argument(
        "--output-dir", "-o", default="/results",
        help="Directory to save output plots (default: /results)"
    )
    parser.add_argument(
        "--compare", action="store_true",
        help="Generate defense comparison chart across all provided pcaps"
    )
    parser.add_argument(
        "--labels", nargs="*",
        help="Labels for comparison chart (one per pcap file)"
    )

    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    print("=" * 70)
    print("  ICMP SMURF ATTACK — VISUALIZATION")
    print("=" * 70)

    # Generate plots for each pcap
    for filepath in args.pcap_files:
        requests, replies = extract_data(filepath)
        basename = os.path.splitext(os.path.basename(filepath))[0]

        print(f"\n  Processing: {filepath}")
        print(f"    Requests: {len(requests)}, Replies: {len(replies)}")

        if replies:
            plot_reply_timeline(
                replies,
                os.path.join(args.output_dir, f"{basename}_timeline.png"),
                title=f"Echo Reply Timeline — {basename}"
            )
            plot_source_distribution(
                replies,
                os.path.join(args.output_dir, f"{basename}_sources.png"),
                title=f"Replies per Amplifier — {basename}"
            )

        if requests and replies:
            plot_amplification(
                requests, replies, args.expected_hosts,
                os.path.join(args.output_dir, f"{basename}_amplification.png")
            )

    # Defense comparison
    if args.compare and len(args.pcap_files) >= 2:
        labels = args.labels or [
            os.path.splitext(os.path.basename(f))[0][:12]
            for f in args.pcap_files
        ]
        plot_defense_comparison(
            args.pcap_files, labels, args.expected_hosts,
            os.path.join(args.output_dir, "defense_comparison.png")
        )

    print(f"\n  All plots saved to: {args.output_dir}/")
    print("=" * 70)


if __name__ == "__main__":
    main()
