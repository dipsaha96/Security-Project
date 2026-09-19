#!/bin/bash
# Defense 2: Ingress Filtering / Source-Address Validation 
# Run on: ROUTER (or attacker's egress point)
#
# Effect: Drops packets with source addresses that don't belong to the
#         network they arrived from. Specifically, blocks any packet
#         arriving from the attacker network (10.0.0.0/24) that claims
#         a source outside that range (e.g., spoofed 198.51.100.10).

ACTION="${1:-enable}"

echo "============================================================"
echo "  DEFENSE 2: Ingress Filtering (BCP 38 / RFC 2827)"
echo "============================================================"

if [ "$ACTION" = "enable" ]; then
    echo "  [+] Enabling source-address validation..."

    # Reverse path filtering (strict mode) on all interfaces
    for iface in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 1 > "$iface" 2>/dev/null
    done

    # Also add explicit iptables rules for clarity and logging:
    # Drop packets from attacker_net interface that claim source != 10.0.0.0/24
    # The router's attacker-facing interface has IP 10.0.0.1
    iptables -I FORWARD -s 198.51.100.0/24 -i eth0 -j DROP 2>/dev/null
    iptables -I FORWARD -s 203.0.113.0/24 -i eth0 -j DROP 2>/dev/null

    # Log spoofed packets before dropping (for analysis)
    iptables -I FORWARD -s 198.51.100.0/24 -i eth0 -j LOG \
        --log-prefix "INGRESS_FILTER_DROP: " 2>/dev/null

    echo "  [+] Defense ENABLED — spoofed source packets will be dropped."
    echo ""
    echo "  Verification:"
    iptables -L FORWARD -n --line-numbers | head -10

elif [ "$ACTION" = "disable" ]; then
    echo "  [-] Disabling source-address validation..."

    for iface in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 0 > "$iface" 2>/dev/null
    done

    iptables -D FORWARD -s 198.51.100.0/24 -i eth0 -j DROP 2>/dev/null
    iptables -D FORWARD -s 203.0.113.0/24 -i eth0 -j DROP 2>/dev/null
    iptables -D FORWARD -s 198.51.100.0/24 -i eth0 -j LOG \
        --log-prefix "INGRESS_FILTER_DROP: " 2>/dev/null

    echo "  [-] Defense DISABLED — spoofed source packets allowed again."
fi

echo "============================================================"
