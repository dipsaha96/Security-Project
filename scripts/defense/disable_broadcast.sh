#!/bin/bash
# =============================================================================
# Defense 1: Disable Directed-Broadcast Forwarding (§10.2, RFC 2644)
# =============================================================================
# Run on: ROUTER
#
# Effect: The router will no longer forward packets destined to the
#         amplifier subnet's broadcast address (203.0.113.255).
#         This prevents the Smurf request from reaching the amplifier hosts.
# =============================================================================

ACTION="${1:-enable}"   # "enable" to apply defense, "disable" to remove it

echo "============================================================"
echo "  DEFENSE 1: Directed-Broadcast Forwarding Control"
echo "============================================================"

if [ "$ACTION" = "enable" ]; then
    echo "  [+] Blocking directed-broadcast forwarding..."

    # Drop any packet destined to the broadcast address of the amplifier net
    iptables -I FORWARD -d 203.0.113.255 -j DROP
    iptables -I FORWARD -d 203.0.113.0 -j DROP

    echo "  [+] Defense ENABLED — directed broadcasts will be dropped."
    echo ""
    echo "  Verification:"
    iptables -L FORWARD -n --line-numbers | head -10

elif [ "$ACTION" = "disable" ]; then
    echo "  [-] Removing directed-broadcast block..."

    iptables -D FORWARD -d 203.0.113.255 -j DROP 2>/dev/null
    iptables -D FORWARD -d 203.0.113.0 -j DROP 2>/dev/null

    echo "  [-] Defense DISABLED — directed broadcasts allowed again."
fi

echo "============================================================"
