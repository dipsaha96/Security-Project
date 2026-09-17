#!/bin/bash
# =============================================================================
# Defense 4: ICMP Rate Limiting (§10.2)
# =============================================================================
# Run on: ROUTER or VICTIM
#
# Effect: Limits the rate of ICMP traffic forwarded/received using iptables
#         --limit. This is a secondary control that reduces impact of residual
#         traffic without removing the underlying reflection path.
# =============================================================================

ACTION="${1:-enable}"
RATE="${2:-5}"          # packets per second
BURST="${3:-10}"        # burst tolerance

echo "============================================================"
echo "  DEFENSE 4: ICMP Rate Limiting"
echo "============================================================"

if [ "$ACTION" = "enable" ]; then
    echo "  [+] Enabling ICMP rate limiting..."
    echo "      Rate  : ${RATE}/sec"
    echo "      Burst : ${BURST}"

    # Rate-limit ICMP in the FORWARD chain (router)
    iptables -I FORWARD -p icmp --icmp-type echo-reply \
        -m limit --limit "${RATE}/sec" --limit-burst "${BURST}" -j ACCEPT
    iptables -A FORWARD -p icmp --icmp-type echo-reply -j DROP

    echo "  [+] Defense ENABLED — ICMP Echo Replies rate-limited to ${RATE}/s."
    echo ""
    echo "  Verification:"
    iptables -L FORWARD -n --line-numbers | head -10

elif [ "$ACTION" = "disable" ]; then
    echo "  [-] Removing ICMP rate limits..."

    iptables -D FORWARD -p icmp --icmp-type echo-reply \
        -m limit --limit "${RATE}/sec" --limit-burst "${BURST}" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP 2>/dev/null

    echo "  [-] Defense DISABLED — no ICMP rate limiting."
fi

echo "============================================================"
