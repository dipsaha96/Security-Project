#!/bin/bash
# =============================================================================
# Defense 3: Suppress Broadcast ICMP Echo Responses (§10.2)
# =============================================================================
# Run on: AMPLIFIER HOSTS (all H1–H6)
#
# Effect: Hosts will ignore ICMP Echo Requests that are addressed to
#         broadcast or multicast destinations. This removes the amplifier
#         hosts from the reflection mechanism.
# =============================================================================

ACTION="${1:-enable}"

echo "============================================================"
echo "  DEFENSE 3: Suppress Broadcast Echo Response"
echo "  Host: $(hostname) ($(hostname -I | tr -s ' '))"
echo "============================================================"

if [ "$ACTION" = "enable" ]; then
    echo "  [+] Enabling icmp_echo_ignore_broadcasts..."
    echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
    VALUE=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts)
    echo "  [+] icmp_echo_ignore_broadcasts = ${VALUE}"
    echo "  [+] Defense ENABLED — host will NOT respond to broadcast Echo Requests."

elif [ "$ACTION" = "disable" ]; then
    echo "  [-] Disabling icmp_echo_ignore_broadcasts..."
    echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
    VALUE=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts)
    echo "  [-] icmp_echo_ignore_broadcasts = ${VALUE}"
    echo "  [-] Defense DISABLED — host WILL respond to broadcast Echo Requests."
fi

echo "============================================================"
