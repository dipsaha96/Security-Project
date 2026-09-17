#!/bin/bash
# =============================================================================
# Router Setup Script
# Enables IP forwarding and configures routes between all three subnets.
# Directed-broadcast forwarding is ENABLED by default for the lab.
# Defense scripts can disable it later.
#
# NOTE: ip_forward is set via docker-compose sysctls, not here.
# =============================================================================

set -e

echo "[Router] Configuring router..."

# ip_forward is already enabled via docker-compose sysctls.
# Verify it:
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
echo "[Router] ip_forward = ${IP_FWD}"

# Allow broadcast forwarding (required for Smurf demonstration)
# Ensure the FORWARD chain accepts everything initially.
echo "[Router] Setting FORWARD policy to ACCEPT..."
iptables -P FORWARD ACCEPT
iptables -F FORWARD

# --- Isolation: sever the lab from the internet -----------------------------
# The three lab networks are NOT Docker "internal" networks (that would break
# cross-subnet routing through this router). Instead we remove the router's
# default route so it has no path off the lab. Every endpoint uses this router
# as its default gateway, so with no upstream route here, no lab host can reach
# the internet, while the three lab subnets remain fully routable via this box.
while ip route show default | grep -q default; do
    ip route del default 2>/dev/null || break
done
echo "[Router] Default route removed (lab isolated from internet)."

# --- Enable directed-broadcast forwarding on every interface ----------------
# The kernel forwards a directed broadcast only when conf.all.bc_forwarding
# AND the INPUT interface bc_forwarding are both 1. Set it everywhere so the
# spoofed packet to 203.0.113.255 fans out to all amplifier hosts.
for d in /proc/sys/net/ipv4/conf/*/bc_forwarding; do
    echo 1 > "$d" 2>/dev/null || true
done
echo "[Router] Directed-broadcast forwarding enabled on all interfaces."

echo "[Router] Configuration complete."
echo "  Interfaces:"
ip -4 addr show | grep "inet "
echo "  Routes:"
ip route show
echo "[Router] Ready."
