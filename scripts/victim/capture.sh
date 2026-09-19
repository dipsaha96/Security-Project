#!/bin/bash
# Victim Packet Capture Script
# Runs tcpdump on the victim to capture ICMP traffic for analysis.
#
# Usage:
#   ./capture.sh                        # default: capture all ICMP
#   ./capture.sh baseline               # tag capture as "baseline"
#   ./capture.sh attack                 # tag capture as "attack"
#   ./capture.sh defense_broadcast      # tag capture as defense test
#   ./capture.sh <label> <duration>     # custom label and duration in seconds

LABEL="${1:-capture}"
DURATION="${2:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="/captures/${LABEL}_${TIMESTAMP}.pcap"

echo "============================================================"
echo "  VICTIM PACKET CAPTURE"
echo "============================================================"
echo "  Label    : ${LABEL}"
echo "  Duration : ${DURATION}s"
echo "  Output   : ${OUTPUT_FILE}"
echo "  Filter   : icmp"
echo "============================================================"
echo ""
echo "  Capturing... (press Ctrl+C to stop early)"
echo ""

# Capture ICMP traffic on all interfaces
tcpdump -i any \
    -w "${OUTPUT_FILE}" \
    icmp \
    -c 10000 \
    &

TCPDUMP_PID=$!

# Wait for the specified duration, then stop
sleep "${DURATION}"
kill "${TCPDUMP_PID}" 2>/dev/null
wait "${TCPDUMP_PID}" 2>/dev/null

echo ""
echo "  Capture saved: ${OUTPUT_FILE}"
echo ""

# Quick summary using tcpdump read mode
echo "  --- Quick Summary ---"
tcpdump -r "${OUTPUT_FILE}" -q 2>/dev/null | head -20
TOTAL=$(tcpdump -r "${OUTPUT_FILE}" 2>/dev/null | wc -l)
echo "  ..."
echo "  Total packets captured: ${TOTAL}"
echo "============================================================"
