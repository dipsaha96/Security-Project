#!/bin/bash

# ICMP Smurf Attack — Experiment Runner
#
#   Phase 1: Baseline (normal ICMP)
#   Phase 2: Broadcast fan-out verification
#   Phase 3: Smurf attack demonstration
#   Phase 4: Defense tests (one at a time)
#   Phase 5: Analysis & visualization
#
# Run this script from the HOST machine (not inside a container).
#
# Prerequisites:
#   - docker compose up -d  (all containers running)
#
# Usage:
#   ./run_experiment.sh              # run all phases
#   ./run_experiment.sh baseline     # run only baseline phase
#   ./run_experiment.sh attack       # run only attack phase
#   ./run_experiment.sh defense      # run only defense tests
#   ./run_experiment.sh analyze      # run only analysis

set -e

# ── Configuration ──
ATTACK_RATE=2        # packets per second
ATTACK_COUNT=10      # total spoofed packets per test
CAPTURE_DURATION=20  # seconds to capture
VICTIM_IP="198.51.100.10"
BROADCAST_IP="203.0.113.255"
AMPLIFIER_HOSTS=("amp-h1" "amp-h2" "amp-h3" "amp-h4" "amp-h5" "amp-h6")

PHASE="${1:-all}"

echo "ICMP SMURF ATTACK — EXPERIMENT RUNNER"
echo "  Rate          : ${ATTACK_RATE} pkt/s"
echo "  Count         : ${ATTACK_COUNT} packets"
echo "  Capture time  : ${CAPTURE_DURATION}s"
echo "  Phase         : ${PHASE}"
echo ""

# ── Helper functions ──
run_on() {
    local container=$1
    shift
    docker exec "$container" bash -c "$*"
}

wait_msg() {
    echo ""
    echo "  ────────────────────────────────────────────────"
    echo "  $1"
    echo "  ────────────────────────────────────────────────"
    echo ""
}

# PHASE 1: BASELINE — Normal ICMP Echo 
run_baseline() {
    wait_msg "PHASE 1: Normal ICMP Echo Baseline"

    # Start capture on victim
    run_on victim "bash /scripts/capture.sh baseline ${CAPTURE_DURATION}" &
    CAPTURE_PID=$!
    sleep 2

    # Send normal (non-spoofed) pings from attacker to a single amplifier
    run_on attacker "python3 /scripts/smurf_attack.py \
        --mode baseline \
        --broadcast-ip 203.0.113.11 \
        --rate ${ATTACK_RATE} \
        --count ${ATTACK_COUNT}"

    # Wait for capture to finish
    wait $CAPTURE_PID 2>/dev/null || true

    echo "  ✓ Baseline capture complete."
}

# PHASE 2: BROADCAST FAN-OUT 
run_fanout() {
    wait_msg "PHASE 2: Directed Broadcast Fan-Out Verification"

    # Ensure amplifier hosts accept broadcast pings
    for host in "${AMPLIFIER_HOSTS[@]}"; do
        run_on "$host" "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts" 2>/dev/null || true
    done

    # Start capture on victim (to see if anything bounces there)
    run_on victim "bash /scripts/capture.sh fanout ${CAPTURE_DURATION}" &
    CAPTURE_PID=$!
    sleep 2

    # Send non-spoofed ping to broadcast address
    run_on attacker "python3 /scripts/smurf_attack.py \
        --mode baseline \
        --broadcast-ip ${BROADCAST_IP} \
        --rate ${ATTACK_RATE} \
        --count ${ATTACK_COUNT}"

    wait $CAPTURE_PID 2>/dev/null || true

    echo "  ✓ Fan-out verification complete."
}

# PHASE 3: SMURF ATTACK 
run_attack() {
    wait_msg "PHASE 3: Smurf Attack Demonstration"

    # Ensure defenses are OFF
    for host in "${AMPLIFIER_HOSTS[@]}"; do
        run_on "$host" "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts" 2>/dev/null || true
    done

    # Start capture on victim
    run_on victim "bash /scripts/capture.sh attack ${CAPTURE_DURATION}" &
    CAPTURE_PID=$!

    # Start monitor on victim (background)
    run_on victim "python3 /scripts/monitor.py \
        --threshold 5 --sources-threshold 3 --window 5 \
        --duration ${CAPTURE_DURATION} \
        --log /captures/attack_alerts.log" &
    MONITOR_PID=$!

    sleep 2

    # Launch the Smurf attack
    run_on attacker "python3 /scripts/smurf_attack.py \
        --mode attack \
        --victim-ip ${VICTIM_IP} \
        --broadcast-ip ${BROADCAST_IP} \
        --rate ${ATTACK_RATE} \
        --count ${ATTACK_COUNT}"

    # Wait for captures
    wait $CAPTURE_PID 2>/dev/null || true
    wait $MONITOR_PID 2>/dev/null || true

    echo "  ✓ Smurf attack demonstration complete."
}

# PHASE 4: DEFENSE TESTS 
run_defense_tests() {
    wait_msg "PHASE 4: Defense Verification"

    # ── Defense 1: Disable directed-broadcast forwarding ──
    echo "  >>> Defense 1: Disable Directed Broadcast Forwarding"
    run_on router "bash /scripts/defense/disable_broadcast.sh enable"

    run_on victim "bash /scripts/capture.sh defense_broadcast ${CAPTURE_DURATION}" &
    CAPTURE_PID=$!
    sleep 2

    run_on attacker "python3 /scripts/smurf_attack.py \
        --mode attack \
        --victim-ip ${VICTIM_IP} \
        --broadcast-ip ${BROADCAST_IP} \
        --rate ${ATTACK_RATE} \
        --count ${ATTACK_COUNT}"

    wait $CAPTURE_PID 2>/dev/null || true
    run_on router "bash /scripts/defense/disable_broadcast.sh disable"
    echo ""

    # ── Defense 2: Ingress filtering ──
    echo "  >>> Defense 2: Ingress Filtering (Source Validation)"
    run_on router "bash /scripts/defense/ingress_filter.sh enable"

    run_on victim "bash /scripts/capture.sh defense_ingress ${CAPTURE_DURATION}" &
    CAPTURE_PID=$!
    sleep 2

    run_on attacker "python3 /scripts/smurf_attack.py \
        --mode attack \
        --victim-ip ${VICTIM_IP} \
        --broadcast-ip ${BROADCAST_IP} \
        --rate ${ATTACK_RATE} \
        --count ${ATTACK_COUNT}"

    wait $CAPTURE_PID 2>/dev/null || true
    run_on router "bash /scripts/defense/ingress_filter.sh disable"
    echo ""

    # ── Defense 3: Suppress broadcast echo ──
    echo "  >>> Defense 3: Suppress Broadcast Echo Response"
    for host in "${AMPLIFIER_HOSTS[@]}"; do
        run_on "$host" "bash -c 'echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts'"
    done

    run_on victim "bash /scripts/capture.sh defense_echo ${CAPTURE_DURATION}" &
    CAPTURE_PID=$!
    sleep 2

    run_on attacker "python3 /scripts/smurf_attack.py \
        --mode attack \
        --victim-ip ${VICTIM_IP} \
        --broadcast-ip ${BROADCAST_IP} \
        --rate ${ATTACK_RATE} \
        --count ${ATTACK_COUNT}"

    wait $CAPTURE_PID 2>/dev/null || true
    # Re-enable for next test
    for host in "${AMPLIFIER_HOSTS[@]}"; do
        run_on "$host" "bash -c 'echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts'"
    done
    echo ""

    # ── Defense 4: Rate limiting ──
    echo "  >>> Defense 4: ICMP Rate Limiting"
    run_on router "bash /scripts/defense/rate_limit.sh enable 5 10"

    run_on victim "bash /scripts/capture.sh defense_ratelimit ${CAPTURE_DURATION}" &
    CAPTURE_PID=$!
    sleep 2

    run_on attacker "python3 /scripts/smurf_attack.py \
        --mode attack \
        --victim-ip ${VICTIM_IP} \
        --broadcast-ip ${BROADCAST_IP} \
        --rate ${ATTACK_RATE} \
        --count ${ATTACK_COUNT}"

    wait $CAPTURE_PID 2>/dev/null || true
    run_on router "bash /scripts/defense/rate_limit.sh disable"

    echo ""
    echo "  ✓ All defense tests complete."
}

# PHASE 5: ANALYSIS & VISUALIZATION 
run_analysis() {
    wait_msg "PHASE 5: Analysis & Visualization"

    # Find all pcap files
    PCAP_FILES=$(find captures/ -name "*.pcap" 2>/dev/null | sort)

    if [ -z "$PCAP_FILES" ]; then
        echo "  No .pcap files found in captures/. Run experiments first."
        return
    fi

    echo "  Found captures:"
    echo "$PCAP_FILES" | sed 's/^/    /'
    echo ""

    # Run analysis on each file
    for f in $PCAP_FILES; do
        docker exec victim python3 /scripts/analysis/analyze_pcap.py "/captures/$(basename $f)" --expected-hosts 6
    done

    # Run comparison if multiple files exist
    FILE_COUNT=$(echo "$PCAP_FILES" | wc -l)
    if [ "$FILE_COUNT" -ge 2 ]; then
        PCAP_ARGS=$(echo "$PCAP_FILES" | sed 's|captures/|/captures/|' | tr '\n' ' ')
        docker exec victim python3 /scripts/analysis/analyze_pcap.py $PCAP_ARGS --compare
    fi

    # Generate plots
    if [ "$FILE_COUNT" -ge 1 ]; then
        PCAP_ARGS=$(echo "$PCAP_FILES" | sed 's|captures/|/captures/|' | tr '\n' ' ')
        docker exec victim python3 /scripts/analysis/plot_results.py $PCAP_ARGS \
            --output-dir /results --compare 2>/dev/null || echo "  (Plotting skipped — check matplotlib)"
    fi

    echo "  ✓ Analysis complete. Results in results/"
}

case "$PHASE" in
    baseline)   run_baseline ;;
    fanout)     run_fanout ;;
    attack)     run_attack ;;
    defense)    run_defense_tests ;;
    analyze)    run_analysis ;;
    all)
        run_baseline
        run_fanout
        run_attack
        run_defense_tests
        run_analysis
        ;;
    *)
        echo "Usage: $0 {all|baseline|fanout|attack|defense|analyze}"
        exit 1
        ;;
esac

echo ""
echo "EXPERIMENT COMPLETE"
echo "Captures: captures/"
echo "Results:  results/"
