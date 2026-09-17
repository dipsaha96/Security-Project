# ICMP Smurf Attack — Testing Guide

> Complete step-by-step instructions to build, run, and verify every phase of the project.

---

## Prerequisites

| Requirement | Check Command |
|-------------|---------------|
| Docker | `docker --version` |
| Docker Compose | `docker compose version` |
| Docker running | `docker info` |

---

## Step 1: Build All Containers

```bash
cd "/Users/dipsaha/Documents/4-1/CSE 406/Project"
docker compose build
```

This builds 4 images (attacker, router, amplifier, victim). First build takes ~2-3 minutes.

---

## Step 2: Start the Lab

```bash
docker compose up -d
```

Verify all 9 containers are running:

```bash
docker compose ps
```

Expected output — all containers should show **running**:

| Container | IP Address | Role |
|-----------|-----------|------|
| `attacker` | 10.0.0.9 | Generates spoofed traffic |
| `router` | 10.0.0.1 / 203.0.113.254 / 198.51.100.1 | Multi-homed border router |
| `amp-h1` | 203.0.113.1 | Amplifier host |
| `amp-h2` | 203.0.113.2 | Amplifier host |
| `amp-h3` | 203.0.113.3 | Amplifier host |
| `amp-h4` | 203.0.113.4 | Amplifier host |
| `amp-h5` | 203.0.113.5 | Amplifier host |
| `amp-h6` | 203.0.113.6 | Amplifier host |
| `victim` | 198.51.100.10 | Target of reflected replies |

---

## Step 3: Verify Network Connectivity

Run these commands to confirm all nodes can communicate:

```bash
# Attacker → Router
docker exec attacker ping -c 2 10.0.0.1

# Router → Amplifier H1
docker exec router ping -c 2 203.0.113.1

# Router → Victim
docker exec router ping -c 2 198.51.100.10

# Attacker → Amplifier (through router)
docker exec attacker ping -c 2 203.0.113.1

# Attacker → Victim (through router)
docker exec attacker ping -c 2 198.51.100.10
```

✅ **Pass**: All pings show `0% packet loss`.

---

## Step 4: Run the Full Experiment (Automatic)

The quickest way — runs all 5 phases automatically:

```bash
./run_experiment.sh all
```

This executes:
1. **Baseline** — normal ICMP ping (one-to-one)
2. **Fan-out** — broadcast delivery verification
3. **Attack** — Smurf attack demonstration
4. **Defense** — tests all 4 defenses one by one
5. **Analysis** — parses captures and generates charts

Total time: ~3-4 minutes.

You can also run individual phases:

```bash
./run_experiment.sh baseline    # Phase 1 only
./run_experiment.sh fanout      # Phase 2 only
./run_experiment.sh attack      # Phase 3 only
./run_experiment.sh defense     # Phase 4 only
./run_experiment.sh analyze     # Phase 5 only
```

---

## Step 5: Run the Experiment (Manual / Interactive)

For a deeper understanding and live demonstration, use 3 separate terminal windows.

### Terminal 1 — Start Victim Monitor

```bash
docker exec -it victim python3 /scripts/monitor.py --threshold 5 --window 5
```

Keep this running. It will show real-time alerts when an attack is detected.

### Terminal 2 — Start Victim Packet Capture

```bash
docker exec -it victim bash /scripts/capture.sh attack 60
```

This captures all ICMP traffic for 60 seconds.

### Terminal 3 — Run Tests

#### Test 1: Normal Ping (Baseline)

```bash
docker exec attacker python3 /scripts/smurf_attack.py \
    --mode baseline \
    --broadcast-ip 203.0.113.1 \
    --rate 1 --count 5
```

✅ **Expected**: Terminal 1 shows normal traffic, **no alerts**. One request produces one reply.

---

#### Test 2: Smurf Attack

```bash
docker exec attacker python3 /scripts/smurf_attack.py \
    --mode attack \
    --victim-ip 198.51.100.10 \
    --broadcast-ip 203.0.113.255 \
    --rate 2 --count 10
```

✅ **Expected in Terminal 1**:
- 🚨 **CRITICAL** alerts: "SMURF DETECTED"
- 🚨 **CRITICAL** alerts: "REFLECTION PATTERN — 6 unique sources"
- Multiple source IPs (203.0.113.1 through .6) sending replies
- Amplification ratio ≈ 6x

---

#### Test 3: Defense 1 — Disable Directed Broadcast

```bash
# Enable defense
docker exec router bash /scripts/defense/disable_broadcast.sh enable

# Re-run attack
docker exec attacker python3 /scripts/smurf_attack.py \
    --mode attack \
    --victim-ip 198.51.100.10 \
    --broadcast-ip 203.0.113.255 \
    --rate 2 --count 10

# Disable defense (reset for next test)
docker exec router bash /scripts/defense/disable_broadcast.sh disable
```

✅ **Expected**: **0 replies** at victim — broadcast is blocked at router.

---

#### Test 4: Defense 2 — Ingress Filtering (Source Validation)

```bash
# Enable defense
docker exec router bash /scripts/defense/ingress_filter.sh enable

# Re-run attack
docker exec attacker python3 /scripts/smurf_attack.py \
    --mode attack \
    --victim-ip 198.51.100.10 \
    --broadcast-ip 203.0.113.255 \
    --rate 2 --count 10

# Disable defense
docker exec router bash /scripts/defense/ingress_filter.sh disable
```

✅ **Expected**: **Spoofed packets dropped** at router — never reach amplifiers.

---

#### Test 5: Defense 3 — Suppress Broadcast Echo Response

```bash
# Enable defense on ALL amplifier hosts
for i in 1 2 3 4 5 6; do
    docker exec amp-h$i bash -c 'echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts'
done

# Re-run attack
docker exec attacker python3 /scripts/smurf_attack.py \
    --mode attack \
    --victim-ip 198.51.100.10 \
    --broadcast-ip 203.0.113.255 \
    --rate 2 --count 10

# Disable defense (re-enable amplifiers)
for i in 1 2 3 4 5 6; do
    docker exec amp-h$i bash -c 'echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts'
done
```

✅ **Expected**: **0 replies** — amplifier hosts silently ignore broadcast Echo Requests.

---

#### Test 6: Defense 4 — ICMP Rate Limiting

```bash
# Enable defense (limit to 3 replies/sec, burst of 5)
docker exec router bash /scripts/defense/rate_limit.sh enable 3 5

# Re-run attack
docker exec attacker python3 /scripts/smurf_attack.py \
    --mode attack \
    --victim-ip 198.51.100.10 \
    --broadcast-ip 203.0.113.255 \
    --rate 2 --count 10

# Disable defense
docker exec router bash /scripts/defense/rate_limit.sh disable
```

✅ **Expected**: **Reduced reply rate** — only ~3 replies/sec pass through instead of full flood.

---

#### Stop the Monitor

Press `Ctrl+C` in Terminal 1. You'll see a summary:

```
  MONITORING SUMMARY
  Duration          : 120.5s
  Echo Requests (out): 0
  Echo Replies  (in) : 47
  Alerts triggered   : 8
  Amplification ratio: ∞ (no outbound requests!)
  Attack detected    : YES ⚠️
```

---

## Step 6: Analyze Captures

### View captured files

```bash
ls -la captures/
```

### Run analysis on attack capture

```bash
docker exec victim python3 /scripts/analysis/analyze_pcap.py /captures/attack_*.pcap
```

This outputs:
- Packet counts (requests vs replies)
- Unique source IPs
- Observed amplification factor
- Timing statistics

### Compare baseline vs attack vs defense

```bash
docker exec victim python3 /scripts/analysis/analyze_pcap.py \
    /captures/baseline_*.pcap \
    /captures/attack_*.pcap \
    /captures/defense_broadcast_*.pcap \
    --compare
```

### Generate charts

```bash
docker exec victim python3 /scripts/analysis/plot_results.py \
    /captures/attack_*.pcap \
    --output-dir /results
```

### View charts

```bash
open results/*.png
```

Generated charts include:
- **Timeline plot** — packet arrivals over time at the victim
- **Source distribution** — replies per amplifier host
- **Amplification chart** — observed vs theoretical
- **Defense comparison** — before/after reply counts

---

## Step 7: Success Criteria Checklist

| # | Criterion (from Design Report §9.2) | How to Verify | Pass? |
|---|--------------------------------------|---------------|-------|
| 1 | Normal one-to-one ICMP exchange verified | Baseline test: 5 requests → 5 replies | ☐ |
| 2 | Broadcast request reaches configured amplifier hosts | Fan-out test: all 6 hosts respond | ☐ |
| 3 | Victim receives reflected Echo Replies from multiple responders | Attack test: monitor shows 6 unique sources | ☐ |
| 4 | Amplification consistent with number of responding hosts | Analysis shows amplification ≈ 6x | ☐ |
| 5 | Defenses break the reflection path | Each defense reduces/eliminates replies | ☐ |

---

## Step 8: Cleanup

```bash
# Stop and remove all containers + networks
docker compose down

# Also remove built images (optional, saves disk space)
docker compose down --rmi all

# Clear experiment data
rm -f captures/*.pcap captures/*.log results/*.png
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `docker compose up` fails | Check: `docker info` — is Docker Desktop running? |
| Container exits immediately | `docker compose logs <name>` to check error |
| Pings fail between nodes | `docker exec router sysctl net.ipv4.ip_forward` — should be `1` |
| No broadcast replies | `docker exec amp-h1 cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts` — must be `0` |
| Monitor shows nothing | Start monitor **before** running the attack |
| `Permission denied` on scripts | `chmod +x run_experiment.sh scripts/**/*.sh configs/*.sh` |
| Captures directory empty | Check volume mounts: `docker inspect victim \| grep Mounts` |
| Analysis shows 0 packets | Verify pcap path: `docker exec victim ls /captures/` |

---

## Quick Command Reference

```bash
# === LIFECYCLE ===
docker compose build                    # Build images
docker compose up -d                    # Start lab
docker compose ps                       # Check status
docker compose down                     # Stop & cleanup

# === SHELL ACCESS ===
docker exec -it attacker bash           # Shell into attacker
docker exec -it victim bash             # Shell into victim
docker exec -it router bash             # Shell into router
docker exec -it amp-h1 bash             # Shell into amplifier

# === EXPERIMENT ===
./run_experiment.sh all                 # Run everything
./run_experiment.sh baseline            # Normal ping test
./run_experiment.sh attack              # Smurf attack test
./run_experiment.sh defense             # All 4 defense tests
./run_experiment.sh analyze             # Analyze captures

# === LOGS ===
docker compose logs attacker            # View container logs
docker compose logs -f victim           # Follow victim logs
```
