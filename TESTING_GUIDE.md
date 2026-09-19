# ICMP Smurf Attack — Testing Guide

Complete, from-scratch instructions to build, run, and verify every part of the project,
including the live attack, the four defenses, victim-side evidence, and Wireshark analysis.

All addresses use RFC 5737 documentation ranges. The lab is fully isolated (no Internet access).

---

## 0. What you are testing

| Goal | How it's proven |
|------|-----------------|
| The Smurf attack works | 10 spoofed requests → **60** replies at the victim (6× amplification) |
| Reflection / spoofing | Replies come from 6 amplifiers; requests carry the **victim's** IP as source |
| Each defense works | With a defense on, replies reaching the victim drop to **0** (rate-limit: reduced) |
| Isolation | The lab cannot reach the Internet |

---

## 1. Prerequisites

| Requirement | Check command |
|-------------|---------------|
| Docker Desktop running | `docker info` |
| Docker Compose v2 | `docker compose version` |
| (For Wireshark step) Wireshark | `brew install --cask wireshark` |

Work from the project root:

```bash
cd "/Users/dipsaha/Documents/4-1/CSE 406/Project"
```

---

## 2. Build and start the lab

```bash
docker compose up -d --build
```

This builds 4 images and starts **9 containers**. Verify:

```bash
docker compose ps
```

All 9 should show **Up**:

| Container | Address(es) | Role |
|-----------|-------------|------|
| `attacker` | 10.0.0.9 | Generates spoofed ICMP (Scapy) |
| `router`   | 10.0.0.2 · 203.0.113.254 · 198.51.100.2 | Multi-homed router; hosts most defenses |
| `amp-h1`…`amp-h6` | 203.0.113.11 … 203.0.113.16 | Amplifier hosts |
| `victim`   | 198.51.100.10 | Target; captures the flood |

> If `docker compose up` ever prints **"Address already in use"**, it's a stale network from a
> previous run. Fix: `docker compose down` then `docker compose up -d` again.

---

## 3. Verify connectivity and isolation

```bash
# Cross-subnet routing works (through the router)
docker exec attacker ping -c1 -W2 198.51.100.10     # attacker -> victim
docker exec attacker ping -c1 -W2 203.0.113.11      # attacker -> amplifier
docker exec victim   ping -c1 -W2 203.0.113.16      # victim   -> amplifier

# Isolation: these MUST fail (no Internet)
docker exec attacker ping -c1 -W3 8.8.8.8           # expect 100% loss / unreachable
```

Expected: the first three succeed (0% loss); the Internet ping fails.

---

## 4. Run the full experiment (one command)

```bash
./run_experiment.sh all
```

This runs all phases in order and finishes with exit code 0:

| Phase | What it does | Expected |
|-------|--------------|----------|
| 1. Baseline | Normal ICMP | victim capture ~0 (traffic doesn't cross victim) |
| 2. Fan-out | Non-spoofed broadcast ping | confirms broadcast reaches amplifiers |
| 3. Attack | Spoofed broadcast (src = victim) | **60 packets** at victim (6×) |
| 4. Defenses | Each defense on, attack re-run | replies at victim → **0** (rate-limit: reduced) |
| 5. Analysis | Parse pcaps, make plots | figures written to `results/` |

Run individual phases if you prefer:

```bash
./run_experiment.sh baseline
./run_experiment.sh attack
./run_experiment.sh defense
./run_experiment.sh analyze
```

Outputs:
- Packet captures → `captures/*.pcap`
- Plots → `results/*.png` (per-amplifier, timeline, `defense_comparison.png`)

---

## 5. Manual attack demo (for a live viva)

Open two terminals.

**Terminal 1 — the victim's screen** (leave it running):
```bash
docker exec -it victim tcpdump -ni eth0 icmp
```

**Terminal 2 — launch the attack:**
```bash
docker exec attacker python3 /scripts/smurf_attack.py --mode attack \
  --victim-ip 198.51.100.10 --broadcast-ip 203.0.113.255 --rate 5 --count 10
```

Terminal 1 will flood with Echo Replies from `203.0.113.11`–`.16`. Ten requests → sixty replies.

**Intrusion-detection view** (instead of raw tcpdump):
```bash
docker exec -it victim python3 /scripts/monitor.py \
  --threshold 5 --sources-threshold 3 --window 5
```
It escalates to a **SMURF DETECTED** alert during the attack.

---

## 6. Capture the victim "screens" (report screenshots)

One command regenerates the polished terminal screenshots used in the report
(`screenshots/victim_1_baseline.png`, `victim_2_attack.png`, `victim_3_ids.png`):

```bash
./capture_victim_screens.sh
```

---

## 7. Wireshark analysis

The lab prepared three clean capture files for Wireshark. If you want fresh ones you captured
yourself, see step 7c.

### 7a. Open the capture files
```bash
open -a Wireshark "captures/wireshark_attacker_spoofed.pcap"   # spoofed source
open -a Wireshark "captures/wireshark_victim_flood.pcap"       # 60-reply flood
open -a Wireshark "captures/wireshark_combined.pcap"           # both (for the I/O graph)
```

### 7b. Screenshots to take (macOS: ⌘⇧4, drag over the window)
| Open | Capture | Shows |
|------|---------|-------|
| `wireshark_attacker_spoofed.pcap` | packet list | Source column = victim `198.51.100.10` → broadcast (spoofing) |
| `wireshark_victim_flood.pcap` | packet list | 60 replies from `203.0.113.11`–`.16` |
| `wireshark_victim_flood.pcap` | **Statistics → Conversations → IPv4** | 6 conversations, 10 packets each, one-directional |
| `wireshark_combined.pcap` | **Statistics → I/O Graph** | Requests vs Replies over time (6×) |

For the **I/O Graph**, add two rows:
- Display filter `icmp.type==8`, name "Requests"
- Display filter `icmp.type==0`, name "Replies"
- Uncheck "Avg over Time" on both; set **Interval = 0.1 or 0.5 sec**; Style = Bar.

### 7c. Capture your own pcap (optional, to prove it's yours)
```bash
# Terminal 1
docker exec victim tcpdump -ni eth0 icmp -w /captures/my_capture.pcap -c 60
# Terminal 2
docker exec attacker python3 /scripts/smurf_attack.py --mode attack \
  --victim-ip 198.51.100.10 --broadcast-ip 203.0.113.255 --rate 5 --count 10
# then:  open -a Wireshark "captures/my_capture.pcap"
```

---

## 8. Test each defense individually

Each defense is enabled, the attack is re-run, and the victim's reply count is checked.
`run_experiment.sh defense` does all four automatically, but you can test them one at a time:

### Defense 1 — Disable directed-broadcast forwarding (router)
```bash
docker exec router bash /scripts/defense/disable_broadcast.sh enable
# run the attack (step 5); victim should receive 0
docker exec router bash /scripts/defense/disable_broadcast.sh disable   # revert
```

### Defense 2 — Ingress filtering / source validation (router)
```bash
docker exec router bash /scripts/defense/ingress_filter.sh enable
# attack -> 0 at victim (spoofed source dropped)
docker exec router bash /scripts/defense/ingress_filter.sh disable
```

### Defense 3 — Suppress broadcast echo (amplifiers)
The defense scripts are mounted on the router, not the amplifiers, so this defense is applied by
setting the sysctl directly on each amplifier (exactly what `run_experiment.sh` does):
```bash
# enable: amplifiers ignore broadcast Echo Requests
for h in amp-h1 amp-h2 amp-h3 amp-h4 amp-h5 amp-h6; do
  docker exec $h bash -c "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
done
# attack -> 0 at victim
# revert (re-enable amplification for later tests):
for h in amp-h1 amp-h2 amp-h3 amp-h4 amp-h5 amp-h6; do
  docker exec $h bash -c "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"
done
```

### Defense 4 — ICMP rate limiting (router)
```bash
docker exec router bash /scripts/defense/rate_limit.sh enable 5 10
# attack -> reduced (not zero) at victim
docker exec router bash /scripts/defense/rate_limit.sh disable
```

> After testing defenses manually, revert them (the `disable` commands above) before re-running
> a clean attack, or the attack will appear to fail.

---

## 9. Expected results (quick reference)

| Scenario | Replies at victim | Verdict |
|----------|-------------------|---------|
| Baseline | 0 | normal |
| **Attack (no defense)** | **60** (6×) | victim flooded |
| Defense 1 (broadcast disabled) | 0 | blocked |
| Defense 2 (ingress filtering) | 0 | blocked |
| Defense 3 (suppress echo) | 0 | blocked |
| Defense 4 (rate limiting) | reduced | mitigated |

Count replies at the victim from any capture:
```bash
docker exec victim tshark -r /captures/<file>.pcap -q -z endpoints,ip
```

---

## 10. Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `Address already in use` on `up` | Stale networks. `docker compose down` then `up -d`. |
| Attack shows **0** replies at victim | A defense is still enabled from a previous test. Run all four `*.sh … disable` (and re-enable `bc_forwarding`): `docker exec router bash -c 'for d in /proc/sys/net/ipv4/conf/*/bc_forwarding; do echo 1 > "$d"; done'` and `for h in amp-h1 amp-h2 amp-h3 amp-h4 amp-h5 amp-h6; do docker exec $h bash -c "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"; done` |
| `run_experiment.sh` exits early | Make sure all 9 containers are Up (`docker compose ps`). |
| Container can reach the Internet | The router should carry no default route; recreate it: `docker compose up -d --build router`. |
| No plots in `results/` | Run `./run_experiment.sh analyze` after an attack. |

---

## 11. Tear down

```bash
docker compose down          # stop and remove containers + networks
docker compose down --rmi all --volumes   # also remove images (full clean)
```

Generated `captures/` and `results/` are recreated on the next run and are git-ignored.
