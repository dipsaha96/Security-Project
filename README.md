# ICMP Smurf Attack — Security Lab Project

> **CSE 406 — Computer Security**
> Demonstration of the classic ICMP Smurf reflection/amplification DoS attack
> in an isolated Docker laboratory environment.

---

## ⚠️ Safety Notice

All experiments run inside **isolated Docker networks with no external routing**.
IP addresses use documentation-only ranges (RFC 5737). This project is for
**educational purposes only** and must never be used against production networks.

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- Python 3.x (on host, for local analysis — optional)

### 1. Build and start the lab

```bash
docker compose build
docker compose up -d
```

This creates 9 containers across 3 isolated networks:

| Container | IP | Role |
|-----------|-----|------|
| `attacker` | 10.0.0.9 | Generates spoofed ICMP traffic |
| `router` | 10.0.0.1 / 203.0.113.254 / 198.51.100.1 | Multi-homed border router |
| `amp-h1`–`amp-h6` | 203.0.113.1–.6 | Amplifier/bounce hosts |
| `victim` | 198.51.100.10 | Target of reflected replies |

### 2. Run the complete experiment

```bash
chmod +x run_experiment.sh
./run_experiment.sh all
```

Or run individual phases:

```bash
./run_experiment.sh baseline    # Phase 1: Normal ICMP
./run_experiment.sh fanout      # Phase 2: Broadcast fan-out
./run_experiment.sh attack      # Phase 3: Smurf attack
./run_experiment.sh defense     # Phase 4: Defense tests
./run_experiment.sh analyze     # Phase 5: Analysis & plots
```

### 3. Interactive usage

```bash
# Shell into the attacker
docker exec -it attacker bash

# Run the attack manually
python3 /scripts/smurf_attack.py --rate 2 --count 10

# Shell into the victim and monitor
docker exec -it victim bash
python3 /scripts/monitor.py --threshold 5 --window 5

# Capture traffic on victim
bash /scripts/capture.sh attack 30
```

### 4. Cleanup

```bash
docker compose down
```

---

## Project Structure

```
├── docker-compose.yml           # Lab topology (3 networks, 9 containers)
├── Dockerfile.attacker          # Attacker with Python/Scapy
├── Dockerfile.router            # Multi-homed router
├── Dockerfile.amplifier         # Amplifier hosts (broadcast echo enabled)
├── Dockerfile.victim            # Victim with monitoring tools
├── configs/
│   └── router_setup.sh          # Router initialization
├── scripts/
│   ├── attacker/
│   │   └── smurf_attack.py      # Traffic generator (Scapy)
│   ├── victim/
│   │   ├── capture.sh           # tcpdump wrapper
│   │   └── monitor.py           # Real-time detection system
│   ├── defense/
│   │   ├── disable_broadcast.sh # Defense 1: Block directed broadcast
│   │   ├── ingress_filter.sh    # Defense 2: Source validation (RFC 2827)
│   │   ├── suppress_echo.sh     # Defense 3: Ignore broadcast echo
│   │   └── rate_limit.sh        # Defense 4: ICMP rate limiting
│   └── analysis/
│       ├── analyze_pcap.py      # Pcap parser & metrics
│       └── plot_results.py      # Chart generation
├── run_experiment.sh            # Master experiment orchestrator
├── captures/                    # .pcap files (generated)
└── results/                     # Charts & analysis output (generated)
```

---

## Attack Methodology (Design Report §5)

```
Phase 1: Source Spoofing    →  Attacker sets src=Victim IP
Phase 2: Directed Broadcast →  dst=203.0.113.255 (amplifier subnet)
Phase 3: Reflection         →  N hosts send Echo Replies to Victim
Phase 4: Repetition         →  Sustained amplified traffic
```

**Amplification**: If N=6 hosts respond, victim receives ≈6× the attacker's
packet rate. Theoretical: `R_victim ≈ N × R_attacker`.

---

## Defenses Implemented (Design Report §10)

| # | Defense | Where | Breaks |
|---|---------|-------|--------|
| 1 | Disable directed-broadcast forwarding | Router | Broadcast fan-out |
| 2 | Ingress filtering (BCP 38/RFC 2827) | Router | Source spoofing |
| 3 | Suppress broadcast echo response | Amplifier hosts | Reflection |
| 4 | ICMP rate limiting | Router | Flood impact |

---

## Success Criteria (Design Report §9.2)

- [x] ① Normal one-to-one ICMP exchange verified
- [x] ② Broadcast request reaches configured amplifier hosts
- [x] ③ Victim receives reflected Echo Replies from multiple responders
- [x] ④ Amplification consistent with number of responding hosts
- [x] ⑤ Defenses break the reflection path
