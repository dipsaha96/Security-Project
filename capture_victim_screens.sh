#!/bin/bash
# capture_victim_screens.sh
# Capture the VICTIM's terminal evidence during a Smurf attack and render it
# into polished terminal-style PNG screenshots (the ones used in FINAL_REPORT).
#
# Produces in ./screenshots/:
#   victim_1_baseline.png   victim idle (before attack)
#   victim_2_attack.png     tcpdump flood: 60 replies from 6 amplifiers
#   victim_3_ids.png        monitor.py "SMURF DETECTED" alert
#
# Requirements: the lab running (docker compose up -d), Python 3, and
# Google Chrome (used headless to render the images).
#
# Usage:   ./capture_victim_screens.sh
set -e

VICTIM_IP="198.51.100.10"
BROADCAST_IP="203.0.113.255"
COUNT=10
RATE=5
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
WORK="$(mktemp -d)"
mkdir -p screenshots

echo "[*] Resetting attack state (defenses off, amplifiers answer broadcast)..."
docker exec router bash -c 'for d in /proc/sys/net/ipv4/conf/*/bc_forwarding; do echo 1 > "$d"; done' 2>/dev/null || true
docker exec router bash /scripts/defense/disable_broadcast.sh disable >/dev/null 2>&1 || true
docker exec router bash /scripts/defense/ingress_filter.sh   disable >/dev/null 2>&1 || true
docker exec router bash /scripts/defense/rate_limit.sh       disable >/dev/null 2>&1 || true
for h in amp-h1 amp-h2 amp-h3 amp-h4 amp-h5 amp-h6; do
  docker exec "$h" bash -c "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts" 2>/dev/null || true
done

# ---- 1. Baseline (quiet): victim watches, no attack -------------------------
echo "[*] Capturing baseline (quiet) on victim..."
docker exec victim sh -c 'timeout 4 tcpdump -ni eth0 icmp 2>/tmp/base.err; cat /tmp/base.err' >/dev/null 2>&1 || true
docker exec victim sh -c 'cat /tmp/base.err' > "$WORK/baseline.txt"

# ---- 2. Under attack: tcpdump flood (exactly 60 echo replies) ---------------
echo "[*] Capturing attack flood on victim..."
docker exec -d victim sh -c 'tcpdump -ni eth0 "icmp[icmptype]=0" -c 60 > /tmp/vf.txt 2> /tmp/vf.err'
sleep 2
docker exec attacker python3 /scripts/smurf_attack.py --mode attack \
  --victim-ip "$VICTIM_IP" --broadcast-ip "$BROADCAST_IP" --rate "$RATE" --count "$COUNT" >/dev/null 2>&1
sleep 3
docker exec victim sh -c 'head -12 /tmp/vf.txt' > "$WORK/flood_body.txt"
docker exec victim sh -c 'cat /tmp/vf.err'      > "$WORK/flood_stats.txt"

# ---- 3. Intrusion detection: monitor.py raises SMURF DETECTED ---------------
echo "[*] Capturing intrusion-detection alert on victim..."
docker exec -d victim sh -c 'python3 /scripts/monitor.py --threshold 5 --sources-threshold 3 --window 5 --duration 12 --log /tmp/alerts.log > /tmp/mon.txt 2>&1'
sleep 2
docker exec attacker python3 /scripts/smurf_attack.py --mode attack \
  --victim-ip "$VICTIM_IP" --broadcast-ip "$BROADCAST_IP" --rate "$RATE" --count "$COUNT" >/dev/null 2>&1
sleep 6
docker exec victim sh -c 'cat /tmp/mon.txt' | sed $'s/\x1b\\[[0-9;]*m//g' \
  | grep -E "DETECTION|threshold|Listening|NORMAL|ATTACK|CRITICAL|SMURF|REFLECTION" | head -18 > "$WORK/monitor.txt"

# ---- 4. Render the captured text into terminal-style PNGs --------------------
echo "[*] Rendering terminal screenshots with headless Chrome..."
WORK="$WORK" CHROME="$CHROME" python3 - << 'PYEOF'
import html, subprocess, os, re
vs=os.environ["WORK"]; CHROME=os.environ["CHROME"]
def rd(f):
    p=os.path.join(vs,f); return open(p).read() if os.path.exists(p) else ""
CSS="""body{margin:0;background:#0d0d14;font-family:'SF Mono',Menlo,Consolas,monospace;}
.win{width:940px;background:#1b1b28;border-radius:10px;overflow:hidden;}
.bar{background:#2b2b3c;padding:9px 14px;display:flex;align-items:center;gap:8px;}
.dot{width:12px;height:12px;border-radius:50%;} .r{background:#ff5f56;}.y{background:#ffbd2e;}.g{background:#27c93f;}
.title{color:#aaa;font-size:12px;margin-left:10px;}
.body{padding:16px 18px;color:#d6d6e0;font-size:12.5px;line-height:1.5;white-space:pre-wrap;}
.prompt{color:#4ec9b0;}.cmd{color:#dcdcaa;}.src{color:#569cd6;}.dst{color:#ce9178;}.dim{color:#7a7a8c;}
.ok{color:#4ec93f;font-weight:bold;}.warn{color:#ffbd2e;font-weight:bold;}.crit{color:#ff5f56;font-weight:bold;}
.note{color:#8a8aff;font-style:italic;}"""
def render(name,title,body,h):
    doc=f"<!DOCTYPE html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body><div class='win'><div class='bar'><span class='dot r'></span><span class='dot y'></span><span class='dot g'></span><span class='title'>{title}</span></div><div class='body'>{body}</div></div></body></html>"
    hp=f"{vs}/{name}.html"; open(hp,"w").write(doc)
    png=os.path.abspath(f"screenshots/{name}.png")
    subprocess.run([CHROME,"--headless","--disable-gpu","--hide-scrollbars",
        "--force-device-scale-factor=2",f"--screenshot={png}",f"--window-size=940,{h}",hp],capture_output=True)
    # auto-crop trailing background using pymupdf if available
    try:
        import pymupdf
        doc=pymupdf.open(png); pg=doc[0]; pm=pg.get_pixmap()
        w,ht,n,s=pm.width,pm.height,pm.n,pm.samples
        def bgrow(y,bg):
            return all(abs(s[(y*w+x)*n+c]-bg[c])<=6 for x in range(0,w,max(1,w//50)) for c in range(3))
        i0=(2*w+2)*n; bg=(s[i0],s[i0+1],s[i0+2])
        b=ht-1
        while b>0 and bgrow(b,bg): b-=1
        t=0
        while t<ht and bgrow(t,bg): t+=1
        t=max(0,t-22); b=min(ht-1,b+22)
        pg.get_pixmap(clip=pymupdf.Rect(0,t,w,b+1)).save(png)
    except Exception: pass
    print("  wrote", png)
def color(line):
    line=html.escape(line)
    line=re.sub(r'(203\.0\.113\.1[1-6])',r'<span class="src">\1</span>',line)
    line=line.replace('198.51.100.10','<span class="dst">198.51.100.10</span>')
    return line.replace('ICMP echo reply','<span class="dim">ICMP echo reply</span>')
# screen 1
b="<span class='prompt'>root@victim:/scripts#</span> <span class='cmd'>tcpdump -ni eth0 icmp</span>\n"
for l in rd("baseline.txt").strip().splitlines():
    l=html.escape(l); b+=(f"<span class='ok'>{l}</span>" if "0 packets captured" in l else l)+"\n"
b+="<span class='prompt'>root@victim:/scripts#</span> <span class='note'>. Victim is idle - no unsolicited ICMP.</span>"
render("victim_1_baseline","victim - normal operation (before attack)",b,340)
# screen 2
b="<span class='prompt'>root@victim:/scripts#</span> <span class='cmd'>tcpdump -ni eth0 'icmp[icmptype]=0'</span>\n"
for l in rd("flood_body.txt").strip().splitlines(): b+=color(l)+"\n"
b+="<span class='dim'>        ... (flood continues) ...</span>\n"
for l in rd("flood_stats.txt").strip().splitlines():
    l=html.escape(l); b+=(f"<span class='crit'>{l}</span>" if "60 packets captured" in l else l)+"\n"
b+="<span class='prompt'>root@victim:/scripts#</span> <span class='note'>. 10 spoofed requests -> 60 replies from 6 amplifiers = 6x amplification</span>"
render("victim_2_attack","victim - under Smurf attack (60 replies received)",b,620)
# screen 3
b="<span class='prompt'>root@victim:/scripts#</span> <span class='cmd'>python3 monitor.py --threshold 5 --sources-threshold 3 --window 5</span>\n"
for l in rd("monitor.txt").strip().splitlines():
    e=html.escape(l)
    if any(k in l for k in ("SMURF DETECTED","REFLECTION PATTERN","CRITICAL")): e=f"<span class='crit'>{e}</span>"
    elif "ATTACK" in l: e=f"<span class='warn'>{e}</span>"
    elif "NORMAL" in l: e=f"<span class='ok'>{e}</span>"
    b+=e+"\n"
render("victim_3_ids","victim - intrusion detection alert (monitor.py)",b,640)
PYEOF

rm -rf "$WORK"
echo ""
echo "[+] Done. Screenshots saved in ./screenshots/"
ls -1 screenshots/*.png
