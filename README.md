# HNG Stage 3 — Anomaly Detection & DDoS Protection Engine

A production-grade anomaly detection daemon built for HNG Internship Stage 3.
Monitors real-time HTTP traffic to a Nextcloud instance, learns normal traffic
patterns, and automatically blocks malicious IPs using iptables.

## Live Deployment

| Service | URL |
|---------|-----|
| Metrics Dashboard | http://dashboard.samjean.mooo.com |
| Server IP | 3.235.239.150 |
| Nextcloud | http://3.235.239.150 (IP only) |

## Architecture
Internet Traffic
↓
Nginx (port 80)

Reverse proxy in front of Nextcloud
Writes JSON access logs to shared Docker volume (HNG-nginx-logs)
↓
Nextcloud (kefaslungu/hng-nextcloud)
The protected application
Accessible by IP only
↓
Detector Daemon (Python)
Tails /var/log/nginx/hng-access.log in real time
Sliding window tracking per IP and globally
Rolling baseline learning from 30 minutes of traffic
Z-score anomaly detection
iptables banning with auto-unban backoff
Live dashboard on port 8080


## Language Choice

Python — chosen for its readable threading model, deque from the collections
module which is purpose-built for sliding windows, and the math module for
z-score calculations without needing external libraries. The entire detection
logic is implemented from scratch with no rate-limiting libraries.

## How the Sliding Window Works

The sliding window tracks request timestamps using Python's `collections.deque`.

Every incoming request appends its Unix timestamp to two deques:
- One per-IP deque tracking that specific IP's requests
- One global deque tracking all requests

On every new request, old timestamps are evicted from the left of the deque:

```python
cutoff = now - window_seconds  # 60 seconds ago
while self.global_window and self.global_window[0] < cutoff:
    self.global_window.popleft()
```

The length of the deque at any point equals the number of requests in the
last 60 seconds. No counters, no resets — just timestamps being added on
the right and evicted from the left as they age out.

Example:
- Request arrives at t=100 → deque: [100]
- Request arrives at t=110 → deque: [100, 110]
- Request arrives at t=165 → deque: [100, 110, 165]
- Eviction runs → t=100 is older than 165-60=105 → deque: [110, 165]
- Window length = 2 requests in last 60 seconds

## How the Baseline Works

The baseline tracks per-second request counts over a rolling 30-minute window.

Every second, the number of requests that arrived in that second is stored
as a bucket. After 30 minutes, 1800 buckets exist. Mean and standard deviation
are calculated from those buckets every 60 seconds.

Per-hour slots are maintained separately. If the current hour has at least
120 seconds of data, its data is preferred over the full 30-minute window —
this means the baseline adapts to time-of-day traffic patterns automatically.

Floor values prevent division by zero on cold start:
- `effective_mean` minimum: 1.0
- `effective_stddev` minimum: 0.5

Recalculation interval: every 60 seconds
Window size: 30 minutes (1800 seconds)

## How Detection Works

Two conditions trigger an anomaly — whichever fires first:

**Z-score threshold:**
z = (current_rate - baseline_mean) / baseline_stddev
if z > 3.0 → anomaly
A z-score above 3.0 means the current rate is 3 standard deviations above
normal. Statistically this occurs less than 0.3% of the time in normal traffic.

**Rate multiplier threshold:**
if current_rate > baseline_mean * 5.0 → anomaly
Catches sudden bursts even when the baseline stddev is small.

**Error surge tightening:**
If an IP's 4xx/5xx error rate is 3x the baseline error rate, both thresholds
are halved automatically — making detection more sensitive for IPs already
showing suspicious behaviour.

**Per-IP anomaly** → iptables DROP rule + Slack alert within 10 seconds
**Global anomaly** → Slack alert only (no single IP to block)

## How iptables Blocking Works

When an IP is flagged as anomalous the daemon runs:

```bash
iptables -I INPUT 1 -s <IP> -j DROP
```

- `-I INPUT 1` inserts the rule at the top of the INPUT chain (highest priority)
- `-s <IP>` matches packets from that source IP
- `-j DROP` silently discards all packets — the attacker gets no response

To unban:
```bash
iptables -D INPUT -s <IP> -j DROP
```

Auto-unban backoff schedule: 10 min → 30 min → 2 hours → permanent

## Repository Structure
detector/
main.py          — entry point, wires all components together
monitor.py       — tails nginx log file, parses JSON lines
baseline.py      — rolling 30-minute baseline with per-hour slots
detector.py      — sliding window detection, z-score calculation
blocker.py       — iptables ban/unban management
unbanner.py      — background thread for auto-unban on schedule
notifier.py      — Slack webhook alerts
dashboard.py     — HTTP server serving live metrics UI
audit.py         — structured audit log writer
config.yaml      — all thresholds and configuration
requirements.txt — Python dependencies
nginx/
nginx.conf       — reverse proxy config with JSON logging
docs/
architecture.png
screenshots/
Tool-running.png
Ban-slack.png
Unban-slack.png
Global-alert-slack.png
Iptables-banned.png
Audit-log.png
Baseline-graph.png
README.md
docker-compose.yml

## Prerequisites

- Linux VPS — minimum 2 vCPU, 2GB RAM (AWS t3.small or equivalent)
- Docker 24+
- Docker Compose v2+
- Port 80 and 8080 open in firewall/security group
- A domain or subdomain pointing to your server IP

## Setup from a Fresh VPS

**Step 1 — Install Docker**
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
```

**Step 2 — Clone the repository**
```bash
git clone https://github.com/Samjean50/hng14-stage3-devops.git
cd hng14-stage3-devops
```

**Step 3 — Configure environment**
```bash
cp .env.example .env
nano .env
```

Set your Slack webhook URL:
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

**Step 4 — Start the stack**
```bash
docker compose up -d --build
```

**Step 5 — Verify all containers are running**
```bash
docker compose ps
```

Expected output:
NAME                      STATUS          PORTS
hng-stage3-detector-1     Up              0.0.0.0:8080->8080/tcp
hng-stage3-nginx-1        Up              0.0.0.0:80->80/tcp
hng-stage3-nextcloud-1    Up              80/tcp

**Step 6 — Verify detector is working**
```bash
docker compose logs detector --tail=20
```

Expected output:
Starting HNG Anomaly Detection Engine...
Dashboard running on port 8080
Tailing log: /var/log/nginx/hng-access.log
Dashboard: http://0.0.0.0:8080
[2026-04-28 18:35:28 UTC] BASELINE_RECALC - | mean=1.000 stddev=0.500 ...

**Step 7 — Access the dashboard**

Open in browser: `http://YOUR_SERVER_IP:8080`

Or if you have a subdomain configured: `http://dashboard.yourdomain.com`

## Testing Detection

Send a burst of requests to trigger a ban:
```bash
for i in $(seq 1 100); do curl -s http://YOUR_SERVER_IP > /dev/null; done
```

Then check:
```bash
# Detector logs
docker compose logs detector --tail=10

# Active iptables rules
docker exec hng-stage3-detector-1 iptables -L INPUT -n

# Metrics
curl -s http://YOUR_SERVER_IP:8080/metrics | python3 -m json.tool

# Audit log
docker exec hng-stage3-detector-1 cat /var/log/detector-audit.log
```

## Configuration

All thresholds are in `detector/config.yaml` — nothing is hardcoded:

```yaml
window_seconds: 60              # sliding window duration
baseline_window_minutes: 30     # rolling baseline window
baseline_recalc_interval: 60    # recalculate every 60 seconds
zscore_threshold: 3.0           # z-score anomaly threshold
rate_multiplier_threshold: 5.0  # rate multiplier threshold
error_surge_multiplier: 3.0     # error surge detection multiplier
unban_schedule: [10, 30, 120]   # auto-unban backoff in minutes
dashboard_port: 8080            # dashboard port
baseline_floor_mean: 1.0        # minimum baseline mean
baseline_floor_stddev: 0.5      # minimum baseline stddev
allowlist:                      # IPs that are never banned##
  - "127.0.0.1"
  - "172.31.72.252"
```

## Dashboard

The live dashboard refreshes every 3 seconds and shows:

- Global requests per 60 seconds
- Effective baseline mean and stddev
- Number of currently banned IPs
- CPU and memory usage
- Top 10 source IPs in the current window
- Banned IP details with condition, duration, and ban time

## Audit Log Format

Every ban, unban, and baseline recalculation is written to
`/var/log/detector-audit.log`:
[timestamp] ACTION ip | condition | rate=X | baseline=X | duration=X

* Examples:
[2026-04-28 18:36:14 UTC] BAN 1.2.3.4 | zscore=4.00 > 3.0 | rate=3.00 | baseline=1.00 | duration=10min
[2026-04-28 18:46:28 UTC] UNBAN 1.2.3.4 | schedule_expiry | rate=3.00 | baseline=1.00 | duration=released
[2026-04-28 18:35:28 UTC] BASELINE_RECALC - | mean=1.000 stddev=0.500 | rate=1.00 | baseline=1.00 | duration=-

## Slack Alerts

Alerts are sent for:
- **IP ban** — condition fired, current rate, baseline, ban duration
- **IP unban** — original condition, time served
- **Global anomaly** — global rate spike without a single IP to block

Configure by setting `SLACK_WEBHOOK_URL` in your `.env` file.

## GitHub Repository

https://github.com/Samjean50/hng14-stage3-devops

## Blog Post
https://medium.com/@samson.bakare50/how-i-built-a-real-time-ddos-detection-engine-from-scratch-e30b83725cca
