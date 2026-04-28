import time
import threading
import psutil
from http.server import HTTPServer, BaseHTTPRequestHandler
import json


class DashboardHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suppress default HTTP server logs

    def do_GET(self):
        if self.path == "/metrics":
            self._serve_metrics()
        elif self.path == "/" or self.path == "/dashboard":
            self._serve_html()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_metrics(self):
        """Return JSON metrics for the dashboard to poll."""
        state = self.server.state
        mean, stddev = state["baseline"].get_baseline()

        metrics = {
            "uptime_seconds": int(time.time() - state["start_time"]),
            "global_req_per_60s": state["detector"].get_global_rate(),
            "top_ips": state["detector"].get_top_ips(10),
            "banned_ips": list(state["blocker"].get_banned().keys()),
            "banned_details": state["blocker"].get_banned(),
            "effective_mean": round(mean, 3),
            "effective_stddev": round(stddev, 3),
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(metrics).encode())

    def _serve_html(self):
        html = """<!DOCTYPE html>
<html>
<head>
  <title>HNG Anomaly Detector</title>
  <meta charset="UTF-8">
  <style>
    body { font-family: monospace; background: #0d1117; color: #c9d1d9;
           margin: 0; padding: 20px; }
    h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;
            margin-bottom: 20px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            padding: 16px; }
    .card h3 { margin: 0 0 8px 0; color: #8b949e; font-size: 12px;
               text-transform: uppercase; }
    .card .value { font-size: 28px; font-weight: bold; color: #58a6ff; }
    .banned { color: #f85149; }
    .healthy { color: #3fb950; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; padding: 8px; background: #161b22;
         color: #8b949e; font-size: 12px; }
    td { padding: 8px; border-bottom: 1px solid #21262d; }
    .section { background: #161b22; border: 1px solid #30363d;
               border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    #status { color: #3fb950; font-size: 12px; }
  </style>
</head>
<body>
  <h1>🛡 HNG Anomaly Detection Engine</h1>
  <span id="status">● Live</span>
  <span id="timestamp" style="float:right;color:#8b949e;font-size:12px;"></span>

  <div class="grid">
    <div class="card">
      <h3>Global Req / 60s</h3>
      <div class="value" id="global_rate">-</div>
    </div>
    <div class="card">
      <h3>Baseline Mean</h3>
      <div class="value" id="mean">-</div>
    </div>
    <div class="card">
      <h3>Baseline StdDev</h3>
      <div class="value" id="stddev">-</div>
    </div>
    <div class="card">
      <h3>Banned IPs</h3>
      <div class="value banned" id="banned_count">-</div>
    </div>
    <div class="card">
      <h3>CPU Usage</h3>
      <div class="value" id="cpu">-</div>
    </div>
    <div class="card">
      <h3>Memory Usage</h3>
      <div class="value" id="memory">-</div>
    </div>
  </div>

  <div class="section">
    <h3>Top 10 Source IPs (last 60s)</h3>
    <table>
      <thead><tr><th>IP</th><th>Requests</th><th>Status</th></tr></thead>
      <tbody id="top_ips"></tbody>
    </table>
  </div>

  <div class="section">
    <h3>Currently Banned IPs</h3>
    <table>
      <thead>
        <tr><th>IP</th><th>Condition</th><th>Duration</th><th>Banned At</th></tr>
      </thead>
      <tbody id="banned_table"></tbody>
    </table>
  </div>

  <script>
    const REFRESH = 3000;

    async function fetchMetrics() {
      try {
        const r = await fetch('/metrics');
        const d = await r.json();

        document.getElementById('global_rate').textContent = d.global_req_per_60s;
        document.getElementById('mean').textContent = d.effective_mean.toFixed(2);
        document.getElementById('stddev').textContent = d.effective_stddev.toFixed(2);
        document.getElementById('banned_count').textContent = d.banned_ips.length;
        document.getElementById('cpu').textContent = d.cpu_percent.toFixed(1) + '%';
        document.getElementById('memory').textContent = d.memory_percent.toFixed(1) + '%';
        document.getElementById('timestamp').textContent = d.timestamp;

        const bannedSet = new Set(d.banned_ips);
        const topBody = document.getElementById('top_ips');
        topBody.innerHTML = d.top_ips.map(([ip, count]) =>
          `<tr>
            <td>${ip}</td>
            <td>${count}</td>
            <td>${bannedSet.has(ip)
              ? '<span style="color:#f85149">BANNED</span>'
              : '<span style="color:#3fb950">OK</span>'}</td>
          </tr>`
        ).join('');

        const bannedBody = document.getElementById('banned_table');
        bannedBody.innerHTML = Object.entries(d.banned_details).map(([ip, info]) => {
          const bannedAt = new Date(info.ban_time * 1000).toUTCString();
          const dur = info.duration_minutes ? info.duration_minutes + 'min' : 'permanent';
          return `<tr>
            <td style="color:#f85149">${ip}</td>
            <td>${info.condition}</td>
            <td>${dur}</td>
            <td>${bannedAt}</td>
          </tr>`;
        }).join('') || '<tr><td colspan="4" style="color:#3fb950">No banned IPs</td></tr>';

      } catch(e) {
        document.getElementById('status').textContent = '● Reconnecting...';
        document.getElementById('status').style.color = '#f85149';
      }
    }

    fetchMetrics();
    setInterval(fetchMetrics, REFRESH);
  </script>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())


class Dashboard:
    def __init__(self, config: dict, state: dict):
        self.port = config.get("dashboard_port", 8080)
        self.state = state

    def start(self):
        server = HTTPServer(("0.0.0.0", self.port), DashboardHandler)
        server.state = self.state
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f"Dashboard running on port {self.port}")
