import time
from collections import deque
from threading import Lock


class SlidingWindowDetector:
    """
    Tracks per-IP and global request rates using deque-based sliding windows.
    Each window covers the last 60 seconds.
    """

    def __init__(self, config: dict, baseline_tracker):
        self.window_seconds = config.get("window_seconds", 60)
        self.zscore_threshold = config.get("zscore_threshold", 3.0)
        self.rate_multiplier = config.get("rate_multiplier_threshold", 5.0)
        self.error_surge_multiplier = config.get("error_surge_multiplier", 3.0)
        self.baseline = baseline_tracker

        # Per-IP windows: dict of ip -> deque of timestamps
        # Each timestamp = one request from that IP
        # We evict timestamps older than window_seconds
        self.ip_windows = {}

        # Global window: deque of all request timestamps
        self.global_window = deque()

        # Per-IP error tracking: dict of ip -> deque of error timestamps
        self.ip_error_windows = {}

        self.lock = Lock()

    def record(self, entry: dict) -> dict:
        """
        Record a new request and check for anomalies.
        Returns a dict describing any anomaly found, or empty dict if normal.
        """
        ip = entry["source_ip"]
        now = entry["time"]
        status = entry["status"]
        cutoff = now - self.window_seconds

        with self.lock:
            # --- Update global window ---
            self.global_window.append(now)
            # Evict timestamps older than the window from the left
            while self.global_window and self.global_window[0] < cutoff:
                self.global_window.popleft()

            # --- Update per-IP window ---
            if ip not in self.ip_windows:
                self.ip_windows[ip] = deque()
            self.ip_windows[ip].append(now)
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()

            # --- Track errors per IP ---
            if status >= 400:
                if ip not in self.ip_error_windows:
                    self.ip_error_windows[ip] = deque()
                self.ip_error_windows[ip].append(now)
                while (self.ip_error_windows[ip] and
                       self.ip_error_windows[ip][0] < cutoff):
                    self.ip_error_windows[ip].popleft()

            # --- Calculate current rates ---
            ip_rate = len(self.ip_windows[ip])
            global_rate = len(self.global_window)
            ip_error_rate = len(self.ip_error_windows.get(ip, []))

            mean, stddev = self.baseline.get_baseline()

            # --- Check for error surge ---
            # If IP's error rate is 3x the baseline, tighten thresholds
            error_baseline = max(mean * 0.1, 1.0)
            tightened = ip_error_rate > (error_baseline * self.error_surge_multiplier)
            effective_zscore_threshold = (
                self.zscore_threshold * 0.5 if tightened
                else self.zscore_threshold
            )
            effective_multiplier = (
                self.rate_multiplier * 0.5 if tightened
                else self.rate_multiplier
            )

            # --- Z-score calculation ---
            # z = (current_rate - mean) / stddev
            # z > threshold means statistically anomalous
            ip_zscore = (ip_rate - mean) / stddev
            global_zscore = (global_rate - mean) / stddev

            # --- Per-IP anomaly check ---
            ip_anomaly = (
                ip_zscore > effective_zscore_threshold or
                ip_rate > mean * effective_multiplier
            )

            # --- Global anomaly check ---
            global_anomaly = (
                global_zscore > self.zscore_threshold or
                global_rate > mean * self.rate_multiplier
            )

            if ip_anomaly:
                return {
                    "type": "ip",
                    "ip": ip,
                    "ip_rate": ip_rate,
                    "global_rate": global_rate,
                    "mean": mean,
                    "stddev": stddev,
                    "zscore": ip_zscore,
                    "tightened": tightened,
                    "condition": (
                        f"zscore={ip_zscore:.2f} > {effective_zscore_threshold}"
                        if ip_zscore > effective_zscore_threshold
                        else f"rate={ip_rate} > {mean * effective_multiplier:.1f} (5x mean)"
                    )
                }

            if global_anomaly:
                return {
                    "type": "global",
                    "global_rate": global_rate,
                    "mean": mean,
                    "stddev": stddev,
                    "zscore": global_zscore,
                    "condition": (
                        f"global zscore={global_zscore:.2f} > {self.zscore_threshold}"
                        if global_zscore > self.zscore_threshold
                        else f"global rate={global_rate} > {mean * self.rate_multiplier:.1f}"
                    )
                }

            return {}

    def get_top_ips(self, n=10):
        """Return top N IPs by request count in current window."""
        with self.lock:
            return sorted(
                [(ip, len(window)) for ip, window in self.ip_windows.items()],
                key=lambda x: x[1],
                reverse=True
            )[:n]

    def get_global_rate(self):
        """Return current global requests per second."""
        with self.lock:
            return len(self.global_window)
