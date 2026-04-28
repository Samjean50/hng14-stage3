import time
import math
from collections import deque
from threading import Lock


class BaselineTracker:
    """
    Tracks per-second request counts over a rolling 30-minute window.
    Recalculates mean and stddev every 60 seconds.
    Maintains per-hour slots — prefers current hour's data when available.
    """

    def __init__(self, config: dict):
        self.window_minutes = config.get("baseline_window_minutes", 30)
        self.recalc_interval = config.get("baseline_recalc_interval", 60)
        self.floor_mean = config.get("baseline_floor_mean", 1.0)
        self.floor_stddev = config.get("baseline_floor_stddev", 0.5)

        # How many seconds of history to keep
        self.max_seconds = self.window_minutes * 60

        # Deque of (timestamp, count) tuples
        # Each entry = one second bucket
        # deque with maxlen automatically drops old entries
        self.per_second_counts = deque()

        # Current second accumulator
        self.current_second = int(time.time())
        self.current_count = 0

        # Calculated baseline values
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev

        # Per-hour slots — dict of hour_key -> list of per-second counts
        # hour_key = "2026-04-23-14" (year-month-day-hour)
        self.hourly_slots = {}

        self.last_recalc = time.time()
        self.lock = Lock()

    def record_request(self):
        """Called for every incoming request."""
        with self.lock:
            now = int(time.time())

            if now == self.current_second:
                # Same second — increment counter
                self.current_count += 1
            else:
                # New second — save the completed second's count
                self._save_second(self.current_second, self.current_count)
                # Start new second
                self.current_second = now
                self.current_count = 1

        # Recalculate baseline if interval has passed
        if time.time() - self.last_recalc >= self.recalc_interval:
            self.recalculate()

    def _save_second(self, second: int, count: int):
        """
        Save a completed second's count to the deque and hourly slots.
        Evict entries older than the window.
        """
        cutoff = time.time() - self.max_seconds

        # Add to rolling deque
        self.per_second_counts.append((second, count))

        # Evict old entries from the left
        # deque acts as a FIFO queue — oldest entries are on the left
        while self.per_second_counts and self.per_second_counts[0][0] < cutoff:
            self.per_second_counts.popleft()

        # Add to per-hour slot
        hour_key = time.strftime("%Y-%m-%d-%H", time.localtime(second))
        if hour_key not in self.hourly_slots:
            self.hourly_slots[hour_key] = []
        self.hourly_slots[hour_key].append(count)

        # Clean up hourly slots older than 2 hours
        current_hour = time.strftime("%Y-%m-%d-%H")
        keys_to_delete = []
        for key in self.hourly_slots:
            if key < current_hour:
                keys_to_delete.append(key)
        for key in keys_to_delete:
            del self.hourly_slots[key]

    def recalculate(self):
        """
        Recalculate mean and stddev.
        Prefers current hour's data if it has enough samples (>= 120 seconds).
        Falls back to full 30-minute window otherwise.
        """
        with self.lock:
            current_hour = time.strftime("%Y-%m-%d-%H")
            current_hour_data = self.hourly_slots.get(current_hour, [])

            # Use current hour if we have at least 2 minutes of data
            if len(current_hour_data) >= 120:
                counts = current_hour_data
            else:
                # Fall back to full rolling window
                counts = [count for _, count in self.per_second_counts]

            if len(counts) < 10:
                # Not enough data yet — use floor values
                self.effective_mean = self.floor_mean
                self.effective_stddev = self.floor_stddev
            else:
                mean = sum(counts) / len(counts)
                variance = sum((c - mean) ** 2 for c in counts) / len(counts)
                stddev = math.sqrt(variance)

                # Apply floor values — never let mean/stddev go to zero
                # Division by zero in z-score calculation would crash the daemon
                self.effective_mean = max(mean, self.floor_mean)
                self.effective_stddev = max(stddev, self.floor_stddev)

            self.last_recalc = time.time()

        return self.effective_mean, self.effective_stddev

    def get_baseline(self):
        """Return current effective mean and stddev."""
        return self.effective_mean, self.effective_stddev
