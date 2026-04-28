import time
import json
import os
from datetime import datetime


def tail_log(log_path: str):
    """
    Generator that yields parsed log lines as they are written.
    Works like 'tail -f' — opens file, seeks to end,
    then yields new lines as nginx writes them.
    """
    # Wait for the log file to exist
    # Nginx might not have written anything yet on startup
    while not os.path.exists(log_path):
        print(f"Waiting for log file: {log_path}")
        time.sleep(2)

    with open(log_path, 'r') as f:
        # Seek to end of file — we only want NEW lines
        # not historical lines from before daemon started
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                # No new line yet — wait briefly and try again
                # 0.1s sleep means we check 10 times per second
                # fast enough to catch bursts, light enough on CPU
                time.sleep(0.1)
                continue

            line = line.strip()
            if not line:
                continue

            # Parse the JSON log line
            try:
                entry = json.loads(line)

                # Normalise the source IP
                # X-Forwarded-For can be a comma-separated list
                # e.g. "1.2.3.4, 10.0.0.1" — take the first (real client)
                raw_ip = entry.get("source_ip", "")
                if "," in raw_ip:
                    source_ip = raw_ip.split(",")[0].strip()
                else:
                    source_ip = raw_ip.strip() or "unknown"

                yield {
                    "source_ip": source_ip,
                    "timestamp": entry.get("timestamp", ""),
                    "method": entry.get("method", ""),
                    "path": entry.get("path", ""),
                    "status": int(entry.get("status", 0)),
                    "response_size": int(entry.get("response_size", 0)),
                    "time": time.time()  # use current time for window math
                }

            except (json.JSONDecodeError, ValueError):
                # Skip malformed lines — nginx occasionally writes
                # partial lines during log rotation
                continue
