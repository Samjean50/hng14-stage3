import time


class AuditLogger:
    """
    Writes structured log entries for every ban, unban,
    and baseline recalculation.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, config: dict):
        self.log_path = config.get("audit_log_path", "/var/log/detector-audit.log")

    def log(self, action: str, ip: str = "-", condition: str = "-",
            rate: float = 0, baseline: float = 0, duration: str = "-"):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        line = (
            f"[{timestamp}] {action} {ip} | "
            f"{condition} | "
            f"rate={rate:.2f} | "
            f"baseline={baseline:.2f} | "
            f"duration={duration}\n"
        )
        print(line.strip())
        try:
            with open(self.log_path, "a") as f:
                f.write(line)
        except Exception as e:
            print(f"Audit log write failed: {e}")
