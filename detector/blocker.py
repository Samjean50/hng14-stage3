import subprocess
import time
from threading import Lock


class Blocker:
    """
    Manages iptables DROP rules for banned IPs.
    Tracks ban counts per IP for the backoff schedule.
    """

    def __init__(self, config: dict, audit_logger):
        # Backoff schedule in minutes: [10, 30, 120, permanent]
        self.unban_schedule = config.get("unban_schedule", [10, 30, 120])
        self.audit = audit_logger

        # Currently banned IPs: dict of ip -> ban info
        self.banned = {}
        self.lock = Lock()

    def ban(self, ip: str, condition: str, rate: float, mean: float):
        """
        Add iptables DROP rule for the IP.
        Returns the ban duration in minutes.
        """
        with self.lock:
            if ip in self.banned:
                # Already banned — don't re-ban
                return None

            # Determine ban duration based on how many times
            # this IP has been banned before
            ban_count = self.banned.get(f"{ip}_count", 0)
            if ban_count < len(self.unban_schedule):
                duration_minutes = self.unban_schedule[ban_count]
            else:
                duration_minutes = None  # permanent

            # Run iptables command
            # -I INPUT 1 = insert at top of INPUT chain (highest priority)
            # -s = source IP
            # -j DROP = silently discard all packets from this IP
            try:
                subprocess.run([
                    "iptables", "-I", "INPUT", "1",
                    "-s", ip,
                    "-j", "DROP"
                ], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"iptables ban failed for {ip}: {e}")
                return None

            ban_time = time.time()
            self.banned[ip] = {
                "ip": ip,
                "ban_time": ban_time,
                "duration_minutes": duration_minutes,
                "condition": condition,
                "rate": rate,
                "mean": mean,
                "ban_count": ban_count + 1
            }

            # Write audit log
            duration_str = (
                f"{duration_minutes}min" if duration_minutes
                else "permanent"
            )
            self.audit.log(
                action="BAN",
                ip=ip,
                condition=condition,
                rate=rate,
                baseline=mean,
                duration=duration_str
            )

            return duration_minutes

    def unban(self, ip: str, reason: str = "schedule"):
        """Remove iptables DROP rule for the IP."""
        with self.lock:
            if ip not in self.banned:
                return False

            try:
                subprocess.run([
                    "iptables", "-D", "INPUT",
                    "-s", ip,
                    "-j", "DROP"
                ], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"iptables unban failed for {ip}: {e}")
                return False

            ban_info = self.banned.pop(ip)

            self.audit.log(
                action="UNBAN",
                ip=ip,
                condition=reason,
                rate=ban_info.get("rate", 0),
                baseline=ban_info.get("mean", 0),
                duration="released"
            )

            return True

    def get_banned(self):
        """Return list of currently banned IPs with their info."""
        with self.lock:
            return dict(self.banned)

    def is_banned(self, ip: str) -> bool:
        with self.lock:
            return ip in self.banned
