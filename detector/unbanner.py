import time
import threading


class AutoUnbanner:
    """
    Background thread that checks ban expiry every 30 seconds
    and releases IPs on the backoff schedule.
    """

    def __init__(self, blocker, notifier):
        self.blocker = blocker
        self.notifier = notifier
        self.running = True

    def start(self):
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()

    def _run(self):
        while self.running:
            now = time.time()
            to_unban = []

            banned = self.blocker.get_banned()
            for ip, info in banned.items():
                duration = info.get("duration_minutes")

                # None duration = permanent ban, never auto-unban
                if duration is None:
                    continue

                ban_time = info.get("ban_time", now)
                elapsed_minutes = (now - ban_time) / 60

                if elapsed_minutes >= duration:
                    to_unban.append((ip, info))

            for ip, info in to_unban:
                success = self.blocker.unban(ip, reason="schedule_expiry")
                if success:
                    self.notifier.send_unban_alert(ip, info)

            time.sleep(30)
