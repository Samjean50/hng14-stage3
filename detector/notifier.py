import requests
import time
import os


class SlackNotifier:
    """
    Sends structured Slack alerts for bans, unbans, and global anomalies.
    Webhook URL loaded from environment variable for security.
    """

    def __init__(self, config: dict):
        # Environment variable takes priority over config file
        self.webhook_url = (
            os.getenv("SLACK_WEBHOOK_URL") or
            config.get("slack", {}).get("webhook_url", "")
        )

    def _send(self, message: str):
        """Send a message to Slack. Fails silently if webhook not configured."""
        if not self.webhook_url:
            print(f"[SLACK NOT CONFIGURED] {message}")
            return

        try:
            requests.post(
                self.webhook_url,
                json={"text": message},
                timeout=5
            )
        except Exception as e:
            print(f"Slack notification failed: {e}")

    def send_ban_alert(self, ip: str, condition: str, rate: float,
                       mean: float, duration):
        duration_str = f"{duration}min" if duration else "permanent"
        msg = (
            f"🚨 *IP BANNED*\n"
            f"IP: `{ip}`\n"
            f"Condition: {condition}\n"
            f"Current rate: {rate:.1f} req/60s\n"
            f"Baseline mean: {mean:.2f}\n"
            f"Ban duration: {duration_str}\n"
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        )
        self._send(msg)

    def send_unban_alert(self, ip: str, ban_info: dict):
        msg = (
            f"✅ *IP UNBANNED*\n"
            f"IP: `{ip}`\n"
            f"Original condition: {ban_info.get('condition', 'unknown')}\n"
            f"Original rate: {ban_info.get('rate', 0):.1f} req/60s\n"
            f"Baseline at ban time: {ban_info.get('mean', 0):.2f}\n"
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        )
        self._send(msg)

    def send_global_alert(self, condition: str, rate: float, mean: float):
        msg = (
            f"⚠️ *GLOBAL TRAFFIC ANOMALY*\n"
            f"Condition: {condition}\n"
            f"Global rate: {rate:.1f} req/60s\n"
            f"Baseline mean: {mean:.2f}\n"
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
        )
        self._send(msg)
