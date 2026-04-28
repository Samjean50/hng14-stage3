import time
import yaml
import threading
from monitor import tail_log
from baseline import BaselineTracker
from detector import SlidingWindowDetector
from blocker import Blocker
from unbanner import AutoUnbanner
from notifier import SlackNotifier
from dashboard import Dashboard
from audit import AuditLogger


def load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    print("Starting HNG Anomaly Detection Engine...")
    config = load_config()

    # Initialise all components
    audit = AuditLogger(config)
    baseline = BaselineTracker(config)
    detector = SlidingWindowDetector(config, baseline)
    blocker = Blocker(config, audit)
    notifier = SlackNotifier(config)
    unbanner = AutoUnbanner(blocker, notifier)

    # Load allowlist — IPs that should never be banned
    allowlist = config.get("allowlist", [])

    # Shared state for dashboard
    start_time = time.time()
    state = {
        "baseline": baseline,
        "detector": detector,
        "blocker": blocker,
        "start_time": start_time
    }

    # Start background threads
    unbanner.start()

    dashboard = Dashboard(config, state)
    dashboard.start()

    # Start baseline recalculation in background
    def recalc_loop():
        while True:
            time.sleep(config.get("baseline_recalc_interval", 60))
            mean, stddev = baseline.recalculate()
            audit.log(
                action="BASELINE_RECALC",
                condition=f"mean={mean:.3f} stddev={stddev:.3f}",
                rate=mean,
                baseline=mean
            )

    threading.Thread(target=recalc_loop, daemon=True).start()

    print(f"Tailing log: {config['log_path']}")
    print(f"Dashboard: http://0.0.0.0:{config['dashboard_port']}")

    # Main loop — process every log line
    for entry in tail_log(config["log_path"]):

        # Record in baseline tracker
        baseline.record_request()

        # Check for anomalies
        anomaly = detector.record(entry)

        if not anomaly:
            continue

        if anomaly["type"] == "ip":
            ip = anomaly["ip"]

            # Never ban allowlisted IPs
            if ip in allowlist:
                continue

            # Skip if already banned
            if blocker.is_banned(ip):
                continue

            duration = blocker.ban(
                ip=ip,
                condition=anomaly["condition"],
                rate=anomaly["ip_rate"],
                mean=anomaly["mean"]
            )

            if duration is not None:
                notifier.send_ban_alert(
                    ip=ip,
                    condition=anomaly["condition"],
                    rate=anomaly["ip_rate"],
                    mean=anomaly["mean"],
                    duration=duration
                )
                print(
                    f"BANNED {ip} | {anomaly['condition']} | "
                    f"rate={anomaly['ip_rate']} | "
                    f"duration={duration}min"
                )

        elif anomaly["type"] == "global":
            # Global anomaly — Slack alert only, no IP to ban
            notifier.send_global_alert(
                condition=anomaly["condition"],
                rate=anomaly["global_rate"],
                mean=anomaly["mean"]
            )
            print(
                f"GLOBAL ANOMALY | {anomaly['condition']} | "
                f"rate={anomaly['global_rate']}"
            )


if __name__ == "__main__":
    main()
