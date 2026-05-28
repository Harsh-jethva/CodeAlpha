# Network Intrusion Detection System

This project is a Suricata-based network intrusion detection starter.

It provides:

- rule examples for suspicious traffic
- a continuous monitor for Suricata `eve.json` alerts
- SQLite persistence for alert history
- optional response commands for repeated intrusions
- a Streamlit dashboard for trends and recent detections

## 1. Install prerequisites

Install Suricata on the machine that sees the traffic you want to inspect.

Then install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

## 2. Enable the local rules

Copy the rules in `rules/local.rules` into your Suricata rule path and ensure the rules file is loaded from your Suricata config.

At minimum, point Suricata at the local rule file and make sure `eve.json` output is enabled.

Typical locations:

- Linux: `/var/log/suricata/eve.json`
- Windows or custom installs: the path you configured in Suricata

## 3. Run the monitor

```bash
python -m nids monitor --eve-log /var/log/suricata/eve.json --db-path data/nids.db
```

Optional response command example:

```bash
python -m nids monitor --eve-log /var/log/suricata/eve.json --db-path data/nids.db --block-command ufw deny from
```

The command is only used after the same source exceeds the escalation threshold. If no response command is configured, detections are logged only.

## 4. Run the dashboard

```bash
streamlit run src/nids/dashboard.py
```

The dashboard reads the SQLite database and shows recent alerts, top sources, and hourly detection trends.

## 5. Seed sample alerts

If you want to test the pipeline without a live Suricata feed:

```bash
python -m nids seed-sample --db-path data/nids.db
```

## Notes

- This starter is defensive and reads Suricata alerts from `eve.json`.
- It does not replace a full IDS deployment plan for production use.
- For active blocking, pair the response hook with firewall, NAC, or SOAR tooling that matches your environment.
