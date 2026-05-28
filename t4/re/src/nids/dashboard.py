from __future__ import annotations

from pathlib import Path
import sys

import pandas as pd
import plotly.express as px
import streamlit as st

try:
    from .storage import AlertStore
except ImportError:  # pragma: no cover - streamlit executes this file directly
    sys.path.append(str(Path(__file__).resolve().parents[1]))
    from nids.storage import AlertStore


def load_alerts(db_path: Path) -> pd.DataFrame:
    store = AlertStore(db_path)
    rows = store.recent_alerts(limit=500)
    if not rows:
        return pd.DataFrame(columns=["timestamp", "src_ip", "dest_ip", "proto", "signature", "severity", "category", "event_type", "response_action"])
    return pd.DataFrame(rows)


def main() -> None:
    st.set_page_config(page_title="NIDS Dashboard", layout="wide")
    st.title("Network Intrusion Detection System")
    st.caption("Suricata alert monitoring, response tracking, and attack visualization")

    db_path = Path(st.sidebar.text_input("Database path", value="data/nids.db"))
    alerts = load_alerts(db_path)

    total = len(alerts)
    unique_sources = alerts["src_ip"].nunique() if not alerts.empty else 0
    blocked = int((alerts["response_action"] == "blocked").sum()) if not alerts.empty else 0
    escalated = int((alerts["response_action"] == "escalated").sum()) if not alerts.empty else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Alerts", total)
    col2.metric("Source IPs", unique_sources)
    col3.metric("Blocked", blocked)
    col4.metric("Escalated", escalated)

    if alerts.empty:
        st.info("No alerts recorded yet. Run the monitor or seed sample data.")
        return

    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])
    hourly = alerts.set_index("timestamp").resample("1h").size().reset_index(name="alerts")
    top_sources = alerts["src_ip"].value_counts().reset_index()
    top_sources.columns = ["src_ip", "count"]

    left, right = st.columns(2)
    with left:
        st.subheader("Alert volume by hour")
        st.plotly_chart(px.line(hourly, x="timestamp", y="alerts", markers=True), use_container_width=True)

    with right:
        st.subheader("Top source IPs")
        st.plotly_chart(px.bar(top_sources.head(10), x="src_ip", y="count"), use_container_width=True)

    st.subheader("Recent alerts")
    st.dataframe(
        alerts.sort_values("timestamp", ascending=False)[["timestamp", "src_ip", "dest_ip", "proto", "signature", "severity", "response_action"]],
        use_container_width=True,
    )


if __name__ == "__main__":
    main()
