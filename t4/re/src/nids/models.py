from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass(frozen=True)
class AlertEvent:
    timestamp: datetime
    src_ip: str
    dest_ip: str
    proto: str
    signature: str
    severity: int
    category: str
    event_type: str
    raw: dict[str, Any]

    @classmethod
    def from_suricata_event(cls, payload: dict[str, Any]) -> Optional["AlertEvent"]:
        if payload.get("event_type") != "alert":
            return None

        alert = payload.get("alert") or {}
        src_ip = payload.get("src_ip") or "unknown"
        dest_ip = payload.get("dest_ip") or "unknown"
        proto = payload.get("proto") or "unknown"
        signature = alert.get("signature") or "unknown signature"
        severity = int(alert.get("severity") or 0)
        category = alert.get("category") or "unspecified"
        timestamp_text = payload.get("timestamp")

        if timestamp_text:
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        else:
            timestamp = datetime.now(timezone.utc)

        return cls(
            timestamp=timestamp,
            src_ip=src_ip,
            dest_ip=dest_ip,
            proto=proto,
            signature=signature,
            severity=severity,
            category=category,
            event_type=payload.get("event_type", "alert"),
            raw=payload,
        )
