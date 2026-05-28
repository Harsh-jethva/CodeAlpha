from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import AlertEvent
from .responder import Responder
from .storage import AlertStore


@dataclass
class MonitorConfig:
    eve_log: Path
    poll_interval: float = 1.0
    response_window_seconds: int = 300


class AlertMonitor:
    def __init__(self, store: AlertStore, responder: Responder, config: MonitorConfig):
        self.store = store
        self.responder = responder
        self.config = config

    def process_event(self, payload: dict[str, object]) -> AlertEvent | None:
        event = AlertEvent.from_suricata_event(payload)
        if event is None:
            return None

        repeated_count = self.store.alerts_in_window(event.src_ip, self.config.response_window_seconds) + 1
        response_action = self.responder.decide(event, repeated_count)
        self.store.add_alert(event, response_action=response_action)
        return event

    def process_stream(self, stream: Iterable[str]) -> int:
        processed = 0
        for line in stream:
            line = line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            if self.process_event(payload):
                processed += 1

        return processed

    def run_forever(self) -> None:
        self.config.eve_log.parent.mkdir(parents=True, exist_ok=True)
        self.config.eve_log.touch(exist_ok=True)
        with self.config.eve_log.open("r", encoding="utf-8") as handle:
            handle.seek(0, 2)
            while True:
                position = handle.tell()
                line = handle.readline()
                if not line:
                    handle.seek(position)
                    time.sleep(self.config.poll_interval)
                    continue

                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue

                self.process_event(payload)
