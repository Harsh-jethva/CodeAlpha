from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from subprocess import CalledProcessError, run

from .models import AlertEvent


@dataclass
class ResponsePolicy:
    escalation_threshold: int = 5
    block_command: list[str] = field(default_factory=list)
    quarantine_log: Path | None = None


class Responder:
    def __init__(self, policy: ResponsePolicy):
        self.policy = policy
        if self.policy.quarantine_log:
            self.policy.quarantine_log.parent.mkdir(parents=True, exist_ok=True)

    def decide(self, event: AlertEvent, repeated_count: int) -> str:
        if repeated_count < self.policy.escalation_threshold:
            return "logged"

        if self.policy.block_command:
            self._execute_block(event)
            return "blocked"

        self._write_quarantine_note(event)
        return "escalated"

    def _execute_block(self, event: AlertEvent) -> None:
        command = [part.format(src_ip=event.src_ip, dest_ip=event.dest_ip, signature=event.signature) for part in self.policy.block_command]
        try:
            run(command + [event.src_ip], check=True)
        except (CalledProcessError, FileNotFoundError):
            self._write_quarantine_note(event)

    def _write_quarantine_note(self, event: AlertEvent) -> None:
        note = f"{event.timestamp.isoformat()} | {event.src_ip} -> {event.dest_ip} | {event.signature}\n"
        if self.policy.quarantine_log:
            with self.policy.quarantine_log.open("a", encoding="utf-8") as handle:
                handle.write(note)
