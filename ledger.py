"""Rate limiting (in memory) and the audit log (JSON lines in the plugin's data dir)."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Iterable

_WINDOW = 3600.0
_AUDIT_MAX_BYTES = 2 * 1024 * 1024


class RateLimiter:
    """Sliding one-hour window per identity key. ``limit <= 0`` means unlimited."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, limit: int) -> tuple[bool, int]:
        """Record one turn for *key*; returns (allowed, seconds until the next slot frees)."""
        if limit <= 0:
            return True, 0
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= _WINDOW:
                hits.popleft()
            if len(hits) >= limit:
                return False, max(1, int(_WINDOW - (now - hits[0])))
            hits.append(now)
            return True, 0

    def used(self, key: str) -> int:
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key) or deque()
            return sum(1 for t in hits if now - t < _WINDOW)


class AuditLog:
    """Append-only JSON lines. Records the tool name and argument *names* only, never values."""

    def __init__(self, path_fn: Callable[[], Path]) -> None:
        self._path_fn = path_fn
        self._lock = threading.Lock()

    def path(self) -> Path:
        return self._path_fn()

    def write(self, event: str, **fields: Any) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields}
        line = json.dumps(record, ensure_ascii=False, default=str)
        try:
            path = self.path()
            with self._lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists() and path.stat().st_size > _AUDIT_MAX_BYTES:
                    os.replace(path, path.with_suffix(".jsonl.1"))
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError:
            pass  # auditing must never break the agent

    def tail(self, n: int = 20, events: Iterable[str] | None = None) -> list[dict[str, Any]]:
        wanted = set(events) if events else None
        try:
            lines = self.path().read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for raw in reversed(lines):
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if wanted is None or rec.get("event") in wanted:
                out.append(rec)
            if len(out) >= n:
                break
        return list(reversed(out))
