#!/usr/bin/env python3
"""Global and per-host rate limiting."""

import threading
import time

# Ceiling lives in the code, not the flag. --rate 500 gets you 5.
MAX_RPS = 5.0
MIN_RPS = 0.05
MIN_HOST_GAP = 1.0


class Throttle:
    def __init__(self, rps=2.0, host_gap=2.0):
        self.gap = 1.0 / min(max(rps, MIN_RPS), MAX_RPS)
        self.host_gap = max(host_gap, MIN_HOST_GAP)
        self._lock = threading.Lock()
        self._last = 0.0
        self._host_last = {}

    def wait(self, host):
        while True:
            with self._lock:
                now = time.monotonic()
                delay = max(self._last + self.gap - now,
                            self._host_last.get(host, 0.0) + self.host_gap - now,
                            0.0)
                if delay <= 0:
                    self._last = now
                    self._host_last[host] = now
                    return
            # Sleep outside the lock in slices, so one slow host does not stall
            # every other host behind it.
            time.sleep(min(delay, 2.0))
