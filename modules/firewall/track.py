"""Tunnel state per tick, so a log line gets the state at its own time. Pure, no I/O.

A line is read one tick (or more, journal lag) after it was written: the state at
read time is not the state at line time (2026-10-26: pre-connect leak lines read on
the tick the tunnel came up were shown as `tunnel up`, crit).

The state is only known at ticks. Between two ticks with different states it is
`change` (the switch happened somewhere in that window).
"""

LAG = 5.0          # s: a line this much older than the first tick still gets its state
MAX_CHANGES = 64   # changes kept; the oldest folds into the start state


class Track:
    def __init__(self):
        self.first = None      # (wall, up) of the oldest known state
        self.prev = None       # (wall, up) of the tick before the last one
        self.last = None       # (wall, up) of the last tick
        self.changes = []      # (wall before, wall after, up after), oldest first

    def add(self, wall: float, up: bool) -> None:
        """One sample per tick, wall clock ascending."""
        up = bool(up)
        if self.first is None:
            self.first = (wall, up)
        elif up != self.last[1]:
            self.changes.append((self.last[0], wall, up))
            if len(self.changes) > MAX_CHANGES:
                _a, b, u = self.changes.pop(0)
                self.first = (b, u)
        self.prev, self.last = self.last, (wall, up)

    def at(self, ts: float):
        """State at epoch ts: 'up', 'down', 'change' or None (before the first tick)."""
        if self.first is None or ts < self.first[0] - LAG:
            return None
        up = self.first[1]
        for a, b, after in self.changes:
            if ts < a:
                break
            if ts <= b:
                return "change"
            up = after
        return "up" if up else "down"

    def window(self):
        """State over the last tick window: 'up', 'down', 'change' or None (first tick)."""
        if self.prev is None:
            return None
        if self.prev[1] != self.last[1]:
            return "change"
        return "up" if self.last[1] else "down"
