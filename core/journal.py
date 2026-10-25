"""One journal follower for the whole collector (docs/module-interface.md, Journal).

A module that reads the journal declares JOURNAL (match groups + fields). Core
runs ONE long-lived `journalctl -f -o json` with the union of the groups, reads
it without threads (selectors, in the collector loop), gives each entry to the
modules whose groups match and keeps it in a bounded buffer per module until
that module's next collect. Modules never start long-lived children; core does.

Start: --since=@<collector start>, so lines written while the modules ran init()
are not lost (a module skips what its own start scan already saw). Restart after
an exit: --after-cursor=<last entry>, never together with -n (journalctl 255
replays nothing with -n 0, 259 replays: tested 2026-10-25). Cursor refused (exit
without an entry): from the second of the last entry (--since), entries already
given are skipped by cursor. Backoff 1 s, doubling to 60 s, reset after 60 s up.

Host facts (systemd 259, 2026-10-25, journal_check.py): one JSON line per entry
reaches the pipe at once (~450 ms after logger: journald + logger); a burst of
300 entries complete and in order; follows across `journalctl --rotate`; works
under the sectop.service sandbox; idle 0 ms CPU per minute, RSS 21 MiB (journal
file maps); bad cursor: exit 1 "Failed to seek to cursor: Invalid argument".
"""

import collections
import fcntl
import json
import os
import re
import selectors
import subprocess
import time
from dataclasses import dataclass

from core.run import ENV, _unsafe

BIN = "/usr/bin/journalctl"
MAX_GROUPS = 8
MAX_TERMS = 8            # FIELD=VALUE per group
MAX_FIELDS = 32
MAX_ENTRIES = 5000       # buffer per module between two collects (oldest dropped)
MAX_LINE = 64 * 1024     # longer JSON line: dropped, counted as bad
MAX_PUMP = 4 * 1024 * 1024    # bytes read per pump() call
PIPE_SIZE = 1024 * 1024  # fcntl F_SETPIPE_SZ (pipe-max-size default), fewer wakeups
BACKOFF_MAX = 60.0
RESET_AFTER = 60.0       # up this long: next exit starts the backoff at 1 s again
RECENT = 256             # cursors kept to skip repeats after a restart from time
MAX_NOTES = 4
ERR_MAX = 300            # stderr tail kept

FIELD_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
VALUE_RE = re.compile(r"[A-Za-z0-9_.:/@%-]{1,64}")
CURSOR_RE = re.compile(r"[A-Za-z0-9=;_-]{1,512}")


@dataclass(frozen=True)
class Spec:
    groups: tuple        # ((field, value), ...) per group; groups are alternatives
    fields: tuple        # fields the module reads (journalctl --output-fields)


def _seq(x, what: str, most: int) -> list:
    if not isinstance(x, (list, tuple)) or not 1 <= len(x) <= most:
        raise ValueError(f"JOURNAL {what}: list of 1..{most} required")
    return list(x)


def spec(raw) -> Spec:
    """JOURNAL of a module -> Spec. Wrong -> ValueError (module not loaded).

    {"groups": [["_TRANSPORT=kernel"], ["_TRANSPORT=audit", "_AUDIT_TYPE=1123"]],
     "fields": ["MESSAGE"]}
    """
    if not isinstance(raw, dict) or set(raw) != {"groups", "fields"}:
        raise ValueError("JOURNAL: dict with groups and fields required")
    groups = []
    for g in _seq(raw["groups"], "groups", MAX_GROUPS):
        terms = []
        for t in _seq(g, "group", MAX_TERMS):
            field, sep, value = t.partition("=") if isinstance(t, str) else ("", "", "")
            if not sep or not FIELD_RE.fullmatch(field) or not VALUE_RE.fullmatch(value):
                raise ValueError(f"JOURNAL term {t!r}: FIELD=VALUE required "
                                 "(FIELD A-Z 0-9 _, VALUE A-Z a-z 0-9 _ . : / @ % -)")
            terms.append((field, value))
        groups.append(tuple(terms))
    fields = _seq(raw["fields"], "fields", MAX_FIELDS)
    for f in fields:
        if not isinstance(f, str) or not FIELD_RE.fullmatch(f):
            raise ValueError(f"JOURNAL field {f!r}: A-Z 0-9 _ required")
    return Spec(tuple(groups), tuple(fields))


def _text(v) -> str | None:
    """journald JSON value: str, or a byte array (non-UTF-8 / control chars)."""
    if isinstance(v, str):
        return v
    if isinstance(v, list) and v and all(type(b) is int and 0 <= b <= 255 for b in v):
        return bytes(v).decode("utf-8", errors="replace")
    return None


def values(v) -> list:
    """All values of a field: one, or a list when the entry has the field more than once."""
    t = _text(v)
    if t is not None:
        return [t]
    if isinstance(v, list):
        return [t for t in map(_text, v) if t is not None]
    return []


def wants(groups: tuple) -> tuple:
    """Groups -> per group ((field, allowed values), ...) for matches()."""
    out = []
    for g in groups:
        want = {}
        for field, value in g:
            want.setdefault(field, set()).add(value)
        out.append(tuple((f, frozenset(v)) for f, v in want.items()))
    return tuple(out)


def matches(entry: dict, want: tuple) -> bool:
    """journalctl(1) rules: in a group, terms of one field are alternatives, different
    fields must all match; groups (joined by +) are alternatives. want: wants(groups)."""
    return any(all(allowed.intersection(values(entry.get(f))) for f, allowed in g)
               for g in want)


def _spawn(argv):
    """journalctl as a child: trusted binary (core/run.py rules), own session."""
    reason = _unsafe(argv[0])                 # FileNotFoundError if missing
    if reason:
        raise PermissionError(f"refused: {argv[0]}: {reason}")
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, cwd="/", close_fds=True,
                            start_new_session=True)


def _first_line(b: bytes) -> str:
    for line in b.decode("utf-8", errors="replace").splitlines()[::-1]:
        if line.strip():
            return line.strip()[:ERR_MAX]
    return ""


class Reader:
    """The follower. pump() and wait() are the only calls that read; take() hands a
    module its entries. Single thread."""

    def __init__(self, specs: dict, since: float, binary: str = BIN, spawn=_spawn,
                 clock=time.monotonic, sleep=time.sleep):
        self.specs = dict(specs)
        groups, fields = [], set()
        for sp in self.specs.values():
            for g in sp.groups:
                if g not in groups:
                    groups.append(g)
                fields.update(f for f, _ in g)       # routing needs the matched fields
            fields.update(sp.fields)
        self.groups, self.fields = tuple(groups), tuple(sorted(fields))
        self.want = {n: wants(sp.groups) for n, sp in self.specs.items()}
        self.binary, self._spawn, self.clock, self._sleep = binary, spawn, clock, sleep
        self.since = int(since)
        self.cursor = None
        self.use_cursor = True
        self.recent = collections.deque(maxlen=RECENT)
        self.skip_seen = False         # after a restart from time: skip given entries
        self.last_us = None            # __REALTIME_TIMESTAMP of the last entry
        self.child = None
        self.sel = None
        self.part = b""
        self.skip_line = False         # in the tail of an overlong line
        self.err = b""
        self.starts = 0
        self.started = 0.0
        self.run_got = 0               # entries since the child started
        self.delay = 0.0
        self.restart_at = 0.0
        self.why = "not started yet"
        self.buf = {n: collections.deque(maxlen=MAX_ENTRIES) for n in self.specs}
        self.dropped = dict.fromkeys(self.specs, 0)
        self.bad = dict.fromkeys(self.specs, 0)
        self.notes = {n: [] for n in self.specs}

    # --- argv / child -----------------------------------------------------

    def argv(self) -> list:
        out = [self.binary, "-f", "-o", "json", f"--output-fields={','.join(self.fields)}",
               "-q", "--no-pager"]
        if self.cursor and self.use_cursor:
            out.append(f"--after-cursor={self.cursor}")
        else:
            out.append(f"--since=@{self.since}")
        for i, g in enumerate(self.groups):
            if i:
                out.append("+")
            out += [f"{f}={v}" for f, v in g]
        return out

    @property
    def up(self) -> bool:
        return self.child is not None

    def _note(self, text: str) -> None:
        for notes in self.notes.values():
            if not notes or notes[-1] != text:
                notes.append(text)
            del notes[:-MAX_NOTES]

    def _backoff(self) -> None:
        ran = self.clock() - self.started if self.starts else 0.0
        self.delay = 1.0 if self.delay == 0.0 or ran >= RESET_AFTER \
            else min(BACKOFF_MAX, self.delay * 2)
        self.restart_at = self.clock() + self.delay

    def _start(self) -> None:
        argv = self.argv()
        from_cursor = bool(self.cursor and self.use_cursor)
        try:
            child = self._spawn(argv)
        except OSError as e:
            self.why = f"journalctl not started: {e.strerror or e}"
            self._note(self.why)
            self.starts += 1
            self.started = self.clock()
            self._backoff()
            return
        for f in (child.stdout, child.stderr):
            os.set_blocking(f.fileno(), False)
        try:
            fcntl.fcntl(child.stdout.fileno(), fcntl.F_SETPIPE_SZ, PIPE_SIZE)
        except OSError:
            pass                               # default size: only more wakeups
        self.sel = selectors.DefaultSelector()
        self.sel.register(child.stdout, selectors.EVENT_READ)
        self.sel.register(child.stderr, selectors.EVENT_READ)
        if self.starts:
            self._note("journalctl restarted " + ("from the last entry" if from_cursor
                                                  else f"from time @{self.since}"))
        self.child, self.part, self.skip_line, self.err = child, b"", False, b""
        self.skip_seen = not from_cursor and self.cursor is not None
        self.starts += 1
        self.started, self.run_got = self.clock(), 0
        self.why = ""

    def _exited(self) -> None:
        child, self.child = self.child, None
        try:
            rc = child.wait(1.0)
        except subprocess.TimeoutExpired:      # closed stdout but still runs
            child.kill()
            rc = child.wait()
        self._read_err(child)
        self._drop(child)
        err = _first_line(self.err)
        self.why = f"journalctl exited (rc {rc}{': ' + err if err else ''})"
        if self.run_got == 0 and self.cursor and self.use_cursor and rc != 0:
            self.use_cursor = False            # cursor refused: from time next
            if self.last_us is not None:
                self.since = self.last_us // 1_000_000
        self._note(self.why)
        self._backoff()

    def _drop(self, child) -> None:
        if self.sel is not None:
            self.sel.close()
            self.sel = None
        for f in (child.stdout, child.stderr):
            try:
                f.close()
            except OSError:
                pass

    def close(self) -> None:
        child, self.child = self.child, None
        if child is None:
            return
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(1.0)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        self._drop(child)

    # --- reading ----------------------------------------------------------

    def _read_err(self, child) -> None:
        try:
            while data := os.read(child.stderr.fileno(), 65536):
                self.err = (self.err + data)[-4096:]
        except (BlockingIOError, OSError, ValueError):
            return
        if self.sel is not None and child is self.child:     # EOF: no endless wakeups
            try:
                self.sel.unregister(child.stderr)
            except (KeyError, ValueError):
                pass

    def pump(self) -> None:
        """Read what is there (never waits), restart a dead child when due."""
        if self.child is None:
            if self.clock() >= self.restart_at:
                self._start()
            return
        child, got = self.child, 0
        while got < MAX_PUMP:
            try:
                data = os.read(child.stdout.fileno(), 65536)
            except BlockingIOError:
                break
            if not data:
                self._exited()
                return
            got += len(data)
            self.feed(data)
        self._read_err(child)

    def wait(self, seconds: float) -> None:
        """Sleep up to `seconds`, reading entries as they come (the collector's sleep)."""
        end = self.clock() + seconds
        while True:
            self.pump()
            left = end - self.clock()
            if left <= 0:
                return
            if self.sel is None:
                self._sleep(max(0.0, min(left, self.restart_at - self.clock())) or 0.01)
            else:
                self.sel.select(left)

    def feed(self, data: bytes) -> None:
        """Bytes from journalctl -> lines -> entries (a cut line waits for its rest)."""
        lines = (self.part + data).split(b"\n")
        self.part = lines.pop()
        for line in lines:
            if self.skip_line:
                self.skip_line = False         # rest of an overlong line
                continue
            self._line(line)
        if len(self.part) > MAX_LINE:
            self.part, self.skip_line = b"", True
            self._bad()

    def _bad(self) -> None:
        for n in self.bad:
            self.bad[n] += 1

    def _line(self, raw: bytes) -> None:
        if not raw.strip():
            return
        try:
            e = json.loads(raw)
            cur = e["__CURSOR"]
        except (ValueError, KeyError, TypeError):
            self._bad()
            return
        if not isinstance(cur, str) or not CURSOR_RE.fullmatch(cur):
            self._bad()
            return
        if self.skip_seen:
            if cur in self.recent:
                return                         # given before the restart
            self.skip_seen = False
        self.cursor, self.use_cursor = cur, True
        self.recent.append(cur)
        self.run_got += 1
        ts = e.get("__REALTIME_TIMESTAMP")
        if isinstance(ts, str) and ts.isdigit():
            self.last_us = int(ts)
        for name, want in self.want.items():
            if matches(e, want):
                q = self.buf[name]
                if len(q) == q.maxlen:
                    self.dropped[name] += 1
                q.append(e)

    # --- modules ----------------------------------------------------------

    def take(self, name: str) -> tuple:
        """-> (entries since the last take, up, note). note "" = nothing went wrong."""
        q = self.buf[name]
        entries = tuple(q)
        q.clear()
        notes = [n for n in self.notes[name] if self.up or n != self.why]
        if self.dropped[name]:
            notes.append(f"{self.dropped[name]} entries dropped (buffer full)")
        if self.bad[name]:
            notes.append(f"{self.bad[name]} bad line(s)")
        if not self.up:
            left = max(0, self.restart_at - self.clock())
            notes.append(f"{self.why or 'down'}, restart in {left:.0f} s")
        self.notes[name], self.dropped[name], self.bad[name] = [], 0, 0
        seen = set()
        note = "; ".join(n for n in notes if not (n in seen or seen.add(n)))
        return entries, self.up, note


def for_modules(loaded, since: float, **kw):
    """Reader for the active modules with JOURNAL, None if none wants the journal."""
    specs = {ld.name: spec(ld.mod.JOURNAL) for ld in loaded
             if ld.active and getattr(ld.mod, "JOURNAL", None) is not None}
    return Reader(specs, since, **kw) if specs else None
