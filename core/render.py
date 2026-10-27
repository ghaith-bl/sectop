"""Draw core's view in the terminal.

layout() is pure: screens + view + feed + UI state -> Frame (lines, the
boxes shown, the focused box). draw() only paints a Frame with curses.
Every string passes sanitize.display() (in _line(), _title() and
_detail()), so nothing reaches the terminal without clean -> mask.
Width is counted in terminal cells (wide chars = 2, combining marks = 0).

Screen, top to bottom:
    tabs, pause, mask, clock
    alert bar (alert engine: problems from all screens, see _alerts)
    one header per module on this screen
    box grid (panels packed left to right, then events), or one overlay
    box (help, detail of the selected line)
    key help

Cursor: every box has a selected body line; the focused box shows it in
reverse. While the cursor is not on the first line, it stays on the same
row (row id, else line text) when new lines arrive above it (anchor).

Filter: a table / events box shows only lines that match ui.filters[key]
(words all match, !word must not; cells, row detail, raw and masked text).

Detail search: the detail overlay shows the lines that contain ui.find in bold
(case-insensitive, searched on key + value, so a wrap never cuts a match; real
or masked text, like the table filter: what a table shows with mask on). The
current match (ui.mark = its pair index) is in reverse video. ui.seek asks for
a move (first / next / prev); the renderer resolves it, because only it knows
where the wrapped lines are. The frame reports the new mark (BoxInfo.mark).
"""

import curses
import time
import unicodedata
from dataclasses import dataclass

from core.lookup import TIMEOUT as LOOKUP_TIMEOUT
from core.lookup import public
from core.module import SEV_RANK, spark_cell
from core.sanitize import TRUNC, display, mask_ips

TAGS = {"ok": "OK", "info": "INFO", "warn": "WARN", "crit": "CRIT",
        "unknown": "??", "off": "OFF"}
TAG_W = 6                                    # "[CRIT]"
SPARK = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
KEY_MAX = 24                                 # kv / detail key column
COL_MAX = 40                                 # table column
COL_MIN = 6                                  # table column after shrinking (or its header)
KV_MIN, KV_MAX = 24, 56                      # kv content width
TABLE_MIN = 24                               # table content width
SPARK_W = 40                                 # spark content width
GRID_MIN = 4                                 # narrower: no boxes
ALERT_RANK = {"crit": 0, "warn": 1, "unknown": 2}
BAR_SEVS = ("warn", "crit")                  # info alerts: counted, not in the bar
SEL = "sel "                                 # style prefix: reverse video
# severity column: a glyph per level, so color is not the only means (WCAG 2.2, 1.4.1)
GLYPH = {"crit": "!!", "warn": "!", "info": "i", "noise": "~", "ok": ""}
GLYPH_W = 3                                  # glyph (2) + space
HEAD = "head"                                # table header: bold + underline
BOLD = "bold "                               # style prefix: bold (warn line with a tone)
# Colors (docs/architecture.md, Look; my palette 2026-10-27): white frame, purple titles,
# lavender names, cyan = safe / ok values, red / yellow = crit / warn only, blue = info.
# style -> xterm 256 color; basic 8 colors otherwise (COLORS_8).
COLORS_256 = {
    "title": 141, "name": 147, "text": 189, "value": 117, "high": 215, "peak": 212,
    "note": 246, "frame": 255,
    "ok": 117, "info": 111, "warn": 222, "crit": 196, "unknown": 201,
    # row / item tones (meaning, not severity): blue = allowed, green = healthy: both safe
    "red": 210, "blue": 117, "yellow": 222, "green": 117,
}
COLORS_8 = {
    "title": curses.COLOR_MAGENTA, "name": curses.COLOR_BLUE, "text": curses.COLOR_WHITE,
    "value": curses.COLOR_CYAN, "high": curses.COLOR_YELLOW, "peak": curses.COLOR_MAGENTA,
    "note": curses.COLOR_WHITE, "frame": curses.COLOR_WHITE,
    "ok": curses.COLOR_CYAN, "info": curses.COLOR_BLUE, "warn": curses.COLOR_YELLOW,
    "crit": curses.COLOR_RED, "unknown": curses.COLOR_MAGENTA,
    "red": curses.COLOR_RED, "blue": curses.COLOR_CYAN, "yellow": curses.COLOR_YELLOW,
    "green": curses.COLOR_CYAN,
}

# box drawing, U+2500 block
BH, BV = "\u2500", "\u2502"
TL, TR, BL, BR = "\u256d", "\u256e", "\u2570", "\u256f"   # rounded (Look 2026-10-20)
TD, TU, LT, RT, CROSS = "\u252c", "\u2534", "\u251c", "\u2524", "\u253c"

HELP = (
    ("1-9", "screen"),
    ("tab  right  l", "next box"),
    ("shift-tab  left  h", "previous box"),
    ("down up  j k", "select line"),
    ("space PgDn / PgUp", "one page"),
    ("g G  Home End", "first / last line (in help / detail: top / end)"),
    ("!!  !  i", "severity column: crit, warn, info (empty: ok); README.md, Screen legend"),
    ("12s  4m  2h  3d", "age in a row (full local time in the detail; paused: frozen)"),
    ("enter", "detail of the selected line (pauses while open, real IPs)"),
    ("/", "filter the focused table: all words match, !word must not"),
    ("/  (in a detail)", "search its lines: jumps to the first match, enter keeps it"),
    ("n  N  (in a detail)", "next / previous match"),
    ("w", "whois of the selected IP (RDAP by sectop-whois.service, via the tunnel)"),
    ("a", "ack the alerts in the alert bar (dims them; a higher count or severity "
          "shows them again)"),
    ("Esc", "clear the filter of the focused table"),
    ("f", "on a row with a filter (programs): filter the other tables of the screen to "
          "it; again: clear"),
    ("c", "program card: every row of every screen with the selected row's program "
          "(rows that know their program; on the row or in its detail); select a row, "
          "enter = its detail"),
    ("x", "on such a row (one word): hide it in every table of the screen (adds !name, "
          "Esc clears)"),
    ("p", "pause / resume the screen (data is still collected)"),
    ("m", "mask public IPs on / off"),
    ("Esc  q  enter", "close help / detail / card (a detail opened in the card: back to "
                      "the card)"),
    ("q", "quit"),
)
FOOTER = ("1-{n} screen  tab <- -> box  up down j k select  enter detail  c card  / filter  "
          "w whois  a ack  p pause  m mask  ? help  q quit")
TYPING = "  enter apply  esc cancel  (all words match, !word must not)"
TYPING_FIND = "  enter keep  esc cancel  (any case, text of a line)"
FOOTER_DETAIL = (" up down PgUp PgDn scroll  g G Home End top / end  / search  n N match  "
                 "w whois  Esc close")
FOOTER_HELP = " up down PgUp PgDn scroll  g G Home End top / end  Esc close"
FOOTER_CARD = " up down j k select  enter detail (Esc back to the card)  / filter  Esc close"
FILTER_MAX = 60

_ATTR = {}                                   # style -> curses attr, set in setup()


@dataclass(frozen=True)
class BoxInfo:
    key: str
    lines: int          # body lines
    page: int           # body lines visible
    sel: int = 0        # selected body line
    off: int = 0        # first visible body line
    ident: str | None = None   # row id or text of the selected line (anchor)
    cursor: bool = True        # False: overlay text, keys scroll it
    filterable: bool = False   # table / events: / filters it
    ip: str | None = None      # address of the selected line (w = whois)
    pick: str | None = None    # row filter of the selected line (f follow, x hide)
    mark: int | None = None    # detail search: pair index of the current match
    progs: tuple = ()          # program names of the selected line (c = card)


@dataclass(frozen=True)
class Frame:
    lines: list         # each: list of (text, style)
    boxes: tuple        # BoxInfo, in screen order
    focus: str | None = None
    alerts: tuple = ()  # (key, count, sev) of the engine alerts in the bar (ack key)


# --- cells ----------------------------------------------------------------

def _cw(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def cols(s: str) -> int:
    """Terminal cells used by s. ASCII (after clean(): printable) = 1 cell each."""
    if s.isascii():
        return len(s)
    return sum(_cw(ch) for ch in s)


def fit(s: str, width: int) -> str:
    """Cut s to width cells, last cell TRUNC if cut."""
    if width <= 0:
        return ""
    if cols(s) <= width:
        return s
    if s.isascii():
        return s[:width - 1] + TRUNC
    out, used = [], 0
    for ch in s:
        w = _cw(ch)
        if used + w > width - 1:
            break
        out.append(ch)
        used += w
    return "".join(out) + TRUNC


def pad(s: str, width: int) -> str:
    s = fit(s, width)
    return s + " " * (width - cols(s))


def wrap(s: str, width: int) -> list:
    """Split s into pieces of at most width cells (no word logic)."""
    if width <= 0:
        return [""]
    out, cur, used = [], [], 0
    for ch in s:
        w = _cw(ch)
        if cur and used + w > width:
            out.append("".join(cur))
            cur, used = [], 0
        cur.append(ch)
        used += w
    out.append("".join(cur))
    return out


def grow(widths: list, full: list, room: int) -> list:
    """Free room goes to columns cut at COL_MAX, the last one first (a full-width box:
    the command line, not ~ after 40 cells)."""
    out, left = list(widths), room - sum(widths)
    for j in reversed(range(len(out))):
        if left <= 0:
            break
        add = min(left, max(0, full[j] - out[j]))
        out[j] += add
        left -= add
    return out


def shrink(widths: list, floors: list, room: int) -> list:
    """Column widths that fit room cells: the widest column loses a cell first,
    none below its floor. Cut cells end in TRUNC; detail shows them whole."""
    out = list(widths)
    over = sum(out) - room
    while over > 0:
        i = max(range(len(out)), key=lambda j: (out[j] - floors[j] > 0, out[j], -j))
        if out[i] <= floors[i]:
            break                            # at the floors: the line gets cut
        out[i] -= 1
        over -= 1
    return out


def _line(width: int, mask: bool, *parts) -> list:
    """parts: (text, style). Sanitized, cut to width cells in total."""
    out, left = [], width
    for text, style in parts:
        if left <= 0:
            break
        s = fit(display(text, mask), left)
        if s:
            out.append((s, style))
            left -= cols(s)
    return out


def _len(line: list) -> int:
    return sum(cols(t) for t, _ in line)


def _text(line: list) -> str:
    return "".join(t for t, _ in line)


def _right(width: int, mask: bool, parts: list, right: list) -> list:
    """Left parts, then the `right` parts flush right if they fit."""
    left = _line(width, mask, *parts)
    rp = [(display(t, mask), s) for t, s in right]
    gap = width - _len(left) - _len(rp)
    if gap >= 1:
        left = left + [(" " * gap, "plain")] + rp
    return left


def _sev(sev: str) -> str:
    """ok values are drawn plain: only problems get color."""
    return "plain" if sev == "ok" else sev


def _style(it: dict) -> str:
    """Style of a kv item / table row. crit always wins; a tone (meaning, e.g. a
    verdict) replaces the ok / info / warn color, warn adds bold."""
    tone = it.get("tone")
    if not tone or it["sev"] == "crit":
        return _sev(it["sev"])
    return (BOLD if it["sev"] == "warn" else "") + tone


def _text_style(it: dict) -> str:
    """kv value: its severity / tone color, else text color."""
    style = _style(it)
    return "text" if style == "plain" else style


def _pair_style(sev: str) -> str:
    """A detail line / event message: problem severities in their color, else text."""
    return sev if sev in ("info", "warn", "crit") else "text"


def _sev_word(sev: str) -> str:
    """The `severity` line of a detail: its own color, ok = safe (cyan)."""
    return "value" if sev == "ok" else sev


def _num(v) -> str:
    return f"{v:g}" if isinstance(v, float) else str(v)


def _ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _stamp(ts: float) -> str:
    """Full local time: the detail of an age."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _glyph(sev: str) -> tuple:
    """Severity column part: glyph + space, in the severity color."""
    return (pad(GLYPH.get(sev, ""), GLYPH_W - 1) + " ", _sev(sev))


def age(ts: float, ref: float) -> str:
    """12s, 4m, 2h, 3d (whole units, never negative)."""
    sec = max(0, int(ref - ts))
    if sec < 120:
        return f"{sec}s"
    if sec < 7200:
        return f"{sec // 60}m"
    if sec < 172800:
        return f"{sec // 3600}h"
    return f"{sec // 86400}d"


def bars(cell: str, width: int) -> str:
    """Spark cell -> bars of its last `width` values (newest right). Scale: 0 (or the
    lowest value below 0) to the cell's top, else to the highest value."""
    got = spark_cell(cell)
    if not got or not got[0] or width <= 0:
        return ""
    vals, top = got
    vals = vals[-width:]
    lo = min(0.0, min(vals))
    hi = top if top is not None else max(vals)
    span = hi - lo
    last = len(SPARK) - 1
    if span <= 0:
        return SPARK[0] * len(vals)
    return "".join(SPARK[max(0, min(last, round((v - lo) / span * last)))] for v in vals)


def spark_text(cell: str) -> str:
    """Spark cell in a detail / filter / card: last, min, max, points (and scale)."""
    got = spark_cell(cell)
    if not got or not got[0]:
        return "-"
    vals, top = got
    out = (f"last {_num(vals[-1])}  min {_num(min(vals))}  max {_num(max(vals))}  "
           f"{len(vals)} points")
    return out + (f"  (scale 0-{_num(top)})" if top is not None else "")


def _when(cell: str):
    """Age cell -> epoch seconds, None for - / empty / not a number."""
    try:
        return float(cell) if cell not in ("", "-") else None
    except ValueError:
        return None


# --- top lines ------------------------------------------------------------

def _tabs(screens, ui, width: int, now, tsfmt) -> list:
    parts = []
    for i, s in enumerate(screens):
        label = f"{i + 1} {s.name}"
        parts.append(("  " if i else " ", "plain"))
        parts.append((f"[{label}]", "tabon") if i == ui.screen else (label, "note"))
    right = [("PAUSED", "warn"), ("  ", "plain")] if ui.paused else []
    tail = f"mask {'on' if ui.mask else 'off'}"
    if now is not None:
        tail += f"  {tsfmt(now)}"
    return _right(width, ui.mask, parts, right + [(tail + " ", "note")])


def acked(a: dict, acks: dict) -> bool:
    """Acked and nothing new since: same or lower count and severity."""
    ack = acks.get(a["key"])
    return (ack is not None and a["count"] <= ack[0]
            and SEV_RANK[a["sev"]] <= SEV_RANK[ack[1]])


def _alerts(view: list, alerts: list, acks: dict, mask: bool, width: int) -> tuple:
    """Alert bar -> (line, shown engine alerts as (key, count, sev)).

    Items: engine alerts (core/alerts.py active(): warn / crit, not noise) and
    module problems the engine does not cover (status unknown: not loaded,
    stale, error; crit / warn of a v1 module). Not acked first, then acked
    (dim). Each group: crit, warn, unknown, engine order inside. A held alert
    (condition gone, kept for its hold time) has a dim title. Right side:
    counts, incl. info and noise alerts, which are not in the bar.
    """
    items = []                                  # (acked, rank, parts)
    shown = []
    for a in alerts:
        if a["noise"] is not None or a["sev"] not in BAR_SEVS:
            continue
        ack = acked(a, acks)
        title = a["title"] + (f" x{a['count']}" if a["count"] > 1 else "")
        dim = ack or a["state"] != "open"
        items.append((ack, ALERT_RANK[a["sev"]],
                      [("dim" if ack else a["sev"], TAGS[a["sev"]]),
                       ("dim" if dim else "plain", f" {title}")]))
        shown.append((a["key"], a["count"], a["sev"]))
    for m in view:
        st = m["status"]
        if m.get("waiting") or st not in ALERT_RANK or (m.get("engine") and st != "unknown"):
            continue
        items.append((False, ALERT_RANK[st], [(st, TAGS[st]), ("plain", f" {m['name']}")]))
    items.sort(key=lambda it: (it[0], it[1]))   # stable: engine order inside a rank

    n = len(items)
    k = sum(1 for it in items if it[0])
    info = sum(1 for a in alerts if a["noise"] is None and a["sev"] == "info")
    noise = sum(1 for a in alerts if a["noise"] is not None)
    right = f"{n} alert{'s' if n != 1 else ''}" if n else ""
    for count, word in ((k, "acked"), (info, "info"), (noise, "noise")):
        if count:
            right += ("  " if right else "") + f"{count} {word}"
    parts = []
    for i, (_ack, _rank, its) in enumerate(items):
        parts.append(("   " if i else " ", "plain"))
        parts += [(t, s) for s, t in its]
    if not parts:
        parts = [(" no alerts", "dim")]
    if not right:
        return _line(width, mask, *parts), tuple(shown)
    rp = [(right + " ", "dim")]
    room = width - _len(rp) - 1
    if room < 12:                               # too narrow for both: alerts first
        return _line(width, mask, *parts), tuple(shown)
    left = _line(room, mask, *parts)
    return left + [(" " * (width - _len(left) - _len(rp)), "plain")] + rp, tuple(shown)


def _header(m: dict, width: int, mask: bool) -> list:
    tag = f"[{TAGS.get(m['status'], '??')}]".ljust(TAG_W)
    parts = [(tag, m["status"]), (f" {m['name']}", "title"), (f"  {m['summary']}", "text")]
    for flag in m["flags"]:
        style = "warn" if flag.startswith(("error", "failed", "backoff", "slow")) else "dim"
        parts.append((f"  | {flag}", style))
    return _line(width, mask, *parts)


def _footer(n_screens: int, width: int, ui=None) -> list:
    typing = getattr(ui, "typing", None)
    detail = getattr(ui, "detail", None) is not None
    if typing is not None:
        return _line(width, False, (" / ", "focus"), (typing + "_", "text"),
                     (TYPING_FIND if detail else TYPING, "note"))
    hint = getattr(ui, "hint", "")
    if hint:                                 # why the last key did nothing (c: no program)
        return _line(width, False, (" " + hint, "info"))
    if detail:
        return _line(width, False, (FOOTER_DETAIL, "note"))
    if getattr(ui, "card", None) is not None:
        return _line(width, False, (FOOTER_CARD, "note"))
    if getattr(ui, "help", False):
        return _line(width, False, (FOOTER_HELP, "note"))
    return _line(width, False, (" " + FOOTER.format(n=n_screens), "note"))


def _search(parts: list) -> str:
    raw = " ".join(parts)
    return (raw + "\n" + mask_ips(raw)).lower()


def match(hay: str, filt: str) -> bool:
    """All words in hay; a word starting with ! must not be in it."""
    for word in filt.lower().split():
        if word.startswith("!"):
            if len(word) > 1 and word[1:] in hay:
                return False
        elif word not in hay:
            return False
    return True


# --- boxes ----------------------------------------------------------------

class _Box:
    """One box: a panel, the events list, a note or a detail list."""

    def __init__(self, key, title, sev, kind, data, stale=False):
        self.key, self.title, self.sev, self.kind = key, title, sev, kind
        self.data, self.stale = data, stale
        self.full = kind in ("feed", "note", "detail")
        self.grow = kind in ("table", "feed", "note", "detail")
        self.cursor = kind not in ("note", "detail")
        self.prep = None
        self.w = self.h = 0                  # natural content width, lines
        self.least = 0                       # content width it can shrink to
        self.filt = ""                       # table / feed filter
        self.view = []                       # table rows / events after the filter
        self.find = ""                       # detail search text
        self.seek = None                     # detail search: first / next / prev asked
        self.mark = None                     # detail search: current match (pair index)
        self.found = ()                      # detail search: (pair, first line, end) per match
        self.ref = None                      # age reference (now, or the pause moment)
        self.tsfmt = _ts                     # clock time: an age cell without a reference
        self.stampfmt = _stamp               # full time in a detail
        self.secrets = True                  # detail: mask secrets (mask on), IPs real

    @property
    def filterable(self) -> bool:
        return self.kind in ("table", "feed")

    def types(self) -> list:
        cols_ = self.data["columns"]
        return self.data.get("types") or ["text"] * len(cols_)

    def cell(self, c: str, t: str, full: bool = False) -> str:
        """Cell as shown: an age column gives the age (full time in a detail), a spark
        column its bars (last, min, max in a detail)."""
        if t == "spark":
            return spark_text(c) if full else bars(c, COL_MAX)
        if t != "age":
            return c
        ts = _when(c)
        if ts is None:
            return "-"
        if full:
            return self.stampfmt(ts) + ("" if self.ref is None else f"  ({age(ts, self.ref)} ago)")
        return age(ts, self.ref) if self.ref is not None else self.tsfmt(ts)

    def measure(self, mask: bool) -> None:
        if self.kind == "table":
            rows, types = self.data["rows"], self.types()
            self.view = [r for r in rows if not self.filt or match(_search(
                [self.cell(c, t, True) for c, t in zip(r["cells"], types)]
                + [it["v"] for it in r.get("detail", ())]), self.filt)]
        elif self.kind == "feed":
            self.view = [e for e in self.data if not self.filt or match(
                _search([e["sev"], e["src"], e["code"], e["msg"]]), self.filt)]
        self._measure(mask)
        if self.kind in ("kv", "table", "feed"):   # severity column
            self.w += GLYPH_W
            self.least += GLYPH_W
        if self.kind in ("kv", "table"):     # natural width also fits the title
            self.w = max(self.w, cols(display(self.title, mask)) + 3)

    def _measure(self, mask: bool) -> None:
        d = self.data
        if self.kind == "kv":
            keys = [display(it["k"], mask) for it in d["items"]]
            vals = [display(it["v"], mask) for it in d["items"]]
            kw = min(KEY_MAX, max((cols(k) for k in keys), default=0))
            self.prep = (keys, kw)
            vw = max((cols(v) for v in vals), default=1)
            self.w = min(KV_MAX, max(KV_MIN, kw + 2 + vw))
            self.least = KV_MIN
            self.h = max(1, len(keys))
        elif self.kind == "table":
            types = self.types()
            head = [display(c, mask) for c in d["columns"]]
            rows = [[display(self.cell(c, t), mask) for c, t in zip(r["cells"], types)]
                    for r in self.view]
            full = [max(cols(c) for c in col) for col in zip(head, *rows)]
            widths = [min(COL_MAX, w) for w in full]
            floors = [min(w, max(COL_MIN, cols(h))) for w, h in zip(widths, head)]
            self.prep = (head, rows, widths, floors, full)
            gaps = 2 * (len(widths) - 1)
            self.w = max(TABLE_MIN, sum(widths) + gaps)
            self.least = min(self.w, max(TABLE_MIN, sum(floors) + gaps))
            self.h = 1 + max(1, len(rows))
        elif self.kind == "spark":
            self.w, self.h = SPARK_W, 1
            self.least = SPARK_W
        else:                                # feed, note, detail
            self.w, self.h = 0, max(1, len(self.view if self.kind == "feed" else d))

    def content(self, w: int, mask: bool, tsfmt) -> tuple:
        """-> (head lines, body lines), each at most w cells."""
        d = self.data
        dash = [_line(w, mask, ("-", "dim"))]
        if self.kind == "kv":
            keys, kw = self.prep
            body = [_line(w, mask, _glyph(it["sev"]), (pad(k, kw) + "  ", "name"),
                          (it["v"], _text_style(it))) for k, it in zip(keys, d["items"])]
            return [], body or dash
        if self.kind == "table":
            head, rows, widths, floors, full = self.prep
            types = self.types()
            right = [t != "text" for t in types]
            room = w - GLYPH_W - 2 * (len(widths) - 1)
            widths = grow(shrink(widths, floors, room), full, room)
            sparks = [j for j, t in enumerate(types) if t == "spark"]
            if sparks:                       # bars for the width the column got, not cut
                rows = [list(cells) for cells in rows]
                for cells, r in zip(rows, self.view):
                    for j in sparks:
                        cells[j] = bars(r["cells"][j], widths[j])

            def cell(c, cw, r):
                c = fit(c, cw)
                gap = " " * (cw - cols(c))
                return gap + c if r else c + gap

            def row(cells):
                return "  ".join(cell(c, cw, r) for c, cw, r in zip(cells, widths, right)).rstrip()

            def header():
                """Bold + underlined labels, spaces between them plain."""
                parts = [(" " * GLYPH_W, "plain")]
                for j, (c, cw, r) in enumerate(zip(head, widths, right)):
                    c = fit(c, cw)
                    gap = " " * (cw - cols(c))
                    parts += [(gap, "plain"), (c, HEAD)] if r else [(c, HEAD), (gap, "plain")]
                    if j < len(head) - 1:
                        parts.append(("  ", "plain"))
                return _line(w, mask, *parts)

            roles = self.roles()

            def parts(cells, r):
                """ok row without a tone: each cell in its column's color; else the whole
                row in its severity / tone color."""
                style = _style(r)
                if style != "plain":
                    return [(row(cells), style)]
                out, last = [], len(cells) - 1
                for j, (c, cw, rt, role) in enumerate(zip(cells, widths, right, roles)):
                    c = cell(c, cw, rt)
                    if role == "value" and r.get("level") == "high":
                        role = "high"
                    out.append((c.rstrip() if j == last else c, role))
                    if j < last:
                        out.append(("  ", "plain"))
                return out

            body = [_line(w, mask, _glyph(r["sev"]), *parts(cells, r))
                    for cells, r in zip(rows, self.view)]
            return [header()], body or dash
        if self.kind == "spark":
            return [], [_spark(d, w, mask)]
        if self.kind == "feed":
            return [], [_event(e, w, mask, tsfmt, self.ref) for e in self.view] or dash
        if self.kind == "detail":                # opened on purpose: real IPs, no mask
            lines, owner = _detail_rows(d, w, False, self.secrets)
            self.found = _found(d, owner, self.find) if self.find.strip() else ()
            return [], lines or dash
        return [], [_line(w, mask, (t, "note")) for t in d] or dash

    def pairs(self, i: int, tsfmt) -> list:
        """(key, value) pairs for the detail of body line i. [] = nothing."""
        d = self.data
        if self.kind == "kv" and i < len(d["items"]):
            it = d["items"][i]
            return [(it["k"], it["v"], _pair_style(it["sev"])),
                    ("severity", it["sev"], _sev_word(it["sev"]))]
        if self.kind == "table" and i < len(self.view):
            r = self.view[i]
            # a problem row: its own cells in its severity color, so the eye lands there
            hot = _pair_style(r["sev"])
            out = [(c, self.cell(v, t, True), hot) for c, v, t in zip(
                d["columns"], r["cells"], self.types())]
            out.append(("severity", r["sev"], _sev_word(r["sev"])))
            if r.get("detail"):
                out += [("", "")] + [(it["k"], it["v"], _pair_style(it.get("sev", "ok")))
                                     for it in r["detail"]]
            return out
        if self.kind == "spark" and d["values"]:
            v = d["values"]
            unit = f" {d['unit']}" if d["unit"] else ""
            return [("last", _num(v[-1]) + unit), ("min", _num(min(v)) + unit),
                    ("max", _num(max(v)) + unit), ("points", str(len(v))),
                    ("values", " ".join(_num(x) for x in v))]
        if self.kind == "feed" and i < len(self.view):
            e = self.view[i]
            ago = "" if self.ref is None else f"  ({age(e['ts'], self.ref)} ago)"
            return [("time", self.stampfmt(e["ts"]) + ago), ("severity", e["sev"]),
                    ("source", e["src"]), ("code", e["code"]), ("message", e["msg"])]
        return []

    def roles(self) -> list:
        """Column roles (colors of an ok row): given, else name for the first column,
        value for num / spark, note for age, text for the rest."""
        given = self.data.get("roles")
        if given:
            return list(given)
        return ["name" if j == 0 else {"num": "value", "spark": "value", "age": "note"}
                .get(t, "text") for j, t in enumerate(self.types())]

    def ip_at(self, i: int) -> str | None:
        if self.kind == "table" and 0 <= i < len(self.view):
            return self.view[i].get("ip")
        if self.kind == "kv" and 0 <= i < len(self.data["items"]):
            return self.data["items"][i].get("ip")
        return getattr(self, "src_ip", None) if self.kind == "detail" else None

    def progs_at(self, i: int) -> tuple:
        if self.kind == "table" and 0 <= i < len(self.view):
            return tuple(self.view[i].get("progs", ()))
        if self.kind == "detail":                # c in a detail: the card of its row
            return tuple(getattr(self, "src_progs", ()))
        return ()

    def pick_at(self, i: int) -> str | None:
        if self.kind == "table" and 0 <= i < len(self.view):
            return self.view[i].get("filter")
        return None

    def idents(self, texts: list) -> list:
        """Anchor per body line, stable while ages and severities change: table row id,
        else its raw cells; kv key; event time + source + code + message; else the text."""
        if self.kind == "table" and self.view:
            return [r.get("id") or "  ".join(r["cells"]) for r in self.view]
        if self.kind == "kv" and self.data["items"]:
            return [it["k"] for it in self.data["items"]]
        if self.kind == "feed" and self.view:
            return [f"{e['ts']!r} {e['src']} {e['code']} {e['msg']}" for e in self.view]
        return texts

    def total(self) -> int:
        return len(self.data["rows"] if self.kind == "table" else self.data)


def _detail_rows(pairs: list, w: int, mask: bool, secrets: bool | None = None) -> tuple:
    """key  value lines, long values wrapped under the value column.
    -> (lines, owner): owner[i] = index of the pair that line i belongs to."""
    keys = [display(p[0], mask) for p in pairs]
    kw = min(KEY_MAX, max((cols(k) for k in keys), default=0))
    out, owner = [], []
    for n, (k, pair) in enumerate(zip(keys, pairs)):
        v = pair[1]
        style = pair[2] if len(pair) > 2 else "text"      # a problem line: its color
        if not k and not v:
            out.append([])
            owner.append(n)
            continue
        pieces = wrap(display(v, mask, secrets=secrets), max(1, w - kw - 2))
        for j, piece in enumerate(pieces):
            key = pad(k, kw) + "  " if j == 0 else " " * (kw + 2)
            kstyle = style if style in ("warn", "crit") else "name"
            out.append(_line(w, mask, (key, kstyle), (piece, style)))
            owner.append(n)
    return out, owner


def _found(pairs: list, owner: list, query: str) -> tuple:
    """Pairs of a detail that contain query (case-insensitive, key + value as shown, or
    with public IPs masked: the detail shows real IPs, a table with mask on shows
    160.79.x.x, and that is what gets typed).
    -> (pair index, first line, end line) each; a pair that wraps keeps all its lines."""
    q = query.lower()
    hit = set()
    for n, p in enumerate(pairs):
        s = f"{display(p[0], False)} {display(p[1], False)}"
        if q in s.lower() or q in mask_ips(s).lower():
            hit.add(n)
    out = []
    for line, n in enumerate(owner):
        if n in hit:
            if out and out[-1][0] == n:
                out[-1][2] = line + 1
            else:
                out.append([n, line, line + 1])
    return tuple(tuple(x) for x in out)


def _spark(p: dict, w: int, mask: bool) -> list:
    vals = p["values"]
    if not vals:
        return _line(w, mask, ("-", "dim"))
    last = f"  {_num(vals[-1])} {p['unit']}".rstrip()
    room = max(0, w - cols(display(last, mask)))
    vals = vals[-room:] if room else []
    lo, hi = (min(vals), max(vals)) if vals else (0, 0)
    span = hi - lo
    top = len(SPARK) - 1
    bars = "".join(SPARK[0 if span == 0 else round((v - lo) / span * top)] for v in vals)
    return _line(w, mask, (bars, _sev(p["sev"])), (last, "dim"))


def _event(e: dict, width: int, mask: bool, tsfmt, ref=None) -> list:
    """glyph, age (clock time without a reference), source + code, message."""
    when = age(e["ts"], ref) if ref is not None else tsfmt(e["ts"])
    return _line(width, mask, _glyph(e["sev"]), (when.rjust(4) + "  ", "note"),
                 (f"{e['src']} {e['code']} ", "name"), (e["msg"], _pair_style(e["sev"])))


def _boxes(screen, mods: list, feed: list) -> list:
    out = []
    for m in mods:
        for p in m["panels"]:
            out.append(_Box(f"{m['name']}/{p['id']}", p["title"], p["sev"], p["type"], p,
                            stale=m["stale"]))
            if p.get("width") == "full":     # layout hint: a row of its own
                out[-1].full = True
    if screen.feed and mods:
        names = set(screen.modules)
        evs = [e for e in feed if e["src"] in names]
        out.append(_Box(f"{screen.name}/events", f"events  {len(evs)}", "ok", "feed", evs))
    if not out:
        note = screen.note if not mods else "no data yet"
        out.append(_Box(f"{screen.name}/note", screen.name, "ok", "note", [note or "-"]))
    return out


CARD_COLUMNS = ["last", "box", "what"]
CARD_TYPES = ["age", "text", "text"]


def _card(view: list, prog: str, stampfmt=_stamp) -> tuple:
    """Table of a program card: every table row of every module that names prog, box by
    box (module order), rows as the box orders them. A row: its first age cell, the box,
    its other cells; its detail = the columns of its box + its own detail, so enter shows
    everything the box's detail shows. -> (panel, rows, boxes)."""
    rows, n_boxes = [], 0
    for m in view:
        for p in m.get("panels", ()):
            if p.get("type") != "table":
                continue
            hits = [r for r in p["rows"] if prog in r.get("progs", ())]
            if not hits:
                continue
            n_boxes += 1
            types = p.get("types") or ["text"] * len(p["columns"])
            where = f"{m['name']}/{p['id']}"
            for r in hits:
                ages = [c for c, t in zip(r["cells"], types) if t == "age"]
                rest = [spark_text(c) if t == "spark" else c
                        for c, t in zip(r["cells"], types) if t != "age"]
                detail = [{"k": "box title", "v": p["title"]}]
                hot = r.get("sev", "ok")
                for col, c, t in zip(p["columns"], r["cells"], types):
                    when = _when(c) if t == "age" else None
                    v = stampfmt(when) if when is not None else c
                    detail.append({"k": col, "v": spark_text(c) if t == "spark" else v,
                                   "sev": hot})
                detail += list(r.get("detail", ()))
                row = {"cells": [ages[0] if ages else "-", where, "  ".join(rest)],
                       "sev": r.get("sev", "ok"), "id": f"{where}|{r.get('id') or r['cells']}",
                       "detail": detail}
                for k in ("tone", "ip"):
                    if k in r:
                        row[k] = r[k]
                rows.append(row)
    panel = {"id": "card", "title": "", "type": "table", "sev": "ok",
             "columns": list(CARD_COLUMNS), "types": list(CARD_TYPES), "rows": rows}
    return panel, len(rows), n_boxes


def _overlay(boxes: list, ui, mask: bool, tsfmt, view=(), ref=None, stampfmt=_stamp):
    """Help, detail or card box instead of the grid, or None."""
    if ui.help:
        return _Box("help", "keys", "ok", "note", [f"{k:<22}{v}" for k, v in HELP])
    card = getattr(ui, "card", None)
    if card is not None:
        panel, n, nb = _card(view, card, stampfmt)
        title = f"card: {card}   {n} rows in {nb} boxes, all screens"
        cbox = _Box("card", title, "ok", "table", panel)
        cbox.ref, cbox.tsfmt, cbox.stampfmt = ref, tsfmt, stampfmt
        cbox.filt = getattr(ui, "filters", {}).get("card", "")
        if ui.detail != "card":
            return cbox                          # a table: select, / filter, enter detail
        boxes = [cbox]
    if ui.detail is None:
        return None
    b = next((b for b in boxes if b.key == ui.detail), None)
    pairs, ip = [], None
    if b is not None:
        b.measure(mask)
        i = ui.sel.get(b.key, 0)
        pairs = b.pairs(i, tsfmt)
        ip = b.ip_at(i) if pairs else None
    if ip:
        pairs = pairs + [("", "")] + _whois(ui, ip)
    title = f"detail: {b.title}" if b is not None else "detail"
    if mask:
        title += "   real IPs shown"
    box = _Box("detail", title + "   Esc close", "ok", "detail", pairs or [("", "line gone")])
    box.src_ip = ip
    box.src_progs = b.progs_at(i) if b is not None and pairs else ()
    box.find, box.seek, box.mark = (getattr(ui, "find", ""), getattr(ui, "seek", None),
                                    getattr(ui, "mark", None))
    return box


def _whois(ui, ip: str) -> list:
    """whois part of a detail: result, pending, or how to start it."""
    done = getattr(ui, "whois", {})
    if ip in done:
        return [("whois", ip)] + list(done[ip])
    if not public(ip):
        return [("whois", f"{ip}: not a public address, no whois")]
    if getattr(ui, "lookup", None) == ip:
        return [("whois", f"{ip}: looking up (RDAP, up to {LOOKUP_TIMEOUT:g} s) ...")]
    return [("whois", f"{ip}: press w (RDAP by sectop-whois.service, via the tunnel)")]


# --- grid -----------------------------------------------------------------

def _pack(boxes: list, width: int) -> list:
    """Rows of [box, cell width]. Cell = content + 1 space each side.
    A box joins the row while its shrunk width (b.least) fits. A row wider
    than the screen gives cells back from the box with the most room above
    its least width; extra width is shared in the row."""
    rows, cur, used = [], [], 1
    for b in boxes:
        cw = width - 2 if b.full else min(b.w + 2, width - 2)
        least = cw if b.full else min(b.least + 2, cw)
        # sparks (1 line) share a row only with sparks: no tall empty box
        mixed = cur and (b.kind == "spark") != (cur[0][0].kind == "spark")
        if cur and (b.full or mixed or used + least + 1 > width):
            rows.append(cur)
            cur, used = [], 1
        cur.append([b, cw, least])
        used += least + 1
        if b.full:
            rows.append(cur)
            cur, used = [], 1
    if cur:
        rows.append(cur)
    for row in rows:
        over = sum(c[1] + 1 for c in row) + 1 - width
        while over > 0:                      # too wide: shrink the box with most slack
            cell = max(row, key=lambda c: c[1] - c[2])
            if cell[1] <= cell[2]:
                break
            cell[1] -= 1
            over -= 1
        extra = -over                        # share leftover width in the row
        if extra > 0:
            each, rest = divmod(extra, len(row))
            for i, cell in enumerate(row):
                cell[1] += each + (rest if i == len(row) - 1 else 0)
    return [[[b, cw] for b, cw, _ in row] for row in rows]


def _heights(rows: list, room: int) -> list:
    """Content lines per row. room = all lines for the grid (incl. borders)."""
    while rows and room - len(rows) - 1 < len(rows):
        rows.pop()                           # each row needs a border + 1 line
    avail = room - len(rows) - 1
    h = [max(b.h for b, _ in row) for row in rows]
    if not h:
        return h
    if sum(h) < avail:
        grow = [i for i, row in enumerate(rows) if any(b.grow for b, _ in row)]
        h[grow[-1] if grow else -1] += avail - sum(h)
    while sum(h) > avail:                    # shrink the tallest, lower row first
        i = max(range(len(h)), key=lambda j: (h[j], j))
        h[i] -= 1
    return h


def _bars(row: list) -> list:
    xs, x = [0], 0
    for _, cw in row:
        x += cw + 1
        xs.append(x)
    return xs


def _title(b, focused: bool, mask: bool, suffix: str = "") -> list:
    """Left part of a box's top border: title (its own count), stale."""
    t = display(b.title, mask)
    if focused:
        main = (f"[{t}]", "focus")
    else:
        main = (f" {t} ", "title" if b.sev == "ok" else b.sev)
    out = [main]
    if b.stale:
        suffix += "  (stale)"
    if suffix:
        out.append((suffix + " ", "dim"))
    return out


def _state(b, mark, off: int, vis: int, n: int, room: int) -> str:
    """Right part of a box's top border: filter, detail search, position. Too long for
    the room: the counts without the typed text (the footer shows it while typing),
    still too long: nothing."""
    full, short = [], []
    if b.filt:
        count = f"{len(b.view)} of {b.total()}"
        full.append(f"/ {b.filt}  {count}")
        short.append(count)
    if b.find.strip():
        at = [f[0] for f in b.found].index(mark) + 1 if mark is not None else "-"
        count = f"{at}/{len(b.found)}" if b.found else "no match"
        full.append(f"/ {b.find}  {count}")
        short.append(count)
    if n > vis > 0:
        pos = f"{off + 1}-{min(off + vis, n)}/{n}"
        full.append(pos)
        short.append(pos)
    for parts in (full, short):
        s = "  ".join(parts)
        if s and cols(s) + 2 <= room:
            return s
    return ""


def _border(width: int, above, below, titles: list, rights: list = ()) -> list:
    """Line between rows. above / below: bar x positions or None.
    titles: (x, parts, room) written after the corner at x.
    rights: (x_end, text, room) flush right before the corner at x_end (dim)."""
    a, b = set(above or ()), set(below or ())
    cells = []
    for x in range(width):
        if x == 0:
            c = TL if above is None else (BL if below is None else LT)
        elif x == width - 1:
            c = TR if above is None else (BR if below is None else RT)
        elif x in a and x in b:
            c = CROSS
        elif x in b:
            c = TD
        elif x in a:
            c = TU
        else:
            c = BH
        cells.append([c, "frame"])
    for x, parts, room in titles:
        pos, left = x + 2, room
        for text, style in parts:
            for ch in fit(text, left):
                w = _cw(ch)
                if w == 0 or pos + w > width - 1 or left < w:
                    continue
                cells[pos] = [ch, style]
                for k in range(1, w):
                    cells[pos + k] = ["", style]
                pos += w
                left -= w
    for x_end, text, room in rights:
        s = " " + text + " " if cols(text) + 2 <= room else ""
        pos = x_end - 1 - cols(s)
        for ch in s:
            w = _cw(ch)
            if w == 0 or pos < 1 or pos + w > width - 1:
                pos += w
                continue
            cells[pos] = [ch, "dim"]
            for k in range(1, w):
                cells[pos + k] = ["", "dim"]
            pos += w
    out = []
    for ch, style in cells:
        if out and out[-1][1] == style:
            out[-1][0] += ch
        else:
            out.append([ch, style])
    return [(t, s) for t, s in out if t]


def _select(ui, key: str, texts: list, vis: int) -> tuple:
    """-> (sel, off) for a box: anchored cursor, kept inside the visible part."""
    n = len(texts)
    sel = ui.sel.get(key, 0)
    ident = ui.anchor.get(key)
    if sel > 0 and ident is not None:           # line 0 = follow the newest line
        hits = [i for i, t in enumerate(texts) if t == ident]
        if hits:
            sel = min(hits, key=lambda i: abs(i - sel))
    sel = min(max(sel, 0), max(0, n - 1))
    off = ui.scroll.get(key, 0)
    if vis > 0:
        if sel < off:
            off = sel
        elif sel >= off + vis:
            off = sel - vis + 1
    off = min(max(off, 0), max(0, n - vis))
    return sel, off


def _seek(b, off: int, vis: int, n: int) -> tuple:
    """Detail search -> (current match as pair index or None, first visible line).
    b.seek asks for a move: first match, next / previous (wraps); from the top line when
    there is no current match (scrolled by hand). The match is scrolled into view
    (a third of the box from the top) only when it was not fully visible."""
    pairs = [f[0] for f in b.found]
    mark = b.mark if b.mark in pairs else None
    if b.seek == "first":
        mark = pairs[0]
    elif b.seek in ("next", "prev"):
        step = 1 if b.seek == "next" else -1
        if mark is not None:
            mark = pairs[(pairs.index(mark) + step) % len(pairs)]
        elif step > 0:
            mark = next((p for p, start, _ in b.found if start >= off), pairs[0])
        else:
            mark = next((p for p, start, _ in reversed(b.found) if start < off), pairs[-1])
    if b.seek and mark is not None:
        _, start, end = next(f for f in b.found if f[0] == mark)
        if start < off or end > off + vis:
            off = min(max(start - vis // 3, 0), max(0, n - vis))
    return mark, off


def _lit(line: list, current: bool) -> list:
    """A line that matches the detail search: bold; the current match also reverse."""
    style = (SEL if current else "") + BOLD
    return [(t, style + s) for t, s in line]


def _pick_focus(want, pref, boxes: list):
    keys = [b.key for b in boxes]
    if want in keys:
        return want
    if pref in keys:
        return pref
    tables = [b.key for b in boxes if b.kind in ("table", "feed")]
    return tables[0] if tables else (keys[0] if keys else None)


def _grid(boxes: list, ui, width: int, room: int, mask: bool, tsfmt, pref) -> tuple:
    if width < GRID_MIN or room < 3:
        return [], (), None
    for b in boxes:
        b.measure(mask)
    rows = _pack(boxes, width)
    hs = _heights(rows, room)
    rows = rows[:len(hs)]
    shown = [b for row in rows for b, _ in row]
    focus = _pick_focus(None if len(shown) == 1 and not shown[0].cursor
                        else ui.focus.get(ui.screen), pref, shown)

    lines, infos, above = [], [], None
    for row, hr in zip(rows, hs):
        xs = _bars(row)
        titles, rights, cells = [], [], []
        for (b, cw), x, x_end in zip(row, xs, xs[1:]):
            inner = max(0, cw - 2)
            head, body = b.content(inner, mask, tsfmt)
            vis = max(0, hr - len(head))
            ids = b.idents([_text(line) for line in body])
            sel, off = _select(ui, b.key, ids, vis)
            mark = None
            if b.found:                          # detail search: seek, mark
                mark, off = _seek(b, off, vis, len(body))
                if b.seek:
                    sel = off
            infos.append(BoxInfo(b.key, len(body), vis, sel, off,
                                 ids[sel] if ids and b.cursor else None, b.cursor,
                                 b.filterable, b.ip_at(sel), b.pick_at(sel), mark,
                                 b.progs_at(sel)))
            on = b.key == focus
            left = _title(b, on and b.cursor, mask)
            titles.append((x, left, max(0, cw - 3)))
            room = cw - 3 - _len(left) - 1           # flush right, never over the title
            state = _state(b, mark, off, vis, len(body), room)
            if state:
                rights.append((x_end, state, room))
            now = {n for p, s, e in b.found if p == mark for n in range(s, e)}
            lit = {n for _, s, e in b.found for n in range(s, e)}
            shown_body = [_hi(line) if on and b.cursor and off + i == sel
                          else _lit(line, off + i in now) if off + i in lit else line
                          for i, line in enumerate(body[off:off + vis])]
            hi = {len(head) + sel - off} if on and b.cursor else {
                len(head) + n - off for n in now}
            cells.append((cw, (head + shown_body)[:hr], hi))
        lines.append(_border(width, above, xs, titles, rights))
        for i in range(hr):
            parts = [(BV, "frame")]
            for cw, content, hi in cells:
                line = content[i] if i < len(content) else []
                fill = cw - min(cw, 1) - _len(line)
                style = SEL + "plain" if i in hi else "plain"
                parts += ([(" ", style)] if cw else []) + line
                parts += [(" " * fill, style), (BV, "frame")]
            lines.append([(t, s) for t, s in parts if t])
        above = xs
    if rows:
        lines.append(_border(width, above, None, []))
    return lines, tuple(infos), focus


def _hi(line: list) -> list:
    """Selected line: same colors, reverse video."""
    return [(t, SEL + s) for t, s in line] or [(" ", SEL + "plain")]


# --- layout ---------------------------------------------------------------

def layout(screens, view: list, feed: list, ui, width: int, height: int,
           now: float | None = None, tsfmt=_ts, alerts=(), ref: float | None = None,
           stampfmt=_stamp) -> Frame:
    """Frame for the current screen: at most height lines of at most width cells.
    alerts: core/alerts.py active() (the alert bar). ref: time the ages count from
    (default now; paused: the pause moment). No ref and no now: clock times."""
    if width <= 0 or height <= 0:
        return Frame([], ())
    mask = ui.mask
    scr = screens[ui.screen]
    by_name = {m["name"]: m for m in view}
    mods = [by_name[n] for n in scr.modules if n in by_name]

    bar, shown = _alerts(view, list(alerts), getattr(ui, "acks", {}), mask, width)
    top = [_tabs(screens, ui, width, now, tsfmt), bar]
    top += [_header(m, width, mask) for m in mods]
    if len(top) >= height:
        return Frame(top[:height], (), alerts=shown)
    room = height - len(top)
    footer = [_footer(len(screens), width, ui)] if room >= 4 else []
    room -= len(footer)
    boxes = _boxes(scr, mods, feed)
    filters = getattr(ui, "filters", {})
    ref = now if ref is None else ref
    for b in boxes:
        b.ref, b.tsfmt, b.stampfmt = ref, tsfmt, stampfmt
        if b.filterable:
            b.filt = filters.get(b.key, "")
    over = _overlay(boxes, ui, mask, tsfmt, view, ref, stampfmt)
    if over is not None:
        over.ref, over.tsfmt, over.stampfmt = ref, tsfmt, stampfmt
        over.secrets = mask                  # m shows the raw argv, like the IPs
        boxes = [over]
    grid, infos, focus = _grid(boxes, ui, width, room, mask, tsfmt,
                               getattr(scr, "focus", None))
    return Frame(top + grid + footer, infos, focus, shown)


# --- curses ---------------------------------------------------------------

def setup(stdscr) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    try:
        curses.set_escdelay(25)              # Esc closes at once, not after 1 s
    except (AttributeError, curses.error):
        pass
    plain = curses.A_NORMAL
    _ATTR.update(plain=plain, title=curses.A_BOLD, dim=curses.A_DIM, off=curses.A_DIM,
                 focus=curses.A_REVERSE | curses.A_BOLD, tabon=curses.A_REVERSE | curses.A_BOLD,
                 head=curses.A_BOLD | curses.A_UNDERLINE, name=plain, text=plain,
                 value=plain, high=curses.A_BOLD, peak=plain, note=plain, frame=plain)
    if not curses.has_colors():
        _ATTR.update(ok=plain, info=plain, warn=curses.A_BOLD,
                     crit=curses.A_BOLD | curses.A_REVERSE, unknown=curses.A_DIM,
                     red=plain, blue=plain, yellow=plain, green=plain)
        return
    curses.start_color()
    colors = dict(COLORS_256 if getattr(curses, "COLORS", 8) >= 256 else COLORS_8)
    bg = curses.COLOR_BLACK
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        pass
    for i, (style, fg) in enumerate(colors.items(), start=1):
        curses.init_pair(i, fg, bg)
        _ATTR[style] = curses.color_pair(i)
    title = _ATTR["title"]
    _ATTR["crit"] |= curses.A_BOLD
    _ATTR["title"] = title | curses.A_BOLD
    _ATTR["head"] = title | curses.A_BOLD | curses.A_UNDERLINE
    _ATTR["focus"] = title | curses.A_REVERSE | curses.A_BOLD
    _ATTR["tabon"] = title | curses.A_REVERSE | curses.A_BOLD
    _ATTR["value"] |= curses.A_BOLD
    _ATTR["high"] |= curses.A_BOLD


def attr(style: str) -> int:
    extra = curses.A_NORMAL
    if style.startswith(SEL):
        style, extra = style[len(SEL):], extra | curses.A_REVERSE
    if style.startswith(BOLD):
        style, extra = style[len(BOLD):], extra | curses.A_BOLD
    return _ATTR.get(style, curses.A_NORMAL) | extra


def _paint(stdscr, y: int, line: list) -> None:
    x = 0
    for text, style in line:
        try:
            stdscr.addstr(y, x, text, attr(style))
        except curses.error:
            pass
        x += cols(text)


def draw_top(stdscr, screens, ui, now: float) -> None:
    """Only the tabs line (clock), between full redraws."""
    h, w = stdscr.getmaxyx()
    if h < 1 or w < 2:
        return
    stdscr.move(0, 0)
    stdscr.clrtoeol()
    _paint(stdscr, 0, _tabs(screens, ui, w - 1, now, _ts))
    stdscr.refresh()


def draw(stdscr, screens, view: list, feed: list, ui, now: float | None = None,
         alerts=(), ref: float | None = None) -> Frame:
    h, w = stdscr.getmaxyx()
    # w - 1: writing the last cell of a line can raise in curses.
    frame = layout(screens, view, feed, ui, w - 1, h, now, alerts=alerts, ref=ref)
    stdscr.erase()
    for y, line in enumerate(frame.lines):
        _paint(stdscr, y, line)
    stdscr.refresh()
    return frame
