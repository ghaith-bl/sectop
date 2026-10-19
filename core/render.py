"""Draw core's view in the terminal.

layout() is pure: view + feed -> list of lines, each a list of
(text, style). draw() only paints those lines with curses.
Every string passes sanitize.display() inside _line(), so nothing
reaches the terminal without clean -> mask. Width is counted in
terminal cells (wide chars = 2, combining marks = 0).
"""

import curses
import time
import unicodedata

from core.sanitize import TRUNC, display

TAGS = {"ok": "OK", "info": "INFO", "warn": "WARN", "crit": "CRIT",
        "unknown": "??", "off": "OFF"}
TAG_W = 6                                    # "[CRIT]"
SPARK = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
EVENTS_MIN = 6                               # feed lines kept on a short screen
KEY_MAX = 24                                 # kv key column
COL_MAX = 40                                 # table column
INDENT = 2

_ATTR = {}                                   # style -> curses attr, set in setup()


# --- cells ----------------------------------------------------------------

def _cw(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def cols(s: str) -> int:
    """Terminal cells used by s."""
    return sum(_cw(ch) for ch in s)


def fit(s: str, width: int) -> str:
    """Cut s to width cells, last cell TRUNC if cut."""
    if width <= 0:
        return ""
    if cols(s) <= width:
        return s
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


def _sev(sev: str) -> str:
    """ok values are drawn plain: only problems get color."""
    return "plain" if sev == "ok" else sev


def _num(v) -> str:
    return f"{v:g}" if isinstance(v, float) else str(v)


# --- blocks ---------------------------------------------------------------

def _header(m: dict, width: int, mask: bool) -> list:
    tag = f"[{TAGS.get(m['status'], '??')}]".ljust(TAG_W)
    parts = [(tag, m["status"]), (f" {m['name']}", "title"), (f"  {m['summary']}", "plain")]
    for flag in m["flags"]:
        style = "warn" if flag.startswith(("error", "failed", "backoff", "slow")) else "dim"
        parts.append((f"  | {flag}", style))
    return _line(width, mask, *parts)


def _kv(p: dict, width: int, mask: bool, ind: str) -> list:
    keys = [display(it["k"], mask) for it in p["items"]]
    kw = min(KEY_MAX, max((cols(k) for k in keys), default=0))
    return [_line(width, mask, (ind + pad(k, kw) + "  ", "dim"), (it["v"], _sev(it["sev"])))
            for k, it in zip(keys, p["items"])]


def _table(p: dict, width: int, mask: bool, ind: str) -> list:
    head = [display(c, mask) for c in p["columns"]]
    rows = [[display(c, mask) for c in r["cells"]] for r in p["rows"]]
    widths = [min(COL_MAX, max(cols(c) for c in col)) for col in zip(head, *rows)]

    def row(cells):
        return ind + "  ".join(pad(c, w) for c, w in zip(cells, widths)).rstrip()

    out = [_line(width, mask, (row(head), "dim"))]
    out += [_line(width, mask, (row(cells), _sev(r["sev"]))) for cells, r in zip(rows, p["rows"])]
    return out


def _spark(p: dict, width: int, mask: bool, ind: str) -> list:
    vals = p["values"]
    if not vals:
        return [_line(width, mask, (ind + "-", "dim"))]
    last = f"  {_num(vals[-1])} {p['unit']}".rstrip()
    room = max(0, width - len(ind) - cols(display(last, mask)))
    vals = vals[-room:] if room else []
    lo, hi = (min(vals), max(vals)) if vals else (0, 0)
    span = hi - lo
    top = len(SPARK) - 1
    bars = "".join(SPARK[0 if span == 0 else round((v - lo) / span * top)] for v in vals)
    return [_line(width, mask, (ind + bars, _sev(p["sev"])), (last, "dim"))]


_PANEL = {"kv": _kv, "table": _table, "spark": _spark}


def _panel(p: dict, width: int, mask: bool, stale: bool) -> list:
    ind = " " * INDENT
    title = [(ind + p["title"], "title" if p["sev"] == "ok" else p["sev"])]
    if stale:
        title.append(("  (stale)", "dim"))
    return [_line(width, mask, *title)] + _PANEL[p["type"]](p, width, mask, ind * 2)


def _ts(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _event(e: dict, width: int, mask: bool, tsfmt) -> list:
    return _line(width, mask, (tsfmt(e["ts"]) + " ", "dim"),
                 (e["sev"].upper().ljust(4) + " ", e["sev"]),
                 (f"{e['src']} {e['code']} ", "dim"), (e["msg"], "plain"))


# --- layout ---------------------------------------------------------------

def layout(view: list, feed: list, mask: bool, width: int, height: int, tsfmt=_ts) -> list:
    """Lines for the screen, at most height lines of at most width cells."""
    if width <= 0 or height <= 0:
        return []
    top = [_line(width, mask, ("sectop", "title"),
                 (f"  mask {'on' if mask else 'off'}  m: mask  q: quit", "dim"))]

    body = []
    for m in view:
        body.append(_header(m, width, mask))
        for p in m["panels"]:
            body += _panel(p, width, mask, m["stale"])

    ev = [_line(width, mask, ("events", "title"), (f"  {len(feed)}", "dim"))]
    ev += [_event(e, width, mask, tsfmt) for e in feed]
    if not feed:
        ev.append(_line(width, mask, (" " * INDENT + "-", "dim")))

    room = height - len(top)
    if room <= 0:
        return top[:height]
    if len(body) + 1 + len(ev) <= room:
        return top + body + [[]] + ev
    ev_room = min(len(ev), max(EVENTS_MIN, room - len(body) - 1), room)
    body_room = room - ev_room
    if body_room <= 0:
        return top + ev[:room]
    if len(body) + 1 > body_room:
        hidden = len(body) - (body_room - 1)
        body = body[:body_room - 1] + [_line(width, mask, (f"... {hidden} more lines", "dim"))]
    else:
        body = body + [[]]
    return top + body + ev[:ev_room]


# --- curses ---------------------------------------------------------------

def setup(stdscr) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    plain = curses.A_NORMAL
    _ATTR.update(plain=plain, title=curses.A_BOLD, dim=curses.A_DIM, off=curses.A_DIM)
    colors = {"ok": curses.COLOR_GREEN, "info": curses.COLOR_CYAN,
              "warn": curses.COLOR_YELLOW, "crit": curses.COLOR_RED,
              "unknown": curses.COLOR_MAGENTA}
    if not curses.has_colors():
        _ATTR.update(ok=plain, info=plain, warn=curses.A_BOLD,
                     crit=curses.A_BOLD | curses.A_REVERSE, unknown=curses.A_DIM)
        return
    curses.start_color()
    bg = curses.COLOR_BLACK
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        pass
    for i, (style, fg) in enumerate(colors.items(), start=1):
        curses.init_pair(i, fg, bg)
        _ATTR[style] = curses.color_pair(i)
    _ATTR["crit"] |= curses.A_BOLD


def draw(stdscr, view: list, feed: list, mask: bool) -> None:
    h, w = stdscr.getmaxyx()
    stdscr.erase()
    # w - 1: writing the last cell of a line can raise in curses.
    for y, line in enumerate(layout(view, feed, mask, w - 1, h)):
        x = 0
        for text, style in line:
            try:
                stdscr.addstr(y, x, text, _ATTR.get(style, curses.A_NORMAL))
            except curses.error:
                pass
            x += cols(text)
    stdscr.refresh()
