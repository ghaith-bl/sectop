"""UI state and key handling. Pure: no curses calls, only key constants.

The renderer reports what the last frame showed (Frame: boxes + focus).
Each BoxInfo has the box key, body lines, visible lines, the selected
line, the first visible line and the selected line's text (anchor).
Keys act on that: focus moves between those boxes, the cursor moves in
the focused box, the renderer keeps it visible.

Overlays (help, detail) take the whole grid. In an overlay, q / Esc
close it instead of quitting.

whois: w on a line with an address (table row / kv item `ip`) opens its
detail and asks core for a lookup (ui.lookup). core/app.py runs it and
calls done(). Results are kept per address for the session.

Filter: / starts typing a filter for the focused table / events box. Every
key is text until enter (keep) or Esc (back to the old filter). The filter
applies while typing. Esc outside typing clears the focused box's filter.

Detail search: / in a detail types a text; the detail shows the lines that contain it
in bold and jumps to the first one (applied while typing; enter keeps it, Esc goes
back to the text before). n / N: next / previous match. Opened from a table with a
one-word filter, the detail starts at the first line with that word. The renderer
resolves the jump (ui.seek -> BoxInfo.mark): it knows where the wrapped lines are.

Follow / hide (rows with a `filter`, e.g. programs): f sets that filter on
the other filterable boxes of the screen (f again: clears them). x adds
!filter (one word) to every filterable box of the screen. Both are plain
filters: shown in the box titles, Esc clears.

Card: c on a row with `progs` (program names) opens the program card of its first
program: every row of every box of every screen that names the same program, box by box
(docs/architecture.md, Program card). A table overlay (box key "card"): select, / filter,
enter = the detail of that row (Esc: back to the card), Esc closes. Pauses while open.
c in the detail of such a row opens its card too (2026-10-27: c from the detail did
nothing). c on a line without a program: the footer says so (ui.hint, until the next
key), instead of nothing.

Ack: a acks every engine alert in the last alert bar (Frame.alerts): key ->
(count, sev) at ack. render.acked() dims it until its count or severity
rises. Kept here, not in core: the channel stays one-way (docs/architecture.md).
Phase 2: memory only (sectop still runs as root).
"""

import curses
from dataclasses import dataclass, field

TAB = 9
ESC = 27
ENTER_KEYS = (10, 13, curses.KEY_ENTER)
BACK_KEYS = (ESC, curses.KEY_BACKSPACE, 127, 8)
BIG = 1 << 30
FILTER_MAX = 60
WHOIS_MAX = 100          # lookups kept
BACKSPACE = (curses.KEY_BACKSPACE, 127, 8)


@dataclass
class UI:
    n_screens: int
    screen: int = 0
    mask: bool = True
    help: bool = False
    paused: bool = False
    detail: str | None = None        # box key whose selected line is shown in detail
    card: str | None = None          # program whose card is shown (c)
    focus: dict = field(default_factory=dict)    # screen index -> box key
    sel: dict = field(default_factory=dict)      # box key -> selected body line
    scroll: dict = field(default_factory=dict)   # box key -> first visible body line
    anchor: dict = field(default_factory=dict)   # box key -> row id / text of the selected line
    filters: dict = field(default_factory=dict)  # box key -> filter text
    typing: str | None = None                    # filter / search being typed (None = not typing)
    find: str = ""                               # detail search text
    seek: str | None = None                      # detail search move asked: first / next / prev
    mark: int | None = None                      # detail search: current match (pair index)
    whois: dict = field(default_factory=dict)    # ip -> [(key, value)], oldest first
    lookup: str | None = None                    # ip waiting for a lookup (core runs it)
    acks: dict = field(default_factory=dict)     # alert key -> (count, sev) at ack
    bar: tuple = ()                              # (key, count, sev) in the last alert bar
    hint: str = ""                               # why the last key did nothing (footer)
    boxes: tuple = ()                            # BoxInfo of the last frame
    _auto_pause: bool = False                    # pause came from opening detail
    _typing_box: str | None = None
    _typing_old: str = ""

    def update(self, frame) -> None:
        """Take what the renderer resolved (focus, cursor, scroll)."""
        self.boxes = frame.boxes
        self.bar = frame.alerts
        for b in frame.boxes:
            self.sel[b.key], self.scroll[b.key], self.anchor[b.key] = b.sel, b.off, b.ident
            if b.key == "detail":
                self.mark = b.mark
        self.seek = None                         # the frame did the move
        if frame.focus is not None and not self.overlay:
            self.focus[self.screen] = frame.focus

    @property
    def overlay(self) -> bool:
        return self.help or self.detail is not None or self.card is not None

    def focused(self) -> str | None:
        keys = [b.key for b in self.boxes]
        if self.overlay:
            return keys[0] if keys else None
        want = self.focus.get(self.screen)
        return want if want in keys else (keys[0] if keys else None)

    def key(self, k: int) -> bool:
        """Apply one key. Returns False to quit."""
        self.hint = ""
        if self.typing is not None:
            self._type(k)
            return True
        if k in (ord("m"), ord("M")):
            self.mask = not self.mask
        elif k in (ord("p"), ord("P")):
            self.paused = not self.paused
            self._auto_pause = False
        elif k in (ord("w"), ord("W")):
            self._whois()
        elif k in (ord("a"), ord("A")):
            self._ack()
        elif self.overlay:
            if k in (ord("c"), ord("C")) and self.card is None and self.detail is not None:
                self._card()                         # the card of the detail's row
            elif k in ENTER_KEYS and self.card is not None and self.detail is None:
                self._open()                         # the selected card row's detail
            elif k in BACK_KEYS + ENTER_KEYS + (ord("q"), ord("Q"), ord("?")):
                self._close()
            elif k == ord("/") and self.detail is None and self.card is not None:
                self._typing_box, self._typing_old = "card", self.filters.get("card", "")
                self.typing = self._typing_old       # filter the card like a table
            elif k == ord("/") and self.detail is not None:
                self._typing_box, self._typing_old = "detail", self.find
                self.typing = self.find
            elif k in (ord("n"), ord("N")) and self.detail is not None:
                if self.find.strip():
                    self.seek = "next" if k == ord("n") else "prev"
            else:
                self._move_key(k)
        elif k in (ord("q"), ord("Q")):
            return False
        elif k == ord("/"):
            b = self._box()
            if b is not None and b.filterable:
                self._typing_box, self._typing_old = b.key, self.filters.get(b.key, "")
                self.typing = self._typing_old
        elif k in (ord("f"), ord("F")):
            self._follow()
        elif k in (ord("c"), ord("C")):
            self._card()
        elif k in (ord("x"), ord("X")):
            self._hide()
        elif k == ESC:
            b = self._box()
            if b is not None and self.filters.pop(b.key, None) is not None:
                self._reset(b.key)
        elif k == ord("?"):
            self.help = True
        elif k in ENTER_KEYS:
            self._open()
        elif ord("1") <= k <= ord("9"):
            if k - ord("1") < self.n_screens:
                self.screen = k - ord("1")
        elif k in (TAB, curses.KEY_RIGHT, ord("l")):
            self._cycle(1)
        elif k in (curses.KEY_BTAB, curses.KEY_LEFT, ord("h")):
            self._cycle(-1)
        else:
            self._move_key(k)
        return True

    def _follow(self) -> None:
        b = self._box()
        if b is None or not b.pick:
            return
        targets = [x.key for x in self.boxes if x.filterable and x.key != b.key]
        clear = bool(targets) and all(self.filters.get(t) == b.pick for t in targets)
        for t in targets:
            self._set_filter(t, "" if clear else b.pick)

    def _hide(self) -> None:
        b = self._box()
        if b is None or not b.pick or len(b.pick.split()) != 1:
            return
        word = "!" + b.pick.strip()
        for x in self.boxes:
            cur = self.filters.get(x.key, "")
            if not x.filterable or word in cur.split() or len(cur) + 1 + len(word) > FILTER_MAX:
                continue
            self._set_filter(x.key, f"{cur} {word}".strip())

    def _ack(self) -> None:
        """Ack the alerts in the bar. Acks of alerts no longer in it are dropped
        (one that comes back has a higher count: it shows again anyway)."""
        self.acks = {key: (count, sev) for key, count, sev in self.bar}

    def done(self, ip: str, pairs: list) -> None:
        """Lookup finished (core/app.py)."""
        self.whois.pop(ip, None)
        self.whois[ip] = list(pairs)
        while len(self.whois) > WHOIS_MAX:
            del self.whois[next(iter(self.whois))]
        if self.lookup == ip:
            self.lookup = None

    # --- helpers ----------------------------------------------------------

    def _whois(self) -> None:
        if self.help:
            return
        b = self._box()
        if b is None or not b.ip:
            return
        if self.detail is None:
            self._open()
        if b.ip not in self.whois:
            self.lookup = b.ip

    def _type(self, k: int) -> None:
        key = self._typing_box
        if k == ESC:
            self._apply(key, self._typing_old)
        elif k in ENTER_KEYS:
            self._apply(key, self.typing.strip())
        else:
            if k in BACKSPACE:
                self.typing = self.typing[:-1]
            elif 32 <= k < 127 and len(self.typing) < FILTER_MAX:
                self.typing += chr(k)
            else:
                return
            self._apply(key, self.typing)
            return
        self.typing = self._typing_box = None

    def _apply(self, key: str, text: str) -> None:
        """Typed text -> the filter of a box, or the search of the detail."""
        if key == "detail":
            self._set_find(text)
        else:
            self._set_filter(key, text)

    def _set_find(self, text: str) -> None:
        self.find = text
        self.mark = None
        self.seek = "first" if text.strip() else None

    def _set_filter(self, key: str, text: str) -> None:
        if text.strip():
            self.filters[key] = text
        else:
            self.filters.pop(key, None)
        self._reset(key)

    def _reset(self, key: str) -> None:
        """Filter changed: cursor back to the first line."""
        self.sel[key] = self.scroll[key] = 0
        self.anchor.pop(key, None)

    def _box(self):
        key = self.focused()
        return next((b for b in self.boxes if b.key == key), None)

    def _open(self) -> None:
        b = self._box()
        if b is None or b.lines == 0 or not b.cursor:
            return
        self.detail = b.key
        self.sel["detail"] = self.scroll["detail"] = 0
        self.anchor.pop("detail", None)
        words = [w for w in self.filters.get(b.key, "").split() if not w.startswith("!")]
        self._set_find(words[0] if len(words) == 1 else "")   # land on the filtered line
        if not self.paused:                      # freeze while reading the detail
            self.paused = self._auto_pause = True

    def _card(self) -> None:
        b = self._box()
        if b is None or not b.progs:
            self.hint = "c: no program on this line"
            return
        self.card = b.progs[0]
        self.detail = None                       # from a detail: the card replaces it
        self.sel["card"] = self.scroll["card"] = 0
        self.anchor.pop("card", None)
        self.filters.pop("card", None)
        self._set_find("")
        if not self.paused:                      # freeze while reading the card
            self.paused = self._auto_pause = True

    def _close(self) -> None:
        if self.card is not None and self.detail is not None:
            self.detail = None                   # back to the card, still paused
            self._set_find("")
            return
        self.help, self.detail, self.card = False, None, None
        self._set_find("")
        if self._auto_pause:
            self.paused = self._auto_pause = False

    def _cycle(self, step: int) -> None:
        keys = [b.key for b in self.boxes]
        if not keys:
            return
        i = keys.index(self.focused())
        self.focus[self.screen] = keys[(i + step) % len(keys)]

    def _move_key(self, k: int) -> None:
        b = self._box()
        if b is None:
            return
        page = max(1, b.page - 1)
        step = {ord("j"): 1, curses.KEY_DOWN: 1, ord("k"): -1, curses.KEY_UP: -1,
                ord(" "): page, curses.KEY_NPAGE: page, curses.KEY_PPAGE: -page,
                ord("g"): -BIG, curses.KEY_HOME: -BIG,
                ord("G"): BIG, curses.KEY_END: BIG}.get(k)
        if step is None:
            return
        self.focus[self.screen] = self.focus.get(self.screen) or b.key
        if b.cursor:                             # move the selected line
            self.sel[b.key] = min(max(b.sel + step, 0), max(0, b.lines - 1))
            self.anchor.pop(b.key, None)         # explicit move: no re-anchoring this frame
        else:                                    # overlay text: scroll
            top = max(0, b.lines - b.page)
            self.scroll[b.key] = self.sel[b.key] = min(max(b.off + step, 0), top)
            self.mark = None                     # no current match after a manual scroll
