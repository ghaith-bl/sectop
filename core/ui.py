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
    focus: dict = field(default_factory=dict)    # screen index -> box key
    sel: dict = field(default_factory=dict)      # box key -> selected body line
    scroll: dict = field(default_factory=dict)   # box key -> first visible body line
    anchor: dict = field(default_factory=dict)   # box key -> row id / text of the selected line
    filters: dict = field(default_factory=dict)  # box key -> filter text
    typing: str | None = None                    # filter being typed (None = not typing)
    whois: dict = field(default_factory=dict)    # ip -> [(key, value)], oldest first
    lookup: str | None = None                    # ip waiting for a lookup (core runs it)
    boxes: tuple = ()                            # BoxInfo of the last frame
    _auto_pause: bool = False                    # pause came from opening detail
    _typing_box: str | None = None
    _typing_old: str = ""

    def update(self, frame) -> None:
        """Take what the renderer resolved (focus, cursor, scroll)."""
        self.boxes = frame.boxes
        for b in frame.boxes:
            self.sel[b.key], self.scroll[b.key], self.anchor[b.key] = b.sel, b.off, b.ident
        if frame.focus is not None and not self.overlay:
            self.focus[self.screen] = frame.focus

    @property
    def overlay(self) -> bool:
        return self.help or self.detail is not None

    def focused(self) -> str | None:
        keys = [b.key for b in self.boxes]
        if self.overlay:
            return keys[0] if keys else None
        want = self.focus.get(self.screen)
        return want if want in keys else (keys[0] if keys else None)

    def key(self, k: int) -> bool:
        """Apply one key. Returns False to quit."""
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
        elif self.overlay:
            if k in BACK_KEYS + ENTER_KEYS + (ord("q"), ord("Q"), ord("?")):
                self._close()
            else:
                self._move_key(k)
        elif k in (ord("q"), ord("Q")):
            return False
        elif k == ord("/"):
            b = self._box()
            if b is not None and b.filterable:
                self._typing_box, self._typing_old = b.key, self.filters.get(b.key, "")
                self.typing = self._typing_old
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
            self._set_filter(key, self._typing_old)
        elif k in ENTER_KEYS:
            self._set_filter(key, self.typing.strip())
        else:
            if k in BACKSPACE:
                self.typing = self.typing[:-1]
            elif 32 <= k < 127 and len(self.typing) < FILTER_MAX:
                self.typing += chr(k)
            else:
                return
            self._set_filter(key, self.typing)
            return
        self.typing = self._typing_box = None

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
        if not self.paused:                      # freeze while reading the detail
            self.paused = self._auto_pause = True

    def _close(self) -> None:
        self.help, self.detail = False, None
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
