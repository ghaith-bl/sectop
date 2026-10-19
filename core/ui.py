"""UI state and key handling. Pure: no curses calls, only key constants.

The renderer reports what the last frame showed (Frame: boxes + focus).
Each BoxInfo has the box key, body lines, visible lines, the selected
line, the first visible line and the selected line's text (anchor).
Keys act on that: focus moves between those boxes, the cursor moves in
the focused box, the renderer keeps it visible.

Overlays (help, detail) take the whole grid. In an overlay, q / Esc
close it instead of quitting.
"""

import curses
from dataclasses import dataclass, field

TAB = 9
ESC = 27
ENTER_KEYS = (10, 13, curses.KEY_ENTER)
BACK_KEYS = (ESC, curses.KEY_BACKSPACE, 127, 8)
BIG = 1 << 30


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
    anchor: dict = field(default_factory=dict)   # box key -> text of the selected line
    boxes: tuple = ()                            # BoxInfo of the last frame
    _auto_pause: bool = False                    # pause came from opening detail

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
        if k in (ord("m"), ord("M")):
            self.mask = not self.mask
        elif k in (ord("p"), ord("P")):
            self.paused = not self.paused
            self._auto_pause = False
        elif self.overlay:
            if k in BACK_KEYS + ENTER_KEYS + (ord("q"), ord("Q"), ord("?")):
                self._close()
            else:
                self._move_key(k)
        elif k in (ord("q"), ord("Q")):
            return False
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

    # --- helpers ----------------------------------------------------------

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
