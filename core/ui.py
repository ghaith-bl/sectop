"""UI state and key handling. Pure: no curses calls, only key constants.

The renderer reports which boxes the last frame showed (BoxInfo: key,
scrollable lines, visible lines). Keys act on that: focus moves between
those boxes, scroll is clamped to what the box can show.
"""

import curses
from dataclasses import dataclass, field

TAB = 9
ESC = 27
BIG = 1 << 30


@dataclass
class UI:
    n_screens: int
    screen: int = 0
    mask: bool = True
    help: bool = False
    focus: dict = field(default_factory=dict)    # screen index -> box key
    scroll: dict = field(default_factory=dict)   # box key -> first body line
    boxes: tuple = ()                            # BoxInfo of the last frame

    def focused(self) -> str | None:
        """Focused box key on this screen. Gone or never set -> first box."""
        return pick_focus(self.focus.get(self.screen), [b.key for b in self.boxes])

    def key(self, k: int) -> bool:
        """Apply one key. Returns False to quit."""
        if k in (ord("q"), ord("Q")):
            return False
        if k in (ord("m"), ord("M")):
            self.mask = not self.mask
        elif self.help:
            if k in (ord("?"), ESC):
                self.help = False
        elif k == ord("?"):
            self.help = True
        elif ord("1") <= k <= ord("9"):
            if k - ord("1") < self.n_screens:
                self.screen = k - ord("1")
        elif k == TAB:
            self._cycle(1)
        elif k == curses.KEY_BTAB:
            self._cycle(-1)
        elif k in (ord("j"), curses.KEY_DOWN):
            self._scroll(1)
        elif k in (ord("k"), curses.KEY_UP):
            self._scroll(-1)
        elif k in (ord(" "), curses.KEY_NPAGE):
            self._scroll(self._page())
        elif k == curses.KEY_PPAGE:
            self._scroll(-self._page())
        elif k in (ord("g"), curses.KEY_HOME):
            self._scroll(-BIG)
        elif k in (ord("G"), curses.KEY_END):
            self._scroll(BIG)
        return True

    # --- helpers ----------------------------------------------------------

    def _box(self):
        key = self.focused()
        return next((b for b in self.boxes if b.key == key), None)

    def _cycle(self, step: int) -> None:
        keys = [b.key for b in self.boxes]
        if not keys:
            return
        i = keys.index(self.focused())
        self.focus[self.screen] = keys[(i + step) % len(keys)]

    def _page(self) -> int:
        b = self._box()
        return max(1, b.page - 1) if b else 1

    def _scroll(self, step: int) -> None:
        b = self._box()
        if b is None:
            return
        top = max(0, b.lines - b.page)
        cur = min(max(self.scroll.get(b.key, 0), 0), top)
        self.scroll[b.key] = min(max(cur + step, 0), top)


def pick_focus(want: str | None, keys: list) -> str | None:
    if want in keys:
        return want
    return keys[0] if keys else None
