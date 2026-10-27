"""Screens: what each one shows. Static, like the module list.

Each screen uses the whole terminal. A module is on exactly one screen;
its panels become boxes there, in module order. The alert bar on top
shows problems from all screens.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Screen:
    name: str                   # [a-z]+, also the start argument
    modules: tuple = ()         # module NAMEs, in box order
    feed: bool = False          # events box for these modules
    note: str = ""              # shown while the screen has no modules
    focus: str = ""             # box focused at start (<module>/<panel id>)


SCREENS = (
    Screen("firewall", ("firewall",), focus="firewall/audit"),   # audit box instead of events
    Screen("security", ("security", "posture"), focus="security/commands",   # logs: phase 4
           note="modules security, posture not loaded"),
    Screen("processes", ("system",), focus="system/system",   # services, processes: next
           note="module system not loaded"),
)


def names(screens=SCREENS) -> tuple:
    return tuple(s.name for s in screens)


def find(arg: str, screens=SCREENS) -> int:
    """Screen name or number (1-based) -> index. Unknown -> ValueError."""
    if arg.isdigit() and arg.isascii():
        i = int(arg) - 1
        if 0 <= i < len(screens):
            return i
    for i, s in enumerate(screens):
        if s.name == arg:
            return i
    raise ValueError(f"unknown screen: {arg!r}")
