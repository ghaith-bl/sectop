"""Module registry: load the modules sectop knows about.

The list is static, in this file. Config can only enable / disable a
listed module, set its interval and pass it options. It can never name
an import path: whoever writes the config must not choose what root
imports.

A module that fails to import, fails check_module(), or raises in
init() is disabled with an error. Other modules are not affected.
A config table for a module that is not listed -> ConfigError.
"""

import copy
import importlib
import re
from dataclasses import dataclass

from core.config import Config, ConfigError
from core.module import check_module

# Import names, in display order. Each is modules/<name>/__init__.py.
MODULES: tuple[str, ...] = ()

IMPORT_RE = re.compile(r"modules\.([a-z0-9_]+)")


@dataclass(frozen=True)
class Loaded:
    name: str                   # <name> from modules.<name>
    import_name: str
    enabled: bool               # from config
    mod: object = None          # None if disabled or import failed
    interval: float = 0.0       # config override or module INTERVAL; 0.0 if not loaded
    state: object = None        # return value of init()
    error: str | None = None    # "<stage>: <ExcType>: <message>"

    @property
    def active(self) -> bool:
        return self.enabled and self.error is None


def _names(import_names) -> dict:
    """import name -> module name. Bad or duplicate entry = bug -> ValueError."""
    out = {}
    for imp in import_names:
        m = IMPORT_RE.fullmatch(imp) if isinstance(imp, str) else None
        if m is None:
            raise ValueError(f"registry: bad entry {imp!r}, expected modules.<name>")
        if imp in out:
            raise ValueError(f"registry: duplicate entry {imp!r}")
        out[imp] = m.group(1)
    return out


def _err(stage: str, e: BaseException) -> str:
    msg = str(e)
    return f"{stage}: {type(e).__name__}: {msg}" if msg else f"{stage}: {type(e).__name__}"


def _load_one(imp: str, name: str, mc) -> Loaded:
    base = {"name": name, "import_name": imp, "enabled": True}
    try:
        mod = importlib.import_module(imp)
    except (Exception, SystemExit) as e:
        return Loaded(**base, error=_err("import", e))
    try:
        check_module(mod)
        if mod.NAME != name:
            raise ValueError(f"NAME {mod.NAME!r} != {name!r}")
    except ValueError as e:
        return Loaded(**base, error=_err("check", e))

    interval = mc.interval if mc.interval is not None else float(mod.INTERVAL)
    try:
        state = mod.init(copy.deepcopy(mc.options))
    except (Exception, SystemExit) as e:
        return Loaded(**base, mod=mod, interval=interval, error=_err("init", e))
    return Loaded(**base, mod=mod, interval=interval, state=state)


def load(config: Config, import_names=MODULES) -> list:
    """Load listed modules in order. Returns list[Loaded].

    Raises ConfigError if config has a table for a module not listed,
    ValueError if the static list itself is wrong.
    """
    names = _names(import_names)
    unknown = set(config.modules) - set(names.values())
    if unknown:
        raise ConfigError(f"modules: unknown module(s): {', '.join(sorted(unknown))}")

    out = []
    for imp, name in names.items():
        mc = config.module(name)
        if not mc.enabled:
            # Not imported at all: disabled code does not run as root.
            out.append(Loaded(name=name, import_name=imp, enabled=False))
            continue
        out.append(_load_one(imp, name, mc))
    return out


def close(loaded) -> list:
    """Call close(state) on active modules, reverse order.

    Errors do not stop the others. Returns list of (name, error str).
    """
    errors = []
    for ld in reversed(loaded):
        if not ld.active:
            continue
        fn = getattr(ld.mod, "close", None)
        if fn is None:
            continue
        try:
            fn(ld.state)
        except (Exception, SystemExit) as e:
            errors.append((ld.name, _err("close", e)))
    return errors
