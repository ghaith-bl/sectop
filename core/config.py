"""Load /etc/sectop/config.toml.

sectop v1 runs as root, so the config must be root-owned and not
writable by others: whoever can write it controls what root runs.
Missing file or directory -> defaults. Anything else wrong -> ConfigError.
"""

import math
import os
import stat
import tomllib
from dataclasses import dataclass, field

from core.module import MIN_INTERVAL, NAME_RE

DEFAULT_PATH = "/etc/sectop/config.toml"
MAX_SIZE = 64 * 1024

CORE_KEYS = {"mask_public_ips"}
MODULE_KEYS = {"enabled", "interval"}  # anything else goes to the module as options


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ModuleConfig:
    enabled: bool = True
    interval: float | None = None      # None = module INTERVAL
    options: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Config:
    mask_public_ips: bool = True
    modules: dict = field(default_factory=dict)   # name -> ModuleConfig

    def module(self, name: str) -> ModuleConfig:
        return self.modules.get(name, ModuleConfig())


def _check_owner(st: os.stat_result, what: str, owner_uid: int) -> None:
    if st.st_uid != owner_uid:
        raise ConfigError(f"{what}: owner uid {st.st_uid}, expected {owner_uid}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{what}: group/other writable")


def read_file(path: str, owner_uid: int) -> bytes | None:
    """Read the file safely. None if it (or its directory) does not exist.
    Also used for /etc/sectop/noise.toml (core/noise.py)."""
    parent = os.path.dirname(os.path.abspath(path))
    try:
        pst = os.lstat(parent)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(pst.st_mode):
        raise ConfigError(f"{parent}: not a directory (symlink?)")
    _check_owner(pst, parent, owner_uid)

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror} (symlink?)") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{path}: not a regular file")
        _check_owner(st, path, owner_uid)
        if st.st_size > MAX_SIZE:
            raise ConfigError(f"{path}: larger than {MAX_SIZE} bytes")
        data = os.read(fd, MAX_SIZE + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_SIZE:
        raise ConfigError(f"{path}: larger than {MAX_SIZE} bytes")
    return data


def _bool(d: dict, key: str, where: str, default: bool) -> bool:
    v = d.get(key, default)
    if not isinstance(v, bool):
        raise ConfigError(f"{where}.{key}: true or false required")
    return v


def _module(name: str, t) -> ModuleConfig:
    where = f"modules.{name}"
    if not NAME_RE.fullmatch(name):
        raise ConfigError(f"{where}: module name must match [a-z0-9_]+")
    if not isinstance(t, dict):
        raise ConfigError(f"{where}: table required")
    interval = t.get("interval")
    if interval is not None:
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) \
                or not math.isfinite(interval) or interval < MIN_INTERVAL:
            raise ConfigError(f"{where}.interval: number >= {MIN_INTERVAL} required")
        interval = float(interval)
    options = {k: v for k, v in t.items() if k not in MODULE_KEYS}
    return ModuleConfig(enabled=_bool(t, "enabled", where, True),
                        interval=interval, options=options)


def parse(data: bytes, path: str = DEFAULT_PATH) -> Config:
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: not UTF-8") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None

    unknown = set(doc) - {"core", "modules"}
    if unknown:
        raise ConfigError(f"unknown table(s): {', '.join(sorted(unknown))}")

    core = doc.get("core", {})
    if not isinstance(core, dict):
        raise ConfigError("core: table required")
    unknown = set(core) - CORE_KEYS
    if unknown:
        raise ConfigError(f"core: unknown key(s): {', '.join(sorted(unknown))}")

    mods = doc.get("modules", {})
    if not isinstance(mods, dict):
        raise ConfigError("modules: table required")

    return Config(
        mask_public_ips=_bool(core, "mask_public_ips", "core", True),
        modules={name: _module(name, t) for name, t in mods.items()},
    )


def load(path: str = DEFAULT_PATH, owner_uid: int = 0) -> Config:
    """owner_uid is 0 in production; tests pass their own uid."""
    data = read_file(path, owner_uid)
    if data is None:
        return Config()
    return parse(data, path)
