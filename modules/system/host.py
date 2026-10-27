"""Host readers for the system box: parsers are pure (text in, numbers out), Host reads
the files under a root (tests: a fake tree in tests/fixtures/system/).

Sources (docs/architecture.md, Processes screen, Sources): /proc/stat, /proc/meminfo,
/proc/loadavg, /proc/pressure/*, /proc/diskstats, /sys/block, /sys/class/hwmon.
No commands, no root. Sizes in bytes, temperatures in C.
"""

import os
from dataclasses import dataclass

SECTOR = 512                     # /proc/diskstats sectors: always 512 bytes (kernel docs)
SKIP_DISKS = ("loop", "ram", "zram", "dm-")   # zram = swap (swap row), dm = same io as
                                              # the disk under it
NO_LIMIT = 200.0                 # a temp limit above this is not set (nvme: 65261.8 C)
MAX_READ = 64 * 1024
PSI = ("cpu", "memory", "io")


def cpu_times(text: str) -> tuple:
    """/proc/stat -> (busy, total, cpus). Jiffies of the `cpu` line: user nice system
    idle iowait irq softirq steal (guest is inside user); idle + iowait = not busy."""
    busy = total = None
    cpus = 0
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "cpu":
            v = [int(x) for x in f[1:9]]
            if len(v) < 4:
                raise ValueError("cpu line: too few fields")
            total = sum(v)
            busy = total - v[3] - (v[4] if len(v) > 4 else 0)
        elif f[0].startswith("cpu") and f[0][3:].isdigit():
            cpus += 1
    if total is None:
        raise ValueError("no cpu line")
    return busy, total, cpus


def meminfo(text: str) -> dict:
    """/proc/meminfo -> {key: bytes} for MemTotal, MemAvailable, SwapTotal, SwapFree."""
    want = ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")
    out = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key in want:
            f = rest.split()
            out[key] = int(f[0]) * (1024 if f[1:] == ["kB"] else 1)
    missing = [k for k in want if k not in out]
    if missing:
        raise ValueError("meminfo: no " + ", ".join(missing))
    return out


def loadavg(text: str) -> tuple:
    """/proc/loadavg -> (1, 5, 15 min)."""
    f = text.split()
    if len(f) < 3:
        raise ValueError("loadavg: too few fields")
    return float(f[0]), float(f[1]), float(f[2])


def pressure(text: str) -> dict:
    """/proc/pressure/<x> -> {"some": {"avg10": .., "avg60": ..}, "full": {..}} in %.
    cpu has a full line on newer kernels (always 0 for the whole system)."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        if not f or f[0] not in ("some", "full"):
            continue
        vals = dict(x.split("=", 1) for x in f[1:] if "=" in x)
        out[f[0]] = {k: float(vals[k]) for k in ("avg10", "avg60")}
    if "some" not in out:
        raise ValueError("pressure: no some line")
    return out


def diskstats(text: str, disks) -> dict:
    """/proc/diskstats -> {name: (bytes read, bytes written)} for the given disks."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 10 and f[2] in disks:
            out[f[2]] = (int(f[5]) * SECTOR, int(f[9]) * SECTOR)
    return out


def whole_disks(names) -> list:
    """/sys/block entries -> disks shown (no partitions there; loop, ram, zram, dm
    left out)."""
    return sorted(n for n in names if not n.startswith(SKIP_DISKS))


def limit(milli: str | None) -> float | None:
    """temp*_max / _crit file text (millidegree) -> C, None when missing or not set."""
    if milli is None:
        return None
    v = int(milli.strip()) / 1000
    return v if v <= NO_LIMIT else None


@dataclass(frozen=True)
class Sensor:
    hw: str              # hwmon name: coretemp, nvme, spd5118
    device: str          # basename of the hwmon's device link: coretemp.0, nvme0, 14-0050
    n: str               # temp<n>
    label: str           # temp<n>_label, "" if none
    temp: float          # C
    max: float | None
    crit: float | None

    @property
    def key(self) -> str:
        """Stable id (the hwmon number changes per boot): name:device:temp<n>."""
        return f"{self.hw}:{self.device}:temp{self.n}"


def wanted(rules, hw: str, label: str) -> bool:
    """rules: ("coretemp:Package id 0", "spd5118", ...): hwmon name, optional label."""
    for r in rules:
        name, sep, lab = r.partition(":")
        if name == hw and (not sep or lab == label):
            return True
    return False


class Host:
    """Files under root ("/" on the host)."""

    def __init__(self, root: str = "/"):
        self.root = root

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/"))

    def read(self, p: str) -> str:
        with open(self.path(p), encoding="ascii", errors="replace") as f:
            return f.read(MAX_READ)

    def maybe(self, p: str) -> str | None:
        try:
            return self.read(p)
        except FileNotFoundError:
            return None

    def listdir(self, p: str) -> list:
        return sorted(os.listdir(self.path(p)))

    def statvfs(self, p: str) -> tuple:
        """-> (free bytes for non-root, size bytes)."""
        st = os.statvfs(self.path(p))
        return st.f_bavail * st.f_frsize, st.f_blocks * st.f_frsize

    def disks(self) -> list:
        return whole_disks(self.listdir("/sys/block"))

    def sensors(self, rules) -> list:
        """Temperature sensors that match rules, sorted by rules order then device."""
        out = []
        base = "/sys/class/hwmon"
        for h in self.listdir(base):
            d = f"{base}/{h}"
            hw = (self.maybe(f"{d}/name") or "").strip()
            if not any(r.partition(":")[0] == hw for r in rules):
                continue
            try:
                device = os.path.basename(os.readlink(self.path(f"{d}/device")))
            except OSError:
                device = h
            for f in self.listdir(d):
                if not (f.startswith("temp") and f.endswith("_input")):
                    continue
                n = f[4:-len("_input")]
                label = (self.maybe(f"{d}/temp{n}_label") or "").strip()
                if not wanted(rules, hw, label):
                    continue
                try:
                    temp = int(self.read(f"{d}/temp{n}_input").strip()) / 1000
                except (OSError, ValueError):
                    continue             # gone, or ENODATA / EIO while a device sleeps
                out.append(Sensor(hw, device, n, label, temp,
                                  limit(self.maybe(f"{d}/temp{n}_max")),
                                  limit(self.maybe(f"{d}/temp{n}_crit"))))
        order = {r.partition(":")[0]: i for i, r in reversed(list(enumerate(rules)))}
        return sorted(out, key=lambda s: (order.get(s.hw, 99), s.device, int(s.n)))
