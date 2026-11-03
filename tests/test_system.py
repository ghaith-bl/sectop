import os
import shutil
import tempfile
import unittest

import modules.system as system
from core import registry
from core.module import Context, check_module, validate
from core.screens import SCREENS, find
from modules.system import host
from modules.system import procs

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "system", "host")
MIB = 1024 * 1024
STAT0 = "cpu  100000 400 40000 4600000 2600 11000 5000 0 0 0\n"


class FakeHost(host.Host):
    """Fixture tree (copied, so a test can change files) + statvfs per mount."""

    def __init__(self, root):
        super().__init__(root)
        self.free = {"/var": 120 * 1024 * MIB, "/boot": 600 * MIB}
        self.size = {"/var": 400 * 1024 * MIB, "/boot": 1024 * MIB}

    def statvfs(self, p):
        if p not in self.free:
            raise PermissionError(13, "Permission denied")
        return self.free[p], self.size[p]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "host")
        shutil.copytree(FIX, self.root, symlinks=True)
        self.h = FakeHost(self.root)
        self.now = 1000.0
        self.st = system.State(host=self.h, mono=lambda: self.now)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, p, s):
        with open(os.path.join(self.root, p.lstrip("/")), "w") as f:
            f.write(s)

    def temp(self, hwmon, n, milli):
        self.write(f"/sys/class/hwmon/hwmon{hwmon}/temp{n}_input", f"{milli}\n")

    def collect(self, at=None):
        if at is not None:
            self.now = at
        return validate(system.collect(self.st, Context()))


def rows(snap):
    return {r["id"]: r for r in snap["panels"][0]["rows"]}


def keys(snap):
    return {c["key"]: c for c in snap["checks"]}


class TestParsers(unittest.TestCase):
    def test_cpu_times(self):
        per = "cpu0 1 0 1 8 0 0 0 0 0 0\ncpu1 1 0 1 8 0 0 0 0 0 0\n"
        busy, total, cpus = host.cpu_times(STAT0 + per)
        self.assertEqual(total, 100000 + 400 + 40000 + 4600000 + 2600 + 11000 + 5000)
        self.assertEqual(busy, total - 4600000 - 2600)          # idle + iowait
        self.assertEqual(cpus, 2)
        with self.assertRaises(ValueError):
            host.cpu_times("intr 1\n")

    def test_meminfo(self):
        m = host.meminfo("MemTotal: 10 kB\nMemAvailable: 4 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
        self.assertEqual(m, {"MemTotal": 10240, "MemAvailable": 4096, "SwapTotal": 0,
                             "SwapFree": 0})
        with self.assertRaises(ValueError):
            host.meminfo("MemTotal: 10 kB\n")

    def test_loadavg_pressure(self):
        self.assertEqual(host.loadavg("0.29 0.65 0.80 2/1200 9000\n"), (0.29, 0.65, 0.8))
        p = host.pressure("some avg10=0.12 avg60=0.05 avg300=0.01 total=9\n"
                          "full avg10=0.10 avg60=0.04 avg300=0.01 total=8\n")
        self.assertEqual(p, {"some": {"avg10": 0.12, "avg60": 0.05},
                             "full": {"avg10": 0.10, "avg60": 0.04}})
        with self.assertRaises(ValueError):
            host.pressure("")

    def test_disks(self):
        self.assertEqual(host.whole_disks(["zram0", "nvme0n1", "dm-0", "loop3", "sda", "ram0"]),
                         ["nvme0n1", "sda"])
        text = " 259 0 nvme0n1 1 2 10 4 5 6 20 8 0 0 0\n 259 1 nvme0n1p1 1 2 3 4 5 6 7 8 0 0 0\n"
        self.assertEqual(host.diskstats(text, {"nvme0n1"}), {"nvme0n1": (5120, 10240)})

    def test_limit(self):
        self.assertEqual(host.limit("84850\n"), 84.85)
        self.assertIsNone(host.limit("65261850\n"))             # nvme: not set
        self.assertIsNone(host.limit(None))

    def test_sensors_from_fixture(self):
        got = FakeHost(FIX).sensors(system.SENSORS)
        self.assertEqual([s.key for s in got], [
            "coretemp:coretemp.0:temp1", "nvme:nvme0:temp1", "spd5118:14-0050:temp1",
            "spd5118:14-0052:temp1"])                           # rules order, then device
        cpu, nvme, ram = got[0], got[1], got[2]
        self.assertEqual((cpu.label, cpu.temp, cpu.max, cpu.crit), ("Package id 0", 37, 100, 100))
        self.assertEqual((nvme.max, nvme.crit), (80.85, 84.85))
        self.assertEqual((ram.label, ram.max, ram.crit), ("", 55, 85))

    def test_sensor_rules(self):
        self.assertTrue(host.wanted(["spd5118"], "spd5118", ""))
        self.assertTrue(host.wanted(["nvme:Composite"], "nvme", "Composite"))
        self.assertFalse(host.wanted(["nvme:Composite"], "nvme", "Sensor 1"))
        self.assertFalse(host.wanted(["coretemp:Package id 0"], "coretemp", "Core 0"))


class TestModule(Base):
    def test_api_and_screen(self):
        check_module(system)
        self.assertIn("modules.system", registry.MODULES)
        s = SCREENS[find("processes")]
        self.assertEqual((s.modules, s.focus), (("system",), "system/system"))

    def test_first_collect(self):
        snap = self.collect()
        r = rows(snap)
        self.assertEqual(list(r), [
            "cpu", "load", "memory", "swap", "psi:cpu", "psi:memory", "psi:io", "io:nvme0n1",
            "space:/var", "space:/boot", "temp:coretemp:coretemp.0:temp1",
            "temp:nvme:nvme0:temp1", "temp:spd5118:14-0050:temp1",
            "temp:spd5118:14-0052:temp1"])
        self.assertEqual(r["cpu"]["cells"], ["cpu", "-", "-", "100%", "20 cpus, all = 100%"])
        self.assertEqual(r["load"]["cells"],
                         ["load", "0.29", "0.29", "20", "5m 0.65  15m 0.80  (limit = cpus)"])
        self.assertEqual(r["io:nvme0n1"]["cells"][1:], ["-", "-", "-", "first read"])
        self.assertEqual(r["memory"]["cells"],
                         ["memory", "5.7G 19%", "5.7G", "31G", "available 25G"])
        self.assertEqual(r["swap"]["cells"][1:4], ["98M", "98M", "8.0G"])
        self.assertEqual(r["psi:io"]["cells"][1:4], ["0.05%", "0.12%", "-"])
        self.assertEqual(r["space:/var"]["cells"][1:],
                         ["120G free", "-", "400G", "70% used  (audit: warn < 75M, crit < 50M)"])
        self.assertEqual(r["space:/boot"]["cells"][4], "41% used")
        self.assertEqual(r["temp:spd5118:14-0050:temp1"]["cells"],
                         ["temp ram 14-0050", "38 C", "38 C", "85 C",
                          "warn 70 C, yellow after 60 s"])
        self.assertEqual(r["temp:coretemp:coretemp.0:temp1"]["cells"][0], "temp cpu")
        self.assertEqual(snap["panels"][0]["roles"], ["name", "value", "peak", "note", "note"])
        self.assertNotIn("level", r["memory"])
        self.assertEqual(r["temp:coretemp:coretemp.0:temp1"]["cells"][4],
                         "warn 75 C, yellow after 60 s")
        self.assertEqual(r["temp:nvme:nvme0:temp1"]["cells"][3:],
                         ["84.85 C", "warn 80.85 C, yellow after 60 s"])
        self.assertEqual((snap["status"], snap["checks"]), ("ok", []))
        self.assertEqual(snap["summary"], "mem 5.7G / 31G | cpu 37 C")
        self.assertEqual(snap["panels"][0]["width"], "full")

    def test_cpu_and_io_delta(self):
        self.collect()
        # +1000 jiffies, 250 busy; nvme0n1 +10240 bytes read, +20480 written in 5 s
        self.write("/proc/stat", "cpu  100200 400 40050 4600750 2600 11000 5000 0 0 0\n")
        self.write("/proc/diskstats", " 259 0 nvme0n1 1 2 2000020 4 5 6 4000040 8 0 0 0\n")
        r = rows(self.collect(1005.0))
        self.assertEqual(r["cpu"]["cells"][1:3], ["25%", "25%"])
        self.assertEqual(r["io:nvme0n1"]["cells"][1:],
                         ["6.0K/s", "6.0K/s", "-", "read 2.0K/s  write 4.0K/s"])
        self.write("/proc/stat", "cpu  100300 400 40050 4601650 2600 11000 5000 0 0 0\n")
        r = rows(self.collect(1010.0))
        self.assertEqual(r["cpu"]["cells"][1:3], ["10%", "25%"])     # peak of 5 min

    def test_temp_crit(self):
        self.temp(2, 1, 100000)                                   # coretemp package
        snap = self.collect()
        r = rows(snap)["temp:coretemp:coretemp.0:temp1"]
        self.assertEqual(r["sev"], "crit")
        d = {it["k"]: it for it in r["detail"]}
        self.assertEqual(d["at crit"], {"k": "at crit", "v": "100.0 C >= 100 C", "sev": "crit"})
        self.assertNotIn("sev", d["sensor"])
        c = keys(snap)["temp_crit:coretemp:coretemp.0:temp1"]
        self.assertEqual((c["sev"], c["title"]), ("crit", "cpu 100 C: at crit 100 C"))
        self.assertEqual(snap["status"], "crit")

    def test_temp_warn_lasts(self):
        self.temp(7, 1, 71000)                                    # ram 14-0050, warn 70
        snap = self.collect(1000.0)
        rid = "temp:spd5118:14-0050:temp1"
        self.assertEqual(rows(snap)[rid]["sev"], "warn")          # row at once
        self.assertEqual(snap["checks"], [])
        self.assertEqual(self.collect(1055.0)["checks"], [])
        c = keys(self.collect(1060.0))["temp_hot:spd5118:14-0050:temp1"]
        self.assertEqual((c["sev"], c["title"]), ("warn", "ram 14-0050 71 C for 60 s"))
        self.temp(7, 1, 60000)
        snap = self.collect(1065.0)
        self.assertEqual((rows(snap)[rid]["sev"], snap["checks"]), ("ok", []))
        self.temp(7, 1, 71000)                                    # starts over
        self.assertEqual(self.collect(1070.0)["checks"], [])

    def test_level_high(self):
        self.temp(9, 1, 64000)                                    # ram 14-0052: 64 / 85
        r = rows(self.collect())["temp:spd5118:14-0052:temp1"]
        self.assertEqual((r["sev"], r.get("level")), ("ok", "high"))      # orange, not warn
        self.temp(9, 1, 71000)
        r = rows(self.collect(1005.0))["temp:spd5118:14-0052:temp1"]
        self.assertEqual((r["sev"], r.get("level")), ("warn", None))     # warn wins
        self.write("/proc/meminfo", "MemTotal: 1000 kB\nMemAvailable: 200 kB\n"
                   "SwapTotal: 0 kB\nSwapFree: 0 kB\n")
        self.assertEqual(rows(self.collect(1010.0))["memory"].get("level"), "high")

    def test_nvme_warn_from_sensor_max(self):
        self.temp(5, 1, 81000)
        r = rows(self.collect())["temp:nvme:nvme0:temp1"]
        self.assertEqual(r["sev"], "warn")
        d = {it["k"]: it["v"] for it in r["detail"]}
        self.assertEqual(d["warn"], "80.85 C (sensor max) for 60 s")

    def test_coretemp_max_equal_crit_is_no_warn(self):
        st = system.State(host=self.h, mono=lambda: self.now, temp_warn={})
        self.st = st
        self.temp(2, 1, 99000)
        r = rows(self.collect())["temp:coretemp:coretemp.0:temp1"]
        self.assertEqual((r["sev"], r["cells"][3:]), ("ok", ["100 C", "no warn limit"]))

    def test_var_space(self):
        self.h.free["/var"] = 60 * MIB
        snap = self.collect()
        c = keys(snap)["space_audit:/var"]
        self.assertEqual((c["sev"], c["title"]), ("warn", "/var free 60M: audit space low"))
        self.h.free["/var"] = 40 * MIB
        self.assertEqual(keys(self.collect(1030.0))["space_audit:/var"]["sev"], "warn")  # 60 s
        c = keys(self.collect(1060.0))["space_audit:/var"]
        self.assertEqual((c["sev"], c["title"]), ("crit", "/var free 40M: audit suspended"))
        self.h.free["/boot"] = 1 * MIB                            # /boot: row only
        self.assertNotIn("space_audit:/boot", keys(self.collect(1120.0)))

    def test_unreadable(self):
        os.remove(os.path.join(self.root, "proc/pressure/io"))
        del self.h.free["/boot"]
        snap = self.collect()
        r = rows(snap)
        self.assertEqual(r["psi:io"]["sev"], "warn")
        self.assertIn("FileNotFoundError", r["psi:io"]["cells"][4])
        self.assertEqual(r["space:/boot"]["cells"][4],
                         "statvfs /boot: PermissionError: Permission denied")
        self.assertEqual(set(keys(snap)), {"read:/proc/pressure/io", "read:statvfs/boot"})
        self.assertIn("load", r)                                   # the rest still there

    def test_peak_window(self):
        self.temp(2, 1, 60000)
        self.collect(1000.0)
        self.temp(2, 1, 40000)
        for i in range(1, system.HIST):
            self.collect(1000.0 + 5 * i)
        rid = "temp:coretemp:coretemp.0:temp1"
        self.assertEqual(rows(self.collect(2000.0))[rid]["cells"][1:3], ["40 C", "40 C"])



def stat(pid, comm, ppid, ticks, rss, state="S", threads=1, start=100):
    """A /proc/<pid>/stat line (fields after comm: state ppid ... utime stime ...)."""
    f = [state, str(ppid)] + ["0"] * 9 + [str(ticks), "0"] + ["0"] * 4 + [str(threads), "0",
                                                                         str(start), "0", str(rss)]
    return f"{pid} ({comm}) " + " ".join(f) + " 0 0\n"


class TestPrograms(Base):
    """Programs box: one row per program (fake processes, names generic)."""

    PROCS = {   # pid: (comm, ppid, ticks, rss pages, cgroup)
        1: ("systemd", 0, 50, 3000, "/init.scope"),
        2: ("kthreadd", 0, 0, 0, "/"),
        30: ("kworker/0:1", 2, 900, 0, "/"),
        800: ("firefox", 1, 1000, 100000, "/user.slice/user-1000.slice/user@1000.service/"
                                         "app.slice/app-org.mozilla.firefox-1234.scope"),
        801: ("Web Content", 800, 200, 50000, "/user.slice/user-1000.slice/user@1000.service/"
                                              "app.slice/app-org.mozilla.firefox-1234.scope"),
        900: ("bash", 1, 10, 1000, "/user.slice/user-1000.slice/session-2.scope"),
        950: ("auditd", 1, 30, 2000, "/system.slice/auditd.service"),
    }

    def setUp(self):
        super().setUp()
        self.h.page = 4096
        for pid, (comm, ppid, ticks, rss, cg) in self.PROCS.items():
            self.proc(pid, comm, ppid, ticks, rss, cg)

    def proc(self, pid, comm, ppid, ticks, rss, cg=None, start=100):
        d = os.path.join(self.root, "proc", str(pid))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "stat"), "w") as f:
            f.write(stat(pid, comm, ppid, ticks, rss, start=start))
        if cg is not None:
            with open(os.path.join(d, "cgroup"), "w") as f:
                f.write(f"0::{cg}\n")

    def programs(self, snap):
        return {r["id"]: r for r in snap["panels"][1]["rows"]}

    def test_rows(self):
        snap = self.collect()
        p = self.programs(snap)
        self.assertEqual(list(p), ["prog:org.mozilla.firefox", "prog:init", "prog:auditd",
                                   "prog:bash (session)"])        # by memory, no kernel
        ff = p["prog:org.mozilla.firefox"]
        self.assertEqual(ff["cells"], ["org.mozilla.firefox", "2", "-", "0.0%", "586M",
                                       "586M", ff["cells"][6]])
        self.assertEqual((ff["progs"], ff["filter"]), (["org.mozilla.firefox"],
                                                        "org.mozilla.firefox"))
        d = [it["v"] for it in ff["detail"]]
        self.assertEqual(d[0], "2, top 2 by memory")
        self.assertTrue(d[1].startswith("firefox  391M  - cpu  S  1 threads"))
        self.assertNotIn("progs", p["prog:bash (session)"])        # a session: no card
        self.assertEqual(snap["panels"][1]["roles"],
                         ["name", "note", "value", "peak", "value", "peak", "note"])

    def test_cpu_and_peak(self):
        self.collect()
        # machine +1000 ticks; firefox +100 +50, auditd +10
        self.write("/proc/stat", "cpu  100200 400 40050 4600750 2600 11000 5000 0 0 0\n")
        self.proc(800, "firefox", 1, 1100, 100000)
        self.proc(801, "Web Content", 800, 250, 50000)
        self.proc(950, "auditd", 1, 40, 2000)
        p = self.programs(self.collect(1005.0))
        self.assertEqual(p["prog:org.mozilla.firefox"]["cells"][2:4], ["15%", "15%"])
        self.assertEqual(p["prog:auditd"]["cells"][2], "1.0%")
        self.proc(800, "firefox", 1, 1100, 10000)                 # idle now, less memory
        self.write("/proc/stat", "cpu  100300 400 40050 4601650 2600 11000 5000 0 0 0\n")
        p = self.programs(self.collect(1010.0))
        ff = p["prog:org.mozilla.firefox"]["cells"]
        self.assertEqual((ff[2], ff[3], ff[4], ff[5]), ("0.0%", "15%", "234M", "586M"))

    def test_pid_reuse(self):
        self.collect()
        self.write("/proc/stat", "cpu  100200 400 40050 4600750 2600 11000 5000 0 0 0\n")
        self.proc(950, "other", 1, 5000, 2000, "/system.slice/other.service", start=900)
        p = self.programs(self.collect(1005.0))
        self.assertIn("prog:other", p)                            # new cgroup read
        self.assertEqual(p["prog:other"]["cells"][2], "0.0%")     # no delta from auditd

    def test_cpu_and_memory_rows_name_the_top(self):
        snap = self.collect()
        r = rows(snap)
        mem = {it["k"]: it["v"] for it in r["memory"]["detail"]}
        self.assertEqual(mem["top 1"], "org.mozilla.firefox  586M  (2 procs)")
        self.assertEqual(r["memory"]["progs"], ["org.mozilla.firefox", "init", "auditd"])
        cpu = {it["k"]: it["v"] for it in r["cpu"]["detail"]}
        self.assertEqual(cpu["top programs"], "after the next scan")
        self.write("/proc/stat", "cpu  100200 400 40050 4600750 2600 11000 5000 0 0 0\n")
        self.proc(950, "auditd", 1, 130, 2000)
        r = rows(self.collect(1005.0))
        cpu = {it["k"]: it["v"] for it in r["cpu"]["detail"]}
        self.assertEqual(cpu["top 1"], "auditd  10%  (1 procs)")
        self.assertEqual(r["cpu"]["progs"][0], "auditd")

    def stuck(self, pid, comm, ppid, state, cg=None, rss=0):
        d = os.path.join(self.root, "proc", str(pid))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "stat"), "w") as f:
            f.write(stat(pid, comm, ppid, 0, rss, state=state))
        if cg is not None:
            with open(os.path.join(d, "cgroup"), "w") as f:
                f.write(f"0::{cg}\n")

    def test_zombie(self):
        self.stuck(990, "defunct-child", 800, "Z")
        snap = self.collect(1000.0)
        p = self.programs(snap)
        z = p["stuck:990:100"]
        self.assertEqual(list(p)[0], "stuck:990:100")               # on top
        self.assertEqual(z["cells"][:2], ["defunct-child (zombie, parent firefox)", "1"])
        self.assertEqual((z["sev"], z["progs"]), ("info", ["org.mozilla.firefox"]))
        d = {it["k"]: it for it in z["detail"]}
        self.assertEqual(d["parent"]["v"], "pid 800 firefox (org.mozilla.firefox)")
        self.assertEqual(p["prog:org.mozilla.firefox"]["cells"][1], "2")   # not counted
        self.assertNotIn("stuck:990:100", keys(snap))
        self.assertIn("zombies 1, D 0", snap["panels"][1]["title"])
        snap = self.collect(1060.0)
        z = self.programs(snap)["stuck:990:100"]
        self.assertEqual(z["sev"], "warn")
        self.assertEqual({it["k"]: it for it in z["detail"]}["state"]["sev"], "warn")
        c = keys(snap)["stuck:990:100"]
        self.assertEqual(c["title"], "zombie defunct-child pid 990 for 60 s, parent firefox "
                                     "pid 800")
        shutil.rmtree(os.path.join(self.root, "proc", "990"))       # reaped
        snap = self.collect(1065.0)
        self.assertNotIn("stuck:990:100", self.programs(snap))
        self.assertNotIn("stuck:990:100", keys(snap))

    def test_d_state_restarts_when_it_wakes(self):
        cg = "/system.slice/backup.service"
        self.stuck(960, "rsync", 1, "D", cg, rss=500)
        self.collect(1000.0)
        self.stuck(960, "rsync", 1, "S", cg, rss=500)                 # woke up
        self.collect(1030.0)
        self.stuck(960, "rsync", 1, "D", cg, rss=500)
        snap = self.collect(1060.0)
        r = self.programs(snap)["stuck:960:100"]
        self.assertEqual((r["cells"][0], r["sev"], r["progs"]), ("rsync (D)", "info",
                                                                  ["backup"]))
        self.assertEqual(self.programs(snap)["prog:backup"]["cells"][1], "1")   # still summed
        self.assertEqual(keys(self.collect(1120.0))["stuck:960:100"]["sev"], "warn")

    def test_strays_in_gnome_shell_cgroup(self):
        """2026-11-03 host: 10 Brave processes in GNOME Shell's cgroup (launcher forked
        before GNOME moved it): named, yellow, one check after STRAY s."""
        shell = ("/user.slice/user-1000.slice/user@1000.service/session.slice/"
                 "org.gnome.Shell@user.service")
        self.proc(1500, "gnome-shell", 1, 10, 30000, shell)
        self.proc(1501, "Xwayland", 1500, 1, 1000, shell)
        self.proc(1502, "glycin-image-rs", 1500, 1, 100, shell)
        for pid in (1600, 1601):
            self.proc(pid, "brave", 1500, 1, 20000, shell)
        self.proc(1602, "cat", 1600, 1, 10, shell)
        snap = self.collect(1000.0)
        r = self.programs(snap)["prog:org.gnome.Shell"]
        self.assertEqual(r["sev"], "info")                          # new: no check yet
        self.assertFalse([k for k in keys(snap) if k.startswith("shared_cgroup:")])
        d = r["detail"]
        self.assertEqual((d[0]["k"], d[0]["v"]),
                         ("not GNOME's own", "brave x2, cat in org.gnome.Shell@user.service"))
        self.assertEqual(r["cells"][1], "6")                        # all still in its sums
        snap = self.collect(1000.0 + procs.STRAY)
        r = self.programs(snap)["prog:org.gnome.Shell"]
        self.assertEqual((r["sev"], r["detail"][0]["sev"]), ("warn", "warn"))
        c = keys(snap)["shared_cgroup:org.gnome.Shell@user.service"]
        self.assertEqual((c["sev"], c["n"]), ("warn", 3))
        self.assertEqual(c["title"], "3 processes in org.gnome.Shell@user.service: brave x2, "
                                     "cat")
        for pid in (1600, 1601, 1602):                              # started via app-unit
            shutil.rmtree(os.path.join(self.root, "proc", str(pid)))
        snap = self.collect(1020.0)
        self.assertEqual(self.programs(snap)["prog:org.gnome.Shell"]["sev"], "ok")
        self.assertFalse([k for k in keys(snap) if k.startswith("shared_cgroup:")])

    def test_many_stuck_one_more_check(self):
        for pid in range(3000, 3015):
            self.stuck(pid, "z", 1, "Z")
        self.collect(1000.0)
        k = keys(self.collect(1060.0))
        self.assertEqual(len([x for x in k if x.startswith("stuck:3")]), 10)
        self.assertEqual(k["stuck:more"]["title"], "5 more zombie / D processes")

    def test_parse_stat(self):
        p = host.proc_stat(stat(5, "a (b) c", 1, 7, 9, state="D", threads=3, start=44), 5)
        self.assertEqual((p.comm, p.state, p.ppid, p.ticks, p.rss, p.threads, p.start),
                         ("a (b) c", "D", 1, 7, 9, 3, 44))


class TestOptions(unittest.TestCase):
    def test_defaults(self):
        st = system.init({})
        self.assertEqual(st.sensors, system.SENSORS)
        self.assertEqual(st.temp_warn, {"coretemp": 75, "spd5118": 70})
        self.assertEqual((st.space_left, st.admin_space_left), (75, 50))

    def test_options(self):
        st = system.init({"sensors": ["k10temp"], "temp_warn": {"k10temp": 85},
                          "temp_warn_for": 30, "audit_space_left": 100,
                          "audit_admin_space_left": 80})
        self.assertEqual((st.sensors, st.temp_warn, st.warn_for), (("k10temp",),
                                                                  {"k10temp": 85.0}, 30.0))

    def test_bad(self):
        for cfg in ({"x": 1}, {"sensors": []}, {"sensors": [":x"]}, {"temp_warn": {"a": 500}},
                    {"temp_warn": {"a": True}}, {"temp_warn_for": -1},
                    {"audit_admin_space_left": 90}):
            with self.assertRaises(ValueError, msg=cfg):
                system.init(cfg)


if __name__ == "__main__":
    unittest.main()
