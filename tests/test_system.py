import os
import shutil
import tempfile
import unittest

import modules.system as system
from core import registry
from core.module import Context, check_module, validate
from core.screens import SCREENS, find
from modules.system import host

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
