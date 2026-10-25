import json
import os
import unittest

import modules.security as sec
from core import journal as corejournal
from core.module import Context, check_module, validate
from core.screens import SCREENS, find

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "security")
USERS = {"0": "root", "1000": "null"}


def fix(name):
    with open(os.path.join(FIX, name + ".json"), encoding="ascii") as f:
        return [json.loads(line) for line in f if line.strip()]


def end(entries):
    return max(int(e["__REALTIME_TIMESTAMP"]) for e in entries) / 1e6


class Run:
    """The module with a fake clock, fed like core's follower does."""

    def __init__(self):
        self.now = 0.0
        self.st = sec.State(wall=lambda: self.now, user=lambda uid: USERS.get(uid, uid),
                            stamp=lambda ts: f"T{int(ts)}")

    def collect(self, entries, now):
        self.now = now
        return validate(sec.collect(self.st, Context(tuple(entries), True, "")))


def rows(snap):
    p = snap["panels"][0]
    out = {}
    for r in p["rows"]:
        d = {it["k"]: it["v"] for it in r["detail"]}
        out[r["cells"][4]] = (r["cells"][1], r["cells"][2], r["cells"][3], d)
    return out


def capture(name, later=10.0):
    entries = fix(name)
    r = Run()
    return r, r.collect(entries, end(entries) + later)


class TestModule(unittest.TestCase):
    def test_api(self):
        check_module(sec)
        sp = corejournal.spec(sec.JOURNAL)
        self.assertEqual(sp.groups, ((("_TRANSPORT", "audit"),),))
        self.assertEqual(sp.fields, ("MESSAGE", "_AUDIT_ID", "_AUDIT_TYPE", "_AUDIT_TYPE_NAME"))
        self.assertIsInstance(sec.init({}), sec.State)
        with self.assertRaises(ValueError):
            sec.init({"x": 1})

    def test_on_screen_2(self):
        s = SCREENS[find("security")]
        self.assertEqual((s.modules, s.focus, s.feed), (("security",), "security/commands", False))

    def test_normalize(self):
        self.assertEqual(sec.normalize(["/proc/44494/exe"]), "/proc/#/exe")
        self.assertEqual(sec.normalize(["--id", "0xdeadbeef", "a1b2c3d4e5f6a7b8"]),
                         "--id <hex> <hex>")
        self.assertEqual(sec.normalize(["123e4567-e89b-12d3-a456-426614174000", "8.8.8.8"]),
                         "<uuid> <ip>")
        self.assertEqual(sec.normalize(["--token", "abc"]), sec.normalize(["--token", "xyz"]))


class TestCommands(unittest.TestCase):
    def test_sudo_and_root_shell(self):
        r, snap = capture("sudo")
        got = rows(snap)
        self.assertEqual(got["su"][:3], ("1", "null>root", "sudo pts/0"))       # via sudo + tty
        self.assertEqual(got["su"][3]["password checks"], "1")                  # unix_chkpwd folded
        self.assertEqual(got["bash"][2], "su")                                  # parent seen before
        self.assertEqual(got["tty"][2], "bash")
        self.assertEqual(got["sudo -k"][2], "no root command")                  # launch only
        self.assertEqual(got["id"][:2], ("2", "null>root"))                     # sudo id + id in root shell
        self.assertTrue(got["readlink /proc/44494/exe"][2].startswith("ppid "))  # parent not seen
        self.assertNotIn("/usr/bin/unix_chkpwd null nonull", got)              # never a row
        self.assertEqual(r.st.skipped, 4)                                       # PATH search misses
        self.assertEqual(r.st.runs, 28)
        p = snap["panels"][0]
        self.assertEqual((p["title"], p["width"], p["types"]),
                         ("commands 23  (28 root runs since start)", "full", sec.TYPES))
        self.assertEqual(snap["summary"], "root runs 28 | groups 23")
        d = got["su"][3]
        self.assertEqual((d["exe"], d["argv"], d["cwd"], d["ses"], d["key"]),
                         ("/usr/bin/su", "su", "/var/home/null/my-project/sectop", "18",
                          "root_cmds"))
        self.assertNotIn("result", d)
        self.assertEqual(d["parents"], "sudo pts/0")                           # parent not seen
        self.assertEqual(got["id"][3]["parents"], "bash 44494 < su 44491 < sudo pts/0")
        self.assertEqual(got["sudo -k"][3]["parents"], "ppid 30226")
        tones = {r["cells"][4]: r.get("tone") for r in p["rows"]}
        self.assertEqual((tones["sudo -k"], tones["su"]), ("dim", None))     # launch: dim

    def test_denied_and_launch_only(self):
        _, snap = capture("sudo-denied")
        got = rows(snap)
        self.assertEqual(got["sudo id"][2], "denied")                       # USER_CMD res=failed
        self.assertEqual(got["sudo id"][3]["password checks"], "3")         # 3 wrong passwords
        self.assertEqual(got["sudo id"][3]["denied"], "1 of 1")             # 2nd sudo id: taken back
        self.assertEqual(got["id"][2:3], ("sudo pts/1",))                   # then the right one
        self.assertEqual(got["id"][3]["password checks"], "2")
        _, snap = capture("sudo-l")
        self.assertEqual(rows(snap)["sudo -l"][:3], ("2", "null>root", "no root command"))

    def test_pkexec_same_process(self):
        r, snap = capture("pkexec")
        got = rows(snap)
        self.assertEqual(got["/usr/bin/id"][2], "pkexec")
        helper = got["/usr/lib/polkit-1/polkit-agent-helper-1 null"]   # setuid, runs as root
        self.assertEqual((helper[2], helper[3]["password checks"]), ("setuid", "2"))
        self.assertNotIn("result", helper[3])
        tones = {row["cells"][4]: row.get("tone") for row in snap["panels"][0]["rows"]}
        self.assertIsNone(tones["/usr/lib/polkit-1/polkit-agent-helper-1 null"])
        self.assertEqual(r.st.runs, 2)

    def test_unlock_password_checks(self):
        """gdm-session-worker runs unix_chkpwd as root: folded, never a row (fixture lock)."""
        r, snap = capture("lock")
        got = rows(snap)
        self.assertEqual(list(got), ["gdm-session-worker [pam/gdm-password]"])
        self.assertEqual(got["gdm-session-worker [pam/gdm-password]"][3]["password checks"], "2")
        self.assertEqual((r.st.runs, r.st.lost_checks), (1, 0))

    def test_password_check_under_a_root_command(self):
        """sudo run by root (install.sh, host 2026-10-25): its unix_chkpwd goes to its row."""
        r = Run()
        got = rows(r.collect(_events(
            (600, 599, "0", "/usr/bin/bash", ["/bin/bash", "./install.sh"], "root_cmds"),
            (601, 600, "0", "/usr/bin/sudo", ["sudo", "-u", "null", "git", "log", "-1"],
             "root_cmds"),
            (602, 601, "0", "/usr/bin/unix_chkpwd", ["/usr/bin/unix_chkpwd", "root",
                                                     "chkexpiry"], "root_cmds"),
            (603, 1, "0", "/usr/bin/unix_chkpwd", ["/usr/bin/unix_chkpwd", "root",
                                                   "chkexpiry"], "root_cmds"),
            (604, 1, "1000", "/usr/bin/unix_chkpwd", ["/usr/bin/unix_chkpwd", "null",
                                                      "nonull"], "user_emulation")), 200.0))
        self.assertEqual(sorted(got), ["/bin/bash ./install.sh", "sudo -u null git log -1"])
        self.assertEqual(got["sudo -u null git log -1"][2:3], ("bash",))
        self.assertEqual(got["sudo -u null git log -1"][3]["password checks"], "1")
        self.assertEqual(got["sudo -u null git log -1"][3]["parents"], "bash 600 < ppid 599")
        self.assertEqual((r.st.runs, r.st.lost_checks), (2, 2))     # parent not seen: counted

    def test_setuid_program_runs_as_root(self):
        """nvidia-modprobe (setuid) runs modprobe nvidia (host 2026-10-25): root runs, not
        launches without a root command."""
        r = Run()
        evs = []
        for i in (0, 10):
            evs += [(700 + i, 650, "1000", "/usr/bin/nvidia-modprobe",
                     ["/usr/bin/nvidia-modprobe"], "user_emulation"),
                    (701 + i, 700 + i, "1000", "/usr/bin/kmod", ["modprobe", "nvidia"],
                     "user_emulation")]
        snap = r.collect(_events(*evs), 200.0)
        got = rows(snap)
        self.assertEqual(got["/usr/bin/nvidia-modprobe"][:3], ("2", "null>root", "setuid"))
        self.assertEqual(got["modprobe nvidia"][:3], ("2", "null>root", "nvidia-modprobe"))
        self.assertEqual(r.st.runs, 4)
        self.assertEqual([row.get("tone") for row in snap["panels"][0]["rows"]], [None, None])
        self.assertNotIn("result", got["modprobe nvidia"][3])
        self.assertEqual(got["modprobe nvidia"][3]["parents"], "nvidia-modprobe 710 < setuid")

    def test_su_launch_taken_back_by_its_child(self):
        """su forks the root shell: the child (ppid = su) takes the launch back."""
        r = Run()
        got = rows(r.collect(_events(
            (800, 799, "1000", "/usr/bin/su", ["su", "-"], "user_emulation"),
            (801, 800, "0", "/usr/bin/bash", ["-bash"], "root_cmds")), 200.0))
        self.assertEqual(list(got), ["-bash"])
        self.assertEqual(got["-bash"][2], "su")
        self.assertEqual(got["-bash"][3]["parents"], "su 800 < ppid 799")
        self.assertEqual(r.st.runs, 1)

    def test_parent_chain_limit(self):
        """At most MAX_HOPS parents, then `...`; a loop of pids ends."""
        r = Run()
        n = sec.MAX_HOPS + 3
        got = rows(r.collect(_events(*[(1000 + i, 999 + i, "0", f"/usr/bin/p{chr(97 + i)}",
                                        [f"p{chr(97 + i)}"], "root_cmds") for i in range(n)]),
                             200.0))
        last = got[f"p{chr(97 + n - 1)}"][3]["parents"].split(" < ")
        self.assertEqual(len(last), sec.MAX_HOPS + 1)
        self.assertEqual((last[0], last[-1]), (f"p{chr(97 + n - 2)} {1000 + n - 2}", "..."))
        r = Run()
        got = rows(r.collect(_events((2000, 2001, "0", "/usr/bin/a", ["a"], "root_cmds"),
                                     (2001, 2000, "0", "/usr/bin/b", ["b"], "root_cmds"),
                                     (2000, 2001, "0", "/usr/bin/a", ["a"], "root_cmds")),
                             200.0))
        self.assertEqual(got["a"][3]["parents"], "b 2001 < a 2000 < ppid 2001")   # ends

    def test_via_seen(self):
        """Same program, other ways in: one row, the ways in the detail."""
        entries = sorted(fix("sudo") + fix("pkexec"), key=lambda e: int(e["__REALTIME_TIMESTAMP"]))
        r = Run()
        got = rows(r.collect(entries, end(entries) + 10))
        self.assertEqual(got["/usr/bin/id"][:3], ("3", "null>root", "pkexec"))
        self.assertEqual(got["/usr/bin/id"][3]["via seen"], "pkexec, bash, sudo pts/0")
        self.assertNotIn("via seen", got["su"][3])

    def test_blocked_module_load(self):
        _, snap = capture("module")
        got = rows(snap)
        self.assertEqual([got[c][2] for c in ("modprobe tcp_bbr", "modprobe -r tcp_bbr",
                                              "modprobe sctp")], ["sudo pts/1"] * 3)
        self.assertEqual(got["sh -c -- /bin/false"][2], "kmod")             # install sctp /bin/false
        self.assertEqual(got["/bin/false"][2], "kmod")

    def test_launch_row_taken_back(self):
        """A launch is a row at once; its root command takes it back, however long the
        password took (2026-10-25: a 5 s wait turned slow prompts into launch rows)."""
        entries = fix("sudo")
        cut = next(i for i, e in enumerate(entries) if e.get("_AUDIT_TYPE") == "1123")
        r = Run()
        got = rows(r.collect(entries[:cut], end(entries[:cut]) + 60))   # password: 60 s
        self.assertEqual(got["sudo id"][2], "no root command")          # so far, yes
        self.assertEqual(got["sudo id"][3]["password checks"], "2")
        got = rows(r.collect(entries[cut:], end(entries) + 10))
        self.assertNotIn("sudo id", got)                                # taken back
        self.assertEqual(got["id"][3]["password checks"], "2")          # moved to the command

    def test_secrets(self):
        """cmd cell and grouping: secrets masked; detail argv raw (the UI masks it)."""
        r = Run()
        for i, tok in enumerate(("abc", "xyz")):
            ev = _Ev(argv=["curl", "--token", tok, "https://bob:pw@example.org"])
            sec._root(r.st, ev, 100.0 + i)
        snap = validate(sec.collect(r.st, Context((), True, "")))
        [row] = snap["panels"][0]["rows"]
        self.assertEqual((row["cells"][1], row["cells"][4]),
                         ("2", "curl --token *** https://bob:***@example.org"))
        argvs = [it["v"] for it in row["detail"] if it["k"] == "argv"]
        self.assertEqual(argvs, ["curl --token xyz https://bob:pw@example.org",
                                 "curl --token abc https://bob:pw@example.org"])

    def test_join_window(self):
        entries = fix("sudo-denied")
        late = []
        for e in entries:                                                  # id 6 s after its USER_CMD
            if e.get("_AUDIT_ID") in ("18015",):
                e = {**e, "__REALTIME_TIMESTAMP": str(int(e["__REALTIME_TIMESTAMP"]) + 6_000_000)}
            late.append(e)
        r = Run()
        snap = r.collect(late, end(late) + 10)
        self.assertTrue(rows(snap)["id"][2].startswith("ppid "))           # not joined

    def test_batches_same_as_once(self):
        entries = fix("sudo")
        a = Run()
        once = a.collect(entries, end(entries) + 10)
        b = Run()
        for i in range(0, len(entries), 37):
            b.collect(entries[i:i + 37], end(entries[:i + 37]))
        split = b.collect([], end(entries) + 10)
        strip = lambda s: {k: v[:3] for k, v in rows(s).items()}
        self.assertEqual(strip(once), strip(split))

    def test_limits(self):
        r = Run()
        for i in range(sec.MAX_GROUPS + 5):
            word = "".join(chr(97 + int(d)) for d in str(i))                # no digits
            g = sec._group(r.st, _Ev(argv=["cmd", word]), ["cmd", word], float(i))
        self.assertEqual(len(r.st.groups), sec.MAX_GROUPS)
        for i in range(8):
            g = sec._group(r.st, _Ev(argv=["same", str(i)]), ["same", str(i)], 1000.0 + i)
        self.assertEqual(list(g.argvs), [f"same {i}" for i in range(7, 2, -1)])   # 5 newest
        self.assertEqual(g.n, 8)                                              # numbers: one group

    def test_journal_note_in_title(self):
        r = Run()
        snap = validate(sec.collect(r.st, Context((), True, "3 bad line(s)")))
        self.assertIn("(journal: 3 bad line(s))", snap["panels"][0]["title"])
        snap = validate(sec.collect(r.st, Context((), False, "")))
        self.assertIn("(journal: follower down)", snap["panels"][0]["title"])


def _events(*execs) -> list:
    """Audit journal entries (SYSCALL, EXECVE, CWD, PROCTITLE) of execve events, one second
    apart: (pid, ppid, uid, exe, argv, key). euid 0, auid 1000, ses 18."""
    out = []
    for i, (pid, ppid, uid, exe, argv, key) in enumerate(execs):
        us = str(100_000_000 + i * 1_000_000)
        aid = str(90000 + i)
        msgs = [("1300", "SYSCALL", f"SYSCALL arch=c000003e syscall=59 success=yes exit=0 "
                 f"a0=1 a1=2 a2=3 a3=4 items=2 ppid={ppid} pid={pid} auid=1000 uid={uid} "
                 f"gid={uid} euid=0 suid=0 fsuid=0 egid={uid} sgid={uid} fsgid={uid} "
                 f'tty=pts0 ses=18 comm="x" exe="{exe}" subj=unconfined_u:unconfined_r:'
                 f'unconfined_t:s0-s0:c0.c1023 key="{key}"'),
                ("1309", "EXECVE", f"EXECVE argc={len(argv)} "
                 + " ".join(f'a{n}="{a}"' for n, a in enumerate(argv))),
                ("1307", "CWD", 'CWD cwd="/var/home/null"'),
                ("1327", "PROCTITLE", "PROCTITLE proctitle="
                 + "00".join(a.encode().hex().upper() for a in argv))]
        for typ, name, msg in msgs:
            out.append({"__REALTIME_TIMESTAMP": us, "_TRANSPORT": "audit", "_AUDIT_ID": aid,
                        "_AUDIT_TYPE": typ, "_AUDIT_TYPE_NAME": name, "MESSAGE": msg})
    return out


class _Ev:
    """Minimal audit event for _group()."""

    def __init__(self, argv):
        self.argv, self.cwd, self.keys = argv, "/", ("root_cmds",)
        self.kind, self.ts = "SYSCALL", None

    def get(self, name):
        return {"auid": "1000", "euid": "0", "exe": "/usr/bin/" + self.argv[0],
                "ses": "1", "pid": "2", "ppid": "1"}.get(name)


if __name__ == "__main__":
    unittest.main()
