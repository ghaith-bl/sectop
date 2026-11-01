import collections
import json
import os
import tempfile
import unittest

import modules.security as sec
from core import journal as corejournal
from core.config import ConfigError
from core.module import Context, check_module, validate
from core.screens import SCREENS, find
from modules.security import auth, kernel, logs, watch

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "security")
USERS = {"0": "root", "1000": "null", "1001": "sectop-locktest"}   # 1001: test user


def fix(name):
    with open(os.path.join(FIX, name + ".json"), encoding="ascii") as f:
        return [json.loads(line) for line in f if line.strip()]


def end(entries):
    return max(int(e["__REALTIME_TIMESTAMP"]) for e in entries) / 1e6


class Run:
    """The module with a fake clock, fed like core's follower does."""

    def __init__(self, taint=lambda: 0, prog=lambda pid, ts: None):
        self.now = 0.0
        self.st = sec.State(wall=lambda: self.now, user=lambda uid: USERS.get(uid, uid),
                            stamp=lambda ts: f"T{int(ts)}", taint=taint, prog=prog)

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
        self.assertEqual(sp.groups, (
            (("_TRANSPORT", "audit"),),
            (("SYSLOG_IDENTIFIER", "sudo"), ("PRIORITY", "1")),
            tuple(("PRIORITY", str(p)) for p in range(5)),
            (("_TRANSPORT", "kernel"), ("_KERNEL_SUBSYSTEM", "usb"))))
        self.assertEqual(sp.fields, ("MESSAGE", "_AUDIT_ID", "_AUDIT_TYPE", "_AUDIT_TYPE_NAME",
                                     "_AUDIT_LOGINUID", "_PID", "PRIORITY",
                                     "_KERNEL_SUBSYSTEM", "_KERNEL_DEVICE", "SYSLOG_IDENTIFIER",
                                     "_COMM", "_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT",
                                     "_SYSTEMD_CGROUP"))
        with WatchFile(None):                                   # not the host's file
            self.assertIsInstance(sec.init({}), sec.State)
            with self.assertRaises(ValueError):
                sec.init({"x": 1})

    def test_init_reads_watch_file(self):
        with WatchFile(None):
            st = sec.init({})
            self.assertEqual((st.rules, st.watch_file), ((), False))
            self.assertTrue(validate(sec.collect(st, Context((), True, "")))["summary"]
                            .endswith("| no watch list"))
        with WatchFile(RULES):
            st = sec.init({})
            self.assertEqual(len(st.rules), 4)
            self.assertTrue(validate(sec.collect(st, Context((), True, "")))["summary"]
                            .endswith("| watch 4 rules"))
        with WatchFile(b'[[rule]]\nid = "x"\nsev = "high"\ncmd = "a"\nwhy = "b"\n'):
            with self.assertRaises(ConfigError):                 # module off, header says why
                sec.init({})

    def test_on_screen_2(self):
        s = SCREENS[find("security")]
        self.assertEqual((s.modules, s.focus, s.feed),
                         (("security", "posture"), "security/commands", False))

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
        self.assertEqual(snap["summary"],
                         "root runs 28 | groups 23 | auth fails 0 | kernel 0 | logs 8 | "
                         "no watch list")
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


def auth_rows(snap):
    """login>user, service, result -> (n, sev, tty, detail)."""
    p = snap["panels"][1]
    out = {}
    for r in p["rows"]:
        c = r["cells"]
        out[(c[2], c[3], c[4])] = (c[1], r["sev"], c[5], {d["k"]: d["v"] for d in r["detail"]})
    return out


def follower(entries):
    """What core's follower gives the module: entries that match its JOURNAL groups."""
    want = corejournal.wants(corejournal.spec(sec.JOURNAL).groups)
    return [e for e in entries if corejournal.matches(e, want)]


class TestAuth(unittest.TestCase):
    """Fixtures 2026-10-20 and 2026-10-25 from my host."""

    def test_fixtures(self):
        want = {
            "sudo-denied": {("null>null", "sudo", "failed"): ("3", "warn", "pts/1"),
                            ("null>null", "sudo", "ok"): ("1", "info", "pts/1")},
            "polkit": {("null>null", "polkit", "failed"): ("1", "warn", "-"),
                       ("null>null", "polkit", "ok"): ("1", "info", "-")},
            "lock": {("null>null", "gdm", "ok"): ("1", "info", "tty1")},
            "unlock-fail": {("null>null", "gdm", "failed"): ("1", "warn", "tty1"),
                            ("null>null", "gdm", "ok"): ("1", "info", "tty1")},
            "su-fail": {("null>sectop-locktest", "su", "failed"): ("2", "crit", "pts/0"),
                        ("null>null", "sudo", "failed"): ("2", "warn", "pts/0"),
                        ("null>null", "sudo", "ok"): ("1", "info", "pts/0"),
                        ("null>sectop-locktest", "faillock", "lock reset"):
                            ("1", "info", "pts/2")},
            "not-sudoers": {("null>sectop-locktest", "sudo", "not in sudoers"):
                                ("1", "crit", "pts/2"),
                            ("null>sectop-locktest", "sudo", "failed"): ("3", "warn", "pts/2"),
                            ("null>null", "sudo", "failed"): ("1", "warn", "pts/0"),
                            ("null>null", "sudo", "ok"): ("1", "info", "pts/0")},
            "faillock": {("null>sectop-locktest", "sudo", "locked"): ("1", "crit", "pts/2"),
                         ("null>sectop-locktest", "sudo", "not in sudoers"):
                             ("2", "crit", "pts/2"),
                         ("null>sectop-locktest", "sudo", "failed"): ("6", "warn", "pts/2"),
                         ("null>sectop-locktest", "faillock", "lock reset"):
                             ("1", "info", "pts/2")},
        }
        for name, rows_ in want.items():
            with self.subTest(fixture=name):
                _, snap = capture(name)
                got = {k: v[:3] for k, v in auth_rows(snap).items()}
                self.assertEqual(got, rows_)

    def test_root_su_is_fine(self):
        """sudo su: root runs su (pam_rootok) -> ok, not the su-by-a-user alert."""
        _, snap = capture("sudo")
        self.assertEqual(auth_rows(snap)[("null>root", "su", "ok")][1], "info")
        self.assertEqual(snap["checks"], [])

    def test_alerts_red_only(self):
        _, snap = capture("faillock")
        self.assertEqual(sorted((c["key"], c["title"], c["n"]) for c in snap["checks"]), [
            ("auth:sudo:locked:null:sectop-locktest", "account locked: sectop-locktest (sudo)",
             1),
            ("auth:sudo:not_in_sudoers:null:sectop-locktest",
             "sudo refused: sectop-locktest not in sudoers", 2)])
        self.assertTrue(all(c["sev"] == "crit" for c in snap["checks"]))
        for name in ("sudo-denied", "polkit", "unlock-fail", "lock"):   # warn / info: no alert
            self.assertEqual(capture(name)[1]["checks"], [], name)
        _, snap = capture("su-fail")
        [c] = snap["checks"]
        self.assertEqual((c["title"], c["n"]), ("su by null to sectop-locktest: failed", 2))

    def test_alert_window(self):
        entries = fix("not-sudoers")
        r = Run()
        snap = r.collect(entries, end(entries) + 10)
        self.assertEqual([c["n"] for c in snap["checks"]], [1])
        snap = r.collect([], end(entries) + 60)
        self.assertEqual([c["n"] for c in snap["checks"]], [0])          # open, nothing new
        snap = r.collect([], end(entries) + sec.WINDOW + 1)
        self.assertEqual(snap["checks"], [])

    def test_su_launch_denied(self):
        """su: the failed USER_AUTH in the launch's own pid marks the launch row denied."""
        _, snap = capture("su-fail")
        n, who, via, d = rows(snap)["su sectop-locktest -c true"]
        self.assertEqual((n, via, d["denied"]), ("3", "denied", "2 of 3"))   # 3rd: no password

    def test_only_what_the_follower_gives(self):
        """The real follower only passes JOURNAL matches: same rows as the whole fixture."""
        for name in ("not-sudoers", "faillock", "su-fail", "unlock-fail", "module", "avc",
                     "kernel-warn", "usb", "logs-2h"):
            entries = fix(name)
            a, b = Run(), Run()
            whole = a.collect(entries, end(entries) + 10)
            matched = b.collect(follower(entries), end(entries) + 10)
            self.assertEqual(whole["panels"], matched["panels"], name)
            self.assertEqual(whole["checks"], matched["checks"], name)
            whole = a.collect([], end(entries) + 20)                    # timed-out events
            matched = b.collect([], end(entries) + 20)
            self.assertEqual(whole["panels"], matched["panels"], name)

    def test_sudo_alert_lines(self):
        a = auth.Auth()
        name = lambda uid: USERS.get(uid, uid or "-")
        line = lambda msg: {"MESSAGE": msg, "_AUDIT_LOGINUID": "1000", "_PID": "7"}
        auth.sudo_alert(a, line("    null : 3 incorrect password attempts ; TTY=pts/1 ; "
                                "USER=root ; COMMAND=/usr/sbin/id"), 1.0, name)
        self.assertEqual(a.rows, {})                                      # USER_AUTH has them
        auth.sudo_alert(a, line("bob : command not allowed ; TTY=pts/3 ; PWD=/ ; USER=root ; "
                                "COMMAND=/usr/bin/vi"), 2.0, name)
        auth.sudo_alert(a, line("bob : a password is required ; TTY=pts/3 ; USER=root ; "
                                "COMMAND=/usr/bin/id"), 3.0, name)
        auth.sudo_alert(a, line("no separator here"), 4.0, name)
        got = {(r.user, r.result): (r.sev, r.tty, r.login) for r in a.rows.values()}
        self.assertEqual(got, {("bob", "not allowed"): ("crit", "pts/3", "null"),
                               ("bob", "a password is required"): ("warn", "pts/3", "null")})

    def test_limits_and_names(self):
        self.assertEqual((auth.service("/usr/libexec/gdm-session-worker"),
                          auth.service("/usr/lib/polkit-1/polkit-agent-helper-1"),
                          auth.service("/usr/bin/sshd"), auth.service("/opt/x/myauth"),
                          auth.service(None)), ("gdm", "polkit", "sshd", "myauth", "?"))
        a = auth.Auth()
        for i in range(auth.MAX_ROWS + 5):
            auth._add(a, "null", f"u{i}", "sudo", "failed", float(i), "warn", "w")
        self.assertEqual(len(a.rows), auth.MAX_ROWS)
        auth._add(a, "a" * 40, "b" * 40, "sudo", "x" * 40, 9e9, "crit", "w")
        [c] = [c for c in auth.checks(a, 9e9, 10, str) if c["sev"] == "crit"]
        self.assertTrue(c["key"].startswith("auth:") and len(c["key"]) <= 128)


def kernel_rows(snap):
    """kind, from, what -> (n, sev, detail)."""
    out = {}
    for r in snap["panels"][2]["rows"]:
        c = r["cells"]
        out[(c[2], c[3], c[4])] = (c[1], r["sev"], {d["k"]: d["v"] for d in r["detail"]})
    return out


def _module_events(*calls) -> list:
    """Audit journal entries (SYSCALL, KERN_MODULE, PROCTITLE) of module syscalls, one
    second apart: (syscall, auid, exe, name or None, success, exit, argv)."""
    out = []
    for i, (nr, auid, exe, name, ok, code, argv) in enumerate(calls):
        us, aid = str(300_000_000 + i * 1_000_000), str(95000 + i)
        msgs = [("1300", "SYSCALL", f"SYSCALL arch=c000003e syscall={nr} success={ok} "
                 f"exit={code} a0=3 a1=2 a2=0 a3=0 items=0 ppid=1 pid={600 + i} "
                 f"auid={auid} uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 "
                 f'tty=(none) ses=4294967295 comm="x" exe="{exe}" key="kernel_modules"')]
        if name:
            msgs.append(("1323", "KERN_MODULE", f'KERN_MODULE name="{name}"'))
        msgs.append(("1327", "PROCTITLE", "PROCTITLE proctitle="
                     + "00".join(a.encode().hex().upper() for a in argv)))
        for typ, tname, msg in msgs:
            out.append({"__REALTIME_TIMESTAMP": us, "_TRANSPORT": "audit", "_AUDIT_ID": aid,
                        "_AUDIT_TYPE": typ, "_AUDIT_TYPE_NAME": tname, "MESSAGE": msg})
    return out


def _klog(*lines) -> list:
    """Kernel log entries one second apart: (PRIORITY, MESSAGE[, _KERNEL_SUBSYSTEM])."""
    out = []
    for i, line in enumerate(lines):
        e = {"__REALTIME_TIMESTAMP": str(400_000_000 + i * 1_000_000), "_TRANSPORT": "kernel",
             "PRIORITY": line[0], "SYSLOG_IDENTIFIER": "kernel", "MESSAGE": line[1]}
        if len(line) > 2:
            e["_KERNEL_SUBSYSTEM"] = line[2]
        out.append(e)
    return out


class TestKernel(unittest.TestCase):
    """Kernel box: fixtures 2026-10-20 from my host (module, avc, kernel-warn, usb)."""

    def test_panel(self):
        r = Run(taint=lambda: 12288)
        snap = r.collect([], 100.0)
        p = snap["panels"][2]
        self.assertEqual((p["id"], p["title"], p["width"], p["columns"], p["types"]),
                         ("kernel", "kernel 0  (taint at start: O E)", "full", kernel.COLUMNS,
                          kernel.TYPES))
        self.assertEqual([q["id"] for q in snap["panels"]],
                         ["commands", "auth", "kernel", "logs"])
        self.assertIn("| kernel 0 |", snap["summary"])

    def test_module_fixture(self):
        _, snap = capture("module")
        got = kernel_rows(snap)
        self.assertEqual({k: v[:2] for k, v in got.items()}, {
            ("module", "null", "load tcp_bbr"): ("1", "warn"),          # modprobe from a login
            ("module", "null", "remove tcp_bbr"): ("1", "warn"),
            ("module", "null", "blocked sctp"): ("1", "info"),          # install sctp /bin/false
            ("usb", "3-2", "045e:0745 Microsoft\u00ae 2.4GHz Transceiver v8.0 (Microsoft)"):
                ("1", "info")})
        d = got[("module", "null", "load tcp_bbr")][2]
        self.assertEqual((d["syscall"], d["cmdline"], d["exe"], d["result"], d["tty"]),
                         ("finit_module", "modprobe tcp_bbr", "/usr/bin/kmod", "ok", "pts2"))
        self.assertEqual(got[("module", "null", "remove tcp_bbr")][2]["syscall"],
                         "delete_module")
        d = got[("module", "null", "blocked sctp")][2]
        self.assertEqual((d["cmdline"], d["install"]), ("modprobe sctp", "sh -c -- /bin/false"))
        d = got[("usb", "3-2", "045e:0745 Microsoft\u00ae 2.4GHz Transceiver v8.0 (Microsoft)")][2]
        self.assertEqual((d["id"], d["bcdDevice"], d["manufacturer"]),
                         ("045e:0745", "6.76", "Microsoft"))
        self.assertEqual(snap["checks"], [])                            # no red: no alert

    def test_autoload_and_failed_load(self):
        r = Run()
        got = kernel_rows(r.collect(_module_events(
            ("313", sec.UNSET, "/usr/lib/systemd/systemd-udevd", "snd_hda_intel", "yes", "0",
             ["/usr/lib/systemd/systemd-udevd"]),
            ("313", sec.UNSET, "/usr/bin/kmod", "tcp_bbr", "yes", "0",
             ["/sbin/modprobe", "-q", "--", "tcp_bbr"]),
            ("313", "1000", "/usr/bin/kmod", "nvidia", "no", "-19", ["modprobe", "nvidia"]),
            ("313", "1000", "/usr/bin/kmod", "nvidia", "no", "-19", ["modprobe", "nvidia"]),
            ("175", "1000", "/usr/bin/kmod", None, "no", "-1", ["insmod", "x.ko"]),
            ("176", "1000", "/usr/bin/kmod", "x", "yes", "0", ["rmmod", "x"])), 400.0))
        self.assertEqual({k: v[:2] for k, v in got.items()}, {
            ("module", "-", "load snd_hda_intel"): ("1", "info"),       # udev: no login
            ("module", "-", "load tcp_bbr"): ("1", "info"),             # kernel request
            ("module", "null", "load nvidia failed ENODEV"): ("2", "warn"),
            ("module", "null", "load ? failed EPERM"): ("1", "warn"),   # no KERN_MODULE
            ("module", "null", "remove x"): ("1", "warn")})
        self.assertEqual(got[("module", "null", "load ? failed EPERM")][2]["syscall"],
                         "init_module")
        self.assertEqual(r.st.kernel.loads, 6)
        self.assertEqual(r.st.runs, 0)                                  # not commands rows

    def test_avc_fixture(self):
        entries = fix("avc")
        r = Run()
        r.collect(entries, end(entries) + 1)
        snap = r.collect([], end(entries) + 10)                         # AVC alone: timed out
        got = kernel_rows(snap)
        self.assertEqual({k: v[:2] for k, v in got.items()}, {
            ("avc", "chcon", "{ mac_admin } tuned_t -> tuned_t capability2"): ("156", "info"),
            ("avc", "lsblk", "{ connectto } bootupd_t -> systemd_machined_t "
                             "unix_stream_socket (allowed)"): ("44", "warn")})
        d = got[("avc", "lsblk", "{ connectto } bootupd_t -> systemd_machined_t "
                                 "unix_stream_socket (allowed)")][2]
        self.assertEqual((d["scontext"], d["path"], d["record"]),
                         ("system_u:system_r:bootupd_t:s0",
                          "/run/systemd/userdb/io.systemd.Machine", "AVC"))
        self.assertEqual(got[("avc", "chcon", "{ mac_admin } tuned_t -> tuned_t "
                                              "capability2")][2]["capability"], "33")
        self.assertEqual(snap["checks"], [])

    def test_user_avc(self):
        msg = ("USER_AVC pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:"
               "init_t:s0 msg='avc:  denied  { status } for auid=n/a uid=0 gid=0 "
               'path="/usr/lib/systemd/system/x.service" cmdline="systemctl status x" '
               "scontext=system_u:system_r:unconfined_service_t:s0 tcontext=system_u:"
               "object_r:systemd_unit_file_t:s0 tclass=service permissive=0 "
               "exe=\"/usr/lib/systemd/systemd\" sauid=0 hostname=? addr=? terminal=?'")
        policy = ("USER_AVC pid=1 uid=0 auid=4294967295 ses=4294967295 msg='avc:  received "
                  "policyload notice (seqno=2)  exe=\"/usr/lib/systemd/systemd\" sauid=0'")
        entries = [{"__REALTIME_TIMESTAMP": str(500_000_000 + i), "_TRANSPORT": "audit",
                    "_AUDIT_ID": str(97000 + i), "_AUDIT_TYPE": "1107",
                    "_AUDIT_TYPE_NAME": "USER_AVC", "MESSAGE": m}
                   for i, m in enumerate((msg, policy))]
        got = kernel_rows(Run().collect(entries, 600.0))
        self.assertEqual(list(got), [("avc", "systemd", "{ status } unconfined_service_t -> "
                                                        "systemd_unit_file_t service")])
        d = next(iter(got.values()))[2]
        self.assertEqual((d["record"], d["path"], d["exe"]),
                         ("USER_AVC", "/usr/lib/systemd/system/x.service",
                          "/usr/lib/systemd/systemd"))

    def test_kernel_log_fixture(self):
        _, snap = capture("kernel-warn")
        got = kernel_rows(snap)
        self.assertEqual(len(got), 33)                                  # 196 lines, 1 empty
        self.assertEqual(got[("log", "kernel", "NVRM: No NVIDIA GPU found.")][:2], ("84", "warn"))
        acpi = [v for k, v in got.items() if k[2].startswith("ACPI BIOS Error (bug): Failure")]
        self.assertEqual([v[:2] for v in acpi], [("36", "warn")])       # [..] paths: one group
        [row] = [r for r in snap["panels"][2]["rows"]
                 if r["cells"][4].startswith("ACPI BIOS Error (bug): Failure")]
        lines = [d["v"] for d in row["detail"] if d["k"] == "line"]
        self.assertEqual(len(set(lines)), kernel.MAX_MSGS)              # newest 3, distinct
        self.assertEqual(lines[0], row["cells"][4])
        martian = got[("log", "kernel", "IPv4: martian source (src=192.168.8.1, "
                                        "dst=192.168.8.102, dev=wlo1)")]
        self.assertEqual(martian[:2], ("3", "info"))
        self.assertEqual(martian[2]["priority"], "4 warning")
        self.assertEqual(got[("log", "i2c", "spd5118 14-0052: Failed to write b = 0: -6")][:2],
                         ("2", "warn"))                                 # two devices: one group
        sevs = collections.Counter(v[1] for v in got.values())
        self.assertEqual(dict(sevs), {"warn": 10, "info": 23})
        self.assertEqual(snap["checks"], [])

    def test_kernel_log_levels_and_alert(self):
        r = Run()
        entries = _klog(("0", "Kernel panic - not syncing: x"), ("2", "BUG: soft lockup - CPU#3 "
                        "stuck for 23s! [x:123]"), ("2", "BUG: soft lockup - CPU#5 stuck for "
                        "41s! [y:456]"), ("3", "e1000e: probe failed"), ("4", "warn line"),
                        ("5", "notice line"), ("6", "HFW-OUT-NEW: IN= OUT=wlo1"),
                        ("4", "HFW-IN-DROP: IN=wlo1"), ("6", "usb 1-1: new high-speed USB "
                        "device number 2 using xhci_hcd", "usb"))
        snap = r.collect(entries, 410.0)
        got = kernel_rows(snap)
        self.assertEqual(sorted((k[2][:15], v[0], v[1]) for k, v in got.items()), [
            ("BUG: soft locku", "2", "crit"), ("Kernel panic - ", "1", "crit"),
            ("e1000e: probe f", "1", "warn"), ("warn line", "1", "info")])   # no 5, 6, HFW
        self.assertEqual(sorted((c["title"], c["n"]) for c in snap["checks"]),
                         [("kernel crit: BUG: soft lockup - CPU#5 stuck for 41s! [y:456]", 2),
                          ("kernel emerg: Kernel panic - not syncing: x", 1)])
        self.assertTrue(all(c["key"].startswith("kernel:log:") for c in snap["checks"]))
        snap = r.collect([], 410.0 + 60)
        self.assertEqual([c["n"] for c in snap["checks"]], [0, 0])     # open, nothing new
        snap = r.collect([], 405.0 + sec.WINDOW)                        # last at 402 s
        self.assertEqual([c["title"][:12] for c in snap["checks"]], [])

    def test_taint(self):
        value = [12288]
        r = Run(taint=lambda: value[0])
        r.collect([], 100.0)
        value[0] = 12288 | 1 << 9                                       # W
        snap = r.collect([], 102.0)
        got = kernel_rows(snap)
        self.assertEqual({k: v[:2] for k, v in got.items()},
                         {("taint", "kernel", "W  kernel warning"): ("1", "warn")})
        self.assertEqual(snap["checks"], [])                            # warn: row only
        self.assertEqual(snap["panels"][2]["title"],
                         "kernel 1  (taint at start: O E, now: W O E)")
        value[0] |= 1 << 7 | 1 << 14                                    # D, L
        snap = r.collect([], 104.0)
        self.assertEqual(sorted((c["key"], c["title"], c["n"]) for c in snap["checks"]), [
            ("kernel:taint:D", "kernel tainted: D kernel died (oops or BUG)", 1),
            ("kernel:taint:L", "kernel tainted: L soft lockup", 1)])
        snap = r.collect([], 106.0)                                     # stays one row each
        self.assertEqual([k[2] for k in kernel_rows(snap)],
                         ["D  kernel died (oops or BUG)", "L  soft lockup", "W  kernel warning"])
        self.assertEqual([c["n"] for c in snap["checks"]], [0, 0])
        d = kernel_rows(snap)[("taint", "kernel", "D  kernel died (oops or BUG)")][2]
        self.assertEqual((d["bit"], d["at start"]), ("7", "12288"))
        snap = r.collect([], 104.0 + sec.WINDOW + 1)
        self.assertEqual(snap["checks"], [])                            # rows stay, alert ends
        self.assertEqual(len(kernel_rows(snap)), 3)

    def test_taint_out_of_tree_later_is_red(self):
        value = [0]
        r = Run(taint=lambda: value[0])
        r.collect([], 100.0)
        value[0] = 1 << 12 | 1 << 13 | 1                                # O E P
        snap = r.collect([], 102.0)
        self.assertEqual(sorted(c["key"] for c in snap["checks"]),
                         ["kernel:taint:E", "kernel:taint:O", "kernel:taint:P"])
        value[0] |= 1 << 2                                               # S: not in the table
        got = kernel_rows(r.collect([], 104.0))
        self.assertEqual(got[("taint", "kernel", "S  system out of spec")][1], "warn")

    def test_taint_unreadable(self):
        def fail():
            raise PermissionError(13, "Permission denied")
        r = Run(taint=fail)
        snap = r.collect([], 100.0)
        self.assertEqual(snap["panels"][2]["title"], "kernel 0  (taint: Permission denied)")
        value = [12288]
        r.st.taint = lambda: value[0]
        self.assertEqual(r.collect([], 102.0)["panels"][2]["title"],
                         "kernel 0  (taint at start: O E)")
        r.st.taint = lambda: int("x")
        self.assertIn("(read: invalid literal", r.collect([], 104.0)["panels"][2]["title"])

    def test_taint_file(self):
        with tempfile.NamedTemporaryFile("w", encoding="ascii") as f:
            f.write("12288\n")
            f.flush()
            self.assertEqual(kernel.read_taint(f.name), 12288)
        self.assertEqual(kernel.letters(12288), "O E")
        self.assertEqual(kernel.letters(1), "P")
        self.assertEqual(kernel.letters(0), "")
        self.assertEqual(kernel.letters(1 << 25), "bit25")

    def test_usb_replug_and_product_later(self):
        r = Run()
        new = "usb 3-2: New USB device found, idVendor=045E, idProduct=0745, bcdDevice= 6.76"
        snap = r.collect(_klog(("6", new, "usb")), 410.0)
        self.assertEqual(list(kernel_rows(snap)), [("usb", "3-2", "045e:0745")])
        snap = r.collect(_klog(("6", "usb 3-2: Product: Receiver", "usb"),
                               ("6", "usb 3-1: Product: other port", "usb")), 411.0)
        self.assertEqual(list(kernel_rows(snap)), [("usb", "3-2", "045e:0745 Receiver")])
        snap = r.collect(_klog(("6", new.replace("3-2", "1-4"), "usb")), 412.0)
        [(key, (n, sev, d))] = kernel_rows(snap).items()
        self.assertEqual((key, n, sev, d["port"]),
                         (("usb", "1-4", "045e:0745 Receiver"), "2", "info", "1-4"))

    def test_normalize(self):
        self.assertEqual(kernel.normalize("spd5118 14-0050: Failed  to write b = 0: -6"),
                         "spd# #-#: Failed to write b = #: -#")
        self.assertEqual(kernel.normalize("x [\\_SB.PC00.XHCI] at 0xfedc0000 192.168.8.1"),
                         "x [.] at <hex> <ip>")

    def test_limits(self):
        k = kernel.Kernel()
        for i in range(kernel.MAX_ROWS + 10):
            word = "".join(chr(97 + int(d)) for d in str(i))
            kernel.journal_entry(k, {"_TRANSPORT": "kernel", "PRIORITY": "4",
                                     "MESSAGE": f"line {word}"}, float(i))
        self.assertEqual(len(k.rows), kernel.MAX_ROWS)
        kernel.taint(k, lambda: 0, 1.0)
        kernel.taint(k, lambda: (1 << 20) - 1, 2.0)                     # every bit
        self.assertEqual(len(kernel.rows(k, str)), kernel.MAX_ROWS + 20)
        self.assertLessEqual(kernel.MAX_ROWS + 20, 200)                  # panel max


def log_rows(snap):
    """from, what -> (n, sev, detail, tone)."""
    out = {}
    for r in snap["panels"][3]["rows"]:
        c = r["cells"]
        out[(c[2], c[3])] = (c[1], r["sev"], {d["k"]: d["v"] for d in r["detail"]}, r.get("tone"))
    return out


def _watch_events(*writes) -> list:
    """Audit entries of file watch hits, one second apart: (key, exe, path, auid)."""
    out = []
    for i, (key, exe, path, auid) in enumerate(writes):
        us, aid = str(600_000_000 + i * 1_000_000), str(98000 + i)
        for typ, name, msg in (
                ("1300", "SYSCALL", f"SYSCALL arch=c000003e syscall=257 success=yes exit=3 a0=1 "
                 f"a1=2 a2=3 a3=4 items=2 ppid=1 pid={700 + i} auid={auid} uid=0 gid=0 euid=0 "
                 f'suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="x" exe="{exe}" '
                 f'subj=unconfined_u:unconfined_r:unconfined_t:s0 key="{key}"'),
                ("1302", "PATH", f'PATH item=0 name="{os.path.dirname(path)}/" inode=1 '
                 f"nametype=PARENT"),
                ("1302", "PATH", f'PATH item=1 name="{path}" inode=2 nametype=NORMAL'),
                ("1327", "PROCTITLE", "PROCTITLE proctitle=" + os.path.basename(exe)
                 .encode().hex().upper())):
            out.append({"__REALTIME_TIMESTAMP": us, "_TRANSPORT": "audit", "_AUDIT_ID": aid,
                        "_AUDIT_TYPE": typ, "_AUDIT_TYPE_NAME": name, "MESSAGE": msg})
    return out


def _socket_events(*calls) -> list:
    """Audit entries of af-alg socket rule hits (no PATH record), one second apart:
    (arch, syscall, exit, exe)."""
    out = []
    for i, (arch, nr, code, exe) in enumerate(calls):
        us, aid = str(650_000_000 + i * 1_000_000), str(97000 + i)
        ok = "no" if code.startswith("-") else "yes"
        for typ, name, msg in (
                ("1300", "SYSCALL", f"SYSCALL arch={arch} syscall={nr} success={ok} exit={code} "
                 f"a0=26 a1=5 a2=0 a3=0 items=0 ppid=1 pid={800 + i} auid=1000 uid=1000 "
                 f"gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 "
                 f'tty=pts0 ses=3 comm="x" exe="{exe}" '
                 f'subj=unconfined_u:unconfined_r:unconfined_t:s0 key="af-alg"'),
                ("1327", "PROCTITLE", "PROCTITLE proctitle=" + os.path.basename(exe)
                 .encode().hex().upper())):
            out.append({"__REALTIME_TIMESTAMP": us, "_TRANSPORT": "audit", "_AUDIT_ID": aid,
                        "_AUDIT_TYPE": typ, "_AUDIT_TYPE_NAME": name, "MESSAGE": msg})
    return out


def _jlines(*lines) -> list:
    """Journal entries one second apart: (PRIORITY, SYSLOG_IDENTIFIER, MESSAGE, unit)."""
    return [{"__REALTIME_TIMESTAMP": str(700_000_000 + i * 1_000_000), "_TRANSPORT": "journal",
             "PRIORITY": p, "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg, "_SYSTEMD_UNIT": unit}
            for i, (p, ident, msg, unit) in enumerate(lines)]


class TestLogs(unittest.TestCase):
    """Logs box: fixture logs-2h 2026-10-26 (journal PRIORITY <= 4 + audit, 1.75 h, masked)."""

    def test_fixture(self):
        entries = fix("logs-2h")
        r = Run()
        r.collect(entries, end(entries) + 1)
        snap = r.collect([], end(entries) + 10)                      # timed-out audit events
        got = log_rows(snap)
        p = snap["panels"][3]
        self.assertEqual((p["id"], p["width"], p["columns"], len(got)),
                         ("logs", "full", logs.COLUMNS, 50))
        self.assertEqual(collections.Counter(v[1] for v in got.values()), {"info": 47, "warn": 3})
        self.assertEqual(snap["checks"], [])                          # nothing red in 2 h
        self.assertEqual(got[("audit sudo_log_file", "sudo /var/log/sudo.log")][:2],
                         ("20", "info"))                              # sudo writes its own log
        self.assertEqual(got[("audit session", "sudo /var/run/utmp")][:2], ("40", "info"))
        pam = got[("sudo", "pam_systemd(sudo:session): Failed to check if /run/user/0/bus "
                           "exists, ignoring: Permission denied")]
        self.assertEqual((pam[0], pam[1], pam[2]["unit"]), ("14", "info", "session-#.scope"))
        app = [v for k, v in got.items() if k[0] == "appstreamcli"]
        self.assertEqual([v[0] for v in app], ["9"])                  # quoted app ids: 1 group
        self.assertEqual(got[("selinux", "setxattr invalid context "
                                         "invalid_bootcinstall_testlabel_t")][:2], ("6", "info"))
        tmp = [v for k, v in got.items() if k[0] == "systemd-tmpfiles"]
        self.assertEqual([(v[0], v[1]) for v in tmp], [("3", "warn")])
        locale = [v for k, v in got.items() if k[0] == "audit system-locale"]
        self.assertEqual(sorted(int(v[0]) for v in locale), [4, 8])   # temp files: 1 group
        self.assertFalse(any(k[0] == "kernel" for k in got))           # kernel box has them
        d = got[("audit sudo_log_file", "sudo /var/log/sudo.log")][2]
        self.assertEqual((d["exe"], d["file"], d["noise key"][:13]),
                         ("/usr/bin/sudo", "/var/log/sudo.log", "security/log:"))

    def test_owners(self):
        r = Run()
        got = log_rows(r.collect(_watch_events(
            ("sudo_log_file", "/usr/bin/sudo", "/var/log/sudo.log", "1000"),
            ("sudo_log_file", "/usr/bin/vi", "/var/log/sudo.log", "1000"),
            ("identity", "/usr/bin/systemd-sysusers", "/etc/passwd", "4294967295"),
            ("identity", "/usr/bin/vim", "/etc/shadow", "1000"),
            ("scope", "/usr/sbin/visudo", "/etc/sudoers.d/90-cis", "1000"),
            ("MAC-policy", "/usr/sbin/semodule", "/var/lib/selinux/targeted/active", "1000"),
            ("system-locale", "/usr/bin/sed", "/etc/hosts", "1000"),
            ("perm_chng", "/usr/bin/chcon", "/usr/bin/chcon", "1000")), 800.0))
        sev = {k: v[1] for k, v in got.items()}
        self.assertEqual(sev, {
            ("audit sudo_log_file", "sudo /var/log/sudo.log"): "info",
            ("audit sudo_log_file", "vi /var/log/sudo.log"): "warn",
            ("audit identity", "systemd-sysusers /etc/passwd"): "info",
            ("audit identity", "vim /etc/shadow"): "warn",
            ("audit scope", "visudo /etc/sudoers.d/90-cis"): "warn",
            ("audit MAC-policy", "semodule /var/lib/selinux/targeted/active"): "warn",
            ("audit system-locale", "sed /etc/hosts"): "warn",
            ("audit perm_chng", "chcon /usr/bin/chcon"): "info"})
        d = got[("audit identity", "vim /etc/shadow")][2]
        self.assertEqual((d["login"], d["why"][:38]), ("null", "audit key identity: written by vim, no"))
        self.assertEqual(r.st.runs, 0)                               # not commands rows

    def test_af_alg(self):
        """socket(AF_ALG) rule (key af-alg): no file; blocked by initcall_blacklist =
        EAFNOSUPPORT (host test 2026-11-01: python3 socket(AF_ALG) -> errno 97)."""
        r = Run()
        snap = r.collect(_socket_events(
            ("c000003e", "41", "-97", "/usr/bin/python3.14"),
            ("c000003e", "41", "-97", "/usr/bin/python3.14"),
            ("40000003", "359", "-97", "/opt/game/bin32"),
            ("c000003e", "41", "3", "/usr/bin/python3.14")), 660.0)
        got = log_rows(snap)
        self.assertEqual({k: (v[0], v[1]) for k, v in got.items()}, {
            ("audit af-alg", "python3.14 socket failed EAFNOSUPPORT"): ("2", "warn"),
            ("audit af-alg", "bin32 socket failed EAFNOSUPPORT"): ("1", "warn"),
            ("audit af-alg", "python3.14 socket ok"): ("1", "warn")})
        d = got[("audit af-alg", "python3.14 socket failed EAFNOSUPPORT")][2]
        self.assertEqual((d["file"], d["syscall"], d["result"], d["login"]),
                         ("-", "socket failed", "failed EAFNOSUPPORT", "null"))
        self.assertTrue(d["why"].startswith("AF_ALG socket"))
        self.assertNotIn("result", got[("audit af-alg", "python3.14 socket ok")][2])
        self.assertEqual([c for c in snap["checks"] if c["key"].startswith("log:")], [])

    def test_levels_alert_and_own(self):
        r = Run()
        snap = r.collect(_jlines(
            ("2", "systemd", "Freezing execution.", "init.scope"),
            ("3", "sectop-collector", "security: collect failed", "sectop.service"),
            ("4", "gnome-shell", "warn 1", "user@1000.service"),
            ("1", "sudo", "bob : user NOT in sudoers ; TTY=pts/0", "session-c1.scope"),
            ("5", "systemd", "notice line", "init.scope")), 710.0)
        got = log_rows(snap)
        self.assertEqual({k: v[1] for k, v in got.items()}, {
            ("systemd", "Freezing execution."): "crit",
            ("sectop-collector (own)", "security: collect failed"): "warn",
            ("gnome-shell", "warn 1"): "info"})                       # sudo alert: auth box
        self.assertIn("own", got[("sectop-collector (own)", "security: collect failed")][2])
        [c] = [c for c in snap["checks"] if c["key"].startswith("log:")]
        self.assertEqual((c["title"], c["n"]), ("systemd crit: Freezing execution.", 1))
        snap = r.collect([], 700.0 + sec.WINDOW + 1)
        self.assertEqual([c for c in snap["checks"] if c["key"].startswith("log:")], [])

    def test_noise(self):
        lines = _jlines(("3", "systemd-tmpfiles", '"/home" already exists', "x.service"),
                        ("3", "systemd-tmpfiles", '"/srv" already exists', "x.service"),
                        ("4", "gnome-shell", "other", "user@1000.service"))
        r = Run()
        key = log_rows(r.collect(lines, 710.0))[("systemd-tmpfiles", '"/srv" already exists')
                                                 ][2]["noise key"]
        import datetime
        from core.noise import Entry
        r.st.logs.noise = (Entry(key, "Silverblue: /home is a symlink", datetime.date(2099, 1, 1)),)
        snap = r.collect([], 711.0)
        got = log_rows(snap)
        tmp = got[("systemd-tmpfiles", '"/srv" already exists')]
        self.assertEqual((tmp[0], tmp[3], tmp[2]["noise"]),
                         ("2", "dim", "Silverblue: /home is a symlink"))
        self.assertIsNone(got[("gnome-shell", "other")][3])
        self.assertIn("1 noise)", snap["panels"][3]["title"])
        r.st.logs.noise = (Entry(key, "old", datetime.date(1969, 12, 31)),)  # expired
        self.assertIsNone(log_rows(r.collect([], 712.0))[("systemd-tmpfiles",
                                                           '"/srv" already exists')][3])

    def test_init_reads_noise_file(self):
        with WatchFile(None), NoiseFile(b'[[noise]]\nmatch = "security/log:*"\nreason = "r"\n'
                                        b"expires = 2099-01-01\n"):
            st = sec.init({})
        self.assertEqual([e.match for e in st.logs.noise], ["security/log:*"])

    def test_normalize(self):
        self.assertEqual(logs.normalize("Found icon in 'a/b/*', skipping it."),
                         logs.normalize("Found icon in 'c/d/*', skipping it."))
        self.assertEqual(logs.normalize("PID 4898 at 0x55fc5ab35cf8 from 10.1.2.3"),
                         "PID # at <hex> from <ip>")

    def test_limits(self):
        lg = logs.Logs()
        for i in range(logs.MAX_ROWS + 5):
            word = "".join(chr(97 + int(d)) for d in str(i))
            logs.journal_entry(lg, {"_TRANSPORT": "journal", "PRIORITY": "4",
                                    "SYSLOG_IDENTIFIER": word, "MESSAGE": "x"}, float(i))
        self.assertEqual(len(lg.rows), logs.MAX_ROWS)



class TestProgs(unittest.TestCase):
    """Row progs (c = program card): the program of the audit record's process, else of
    its parent (core/proc.py checks the pid was not reused); journal: its cgroup."""

    PROGS = {"601": "org.gnome.Ptyxis", "4124": "gdm", "1376": "bootupd", "700": None}

    def run_(self):
        return Run(prog=lambda pid, ts: self.PROGS.get(pid))

    def test_commands_and_logs_audit(self):
        r = self.run_()
        snap = r.collect(_events((602, 601, "0", "/usr/bin/id", ["id"], "root_cmds"),
                                 (603, 999, "0", "/usr/bin/tty", ["tty"], "root_cmds")), 200.0)
        got = {row["cells"][4]: row.get("progs") for row in snap["panels"][0]["rows"]}
        self.assertEqual(got, {"id": ["org.gnome.Ptyxis"], "tty": None})   # via the parent
        snap = r.collect(_watch_events(("identity", "/usr/bin/vim", "/etc/shadow", "1000")),
                         800.0)
        self.assertEqual([row.get("progs") for row in snap["panels"][3]["rows"]], [None])

    def test_root_shell_gets_the_terminal(self):
        """sudo su -> bash -> id (fixture sudo): sudo moves into its session scope and the
        root shell stays there; the program is the one of the shell sudo was typed in
        (sudo's parent), handed down the chain."""
        entries = fix("sudo")
        sudo = next(e for e in entries if e.get("_AUDIT_TYPE_NAME") == "EXECVE"
                    and '"sudo"' in e["MESSAGE"] and '"su"' in e["MESSAGE"])
        sid = sudo["_AUDIT_ID"]
        ppid = next(e["MESSAGE"].split(" ppid=")[1].split()[0] for e in entries
                    if e.get("_AUDIT_ID") == sid and e.get("_AUDIT_TYPE_NAME") == "SYSCALL")
        r = Run(prog=lambda pid, ts: "org.gnome.Ptyxis" if pid == ppid else None)
        _, snap = r, r.collect(entries, end(entries) + 10)
        got = {row["cells"][4]: row.get("progs") for row in snap["panels"][0]["rows"]}
        for cmd in ("su", "bash", "id", "tty", "sudo -k"):
            self.assertEqual(got[cmd], ["org.gnome.Ptyxis"], cmd)

    def test_auth_kernel_and_journal(self):
        entries = fix("unlock-fail")
        snap = Run(prog=lambda pid, ts: "gdm").collect(entries, end(entries) + 10)
        self.assertTrue(all(row.get("progs") == ["gdm"] for row in snap["panels"][1]["rows"]))
        entries = fix("avc")
        r = self.run_()
        r.collect(entries, end(entries) + 1)
        snap = r.collect([], end(entries) + 10)
        progs = {row["cells"][3]: row.get("progs") for row in snap["panels"][2]["rows"]}
        self.assertEqual(progs["lsblk"], ["bootupd"])                    # pid 1376 of the AVC
        line = {"__REALTIME_TIMESTAMP": "700000000", "_TRANSPORT": "journal", "PRIORITY": "4",
                "SYSLOG_IDENTIFIER": "gnome-shell", "MESSAGE": "w",
                "_SYSTEMD_CGROUP": "/user.slice/user-1000.slice/user@1000.service/session.slice"
                                   "/org.gnome.Shell@wayland.service"}
        snap = r.collect([line], 710.0)
        self.assertEqual(snap["panels"][3]["rows"][0]["progs"], ["org.gnome.Shell"])

class TestWatch(unittest.TestCase):
    def run_(self, *execs, now=200.0, r=None):
        r = r or Run()
        if not r.st.rules:
            r.st = sec.State(wall=r.st.wall, user=r.st.user, stamp=r.st.stamp,
                             rules=watch.parse(RULES), prog=r.st.prog)
        return r, r.collect(_events(*execs), now)

    def test_rows_rated(self):
        r, snap = self.run_(
            (900, 1, "0", "/usr/bin/setenforce", ["setenforce", "0"], "root_cmds"),
            (901, 1, "0", "/usr/bin/setenforce", ["setenforce", "1"], "root_cmds"),
            (902, 1, "1000", "/usr/bin/kmod", ["modprobe", "nvidia"], "user_emulation"),
            (903, 1, "0", "/usr/bin/systemctl", ["systemctl", "restart", "sectop.service"],
             "root_cmds"),
            (904, 1, "0", "/usr/bin/id", ["id"], "root_cmds"))
        sev = {row["cells"][4]: row["sev"] for row in snap["panels"][0]["rows"]}
        self.assertEqual(sev, {"setenforce 0": "crit", "setenforce 1": "ok",       # own rows
                               "modprobe nvidia": "warn",
                               "systemctl restart sectop.service": "info", "id": "ok"})
        got = rows(snap)
        self.assertEqual(got["setenforce 0"][3]["watch"], "selinux-permissive: SELinux off")
        self.assertNotIn("watch", got["id"][3])
        [c] = snap["checks"]                                    # crit only
        self.assertTrue(c["key"].startswith("watch:selinux-permissive:"))
        self.assertEqual((c["sev"], c["title"], c["n"]), ("crit", "SELinux off: setenforce 0", 1))
        self.assertIn("null>root via ppid 1", c["detail"])

    def test_alert_window(self):
        ev = (900, 1, "0", "/usr/bin/setenforce", ["setenforce", "0"], "root_cmds")
        r, snap = self.run_(ev)
        last = 100.0                                            # _events: first one at 100 s
        self.assertEqual(snap["checks"][0]["n"], 1)
        snap = r.collect([], last + 60)
        self.assertEqual(snap["checks"][0]["n"], 0)              # still open, nothing new
        _, snap = self.run_(ev, now=last + 120, r=r)
        self.assertEqual(snap["checks"][0]["n"], 1)              # ran again
        snap = r.collect([], 100.0 + sec.WINDOW + 1)             # 2nd run was at 100 s too
        self.assertEqual(snap["checks"], [])                     # older than the window

    def test_env_and_bash_of_one_script_one_alert(self):
        r, snap = self.run_(
            (910, 1, "0", "/usr/bin/env", ["/usr/bin/env", "bash", "/usr/local/sbin/hostfw",
                                           "observe"], "root_cmds"),
            (910, 1, "0", "/usr/bin/bash", ["bash", "/usr/local/sbin/hostfw", "observe"],
             "root_cmds"))
        self.assertEqual([row["sev"] for row in snap["panels"][0]["rows"]], ["crit", "crit"])
        [c] = snap["checks"]
        self.assertEqual((c["title"], c["n"]),
                         ("hostfw off: /usr/local/sbin/hostfw observe", 1))   # one run


RULES = b"""
[[rule]]
id = "selinux-permissive"
sev = "crit"
cmd = "setenforce 0|[Pp]ermissive"
why = "SELinux off"

[[rule]]
id = "hostfw-off"
sev = "crit"
cmd = "hostfw observe|remove"
why = "hostfw off"

[[rule]]
id = "kernel-module"
sev = "warn"
cmd = "modprobe|insmod|rmmod !-n"
why = "module"

[[rule]]
id = "unit-change"
sev = "info"
cmd = "systemctl start|restart"
why = "unit"
"""


class WatchFile:
    """sec.WATCH_PATH -> a file with this content (None: missing), owned by me."""

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        os.chmod(self.dir.name, 0o755)
        path = os.path.join(self.dir.name, "watch.toml")
        if self.data is not None:
            with open(path, "wb") as f:
                f.write(self.data)
            os.chmod(path, 0o644)
        self.saved = (sec.WATCH_PATH, sec.WATCH_OWNER)
        sec.WATCH_PATH, sec.WATCH_OWNER = path, os.getuid()
        return self

    def __exit__(self, *exc):
        sec.WATCH_PATH, sec.WATCH_OWNER = self.saved
        self.dir.cleanup()


class NoiseFile(WatchFile):
    """sec.NOISE_PATH -> a file with this content, owned by me."""

    def __enter__(self):
        self.dir = tempfile.TemporaryDirectory()
        os.chmod(self.dir.name, 0o755)
        path = os.path.join(self.dir.name, "noise.toml")
        with open(path, "wb") as f:
            f.write(self.data)
        os.chmod(path, 0o644)
        self.saved_noise = (sec.NOISE_PATH, sec.NOISE_OWNER)
        sec.NOISE_PATH, sec.NOISE_OWNER = path, os.getuid()
        return self

    def __exit__(self, *exc):
        sec.NOISE_PATH, sec.NOISE_OWNER = self.saved_noise
        self.dir.cleanup()


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
