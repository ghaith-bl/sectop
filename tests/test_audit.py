import hashlib
import json
import os
import unittest

from core import audit
from core.audit import Assembler, argv, decode, fields, keys, proctitle, text

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "security")


def fix(name):
    with open(os.path.join(FIX, name + ".json"), encoding="ascii") as f:
        return [json.loads(line) for line in f if line.strip()]


def events(name, now=0.0):
    a = Assembler()
    out = a.feed(fix(name), now)
    return out, a


def rec(aid, t, name, msg, us=1792509946000000, **more):
    e = {"_TRANSPORT": "audit", "_AUDIT_ID": str(aid), "_AUDIT_TYPE": str(t),
         "_AUDIT_TYPE_NAME": name, "MESSAGE": msg, "__REALTIME_TIMESTAMP": str(us)}
    e.update(more)
    return e


def execve(*msgs):
    return [audit.Record(1309, "EXECVE", m, 0.0, fields(m)) for m in msgs]


class TestFixtures(unittest.TestCase):
    def test_sha256sums(self):
        """tests/fixtures/security = sectop-fixtures-2026-10-20.tar (journal_fixture.py)."""
        with open(os.path.join(FIX, "SHA256SUMS"), encoding="ascii") as f:
            sums = [line.split() for line in f if line.strip()]
        self.assertEqual(len(sums), 10)
        for digest, name in sums:
            with open(os.path.join(FIX, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, name)


class TestFields(unittest.TestCase):
    def test_syscall(self):
        f = fields('SYSCALL arch=c000003e syscall=59 success=yes exit=0 a0=5632ba217390 '
                   'a3=21 ppid=30226 pid=44375 auid=1000 uid=1000 euid=0 tty=pts0 ses=18 '
                   'comm="sudo" exe="/usr/bin/sudo" subj=unconfined_u:unconfined_r:'
                   'unconfined_t:s0-s0:c0.c1023 key="user_emulation"')
        self.assertEqual((f["syscall"], f["euid"], f["exe"]), ("59", "0", '"/usr/bin/sudo"'))
        self.assertEqual(text(f, "exe"), "/usr/bin/sudo")
        self.assertEqual(text(f, "a3"), "21")            # SYSCALL args: numbers, not encoded
        self.assertEqual(text(f, "subj"), "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023")
        self.assertEqual(keys(f), ("user_emulation",))

    def test_user_record_msg_opened(self):
        f = fields("AUDIT1123 pid=45097 uid=1000 auid=1000 ses=18 subj=unconfined_u:x "
                   "msg='cwd=\"/var/home/null/x y\" cmd=6D6F6470726F6265207463705F626272 "
                   "exe=\"/usr/bin/sudo\" terminal=pts/1 res=success'")
        self.assertNotIn("msg", f)
        self.assertEqual((text(f, "cmd"), text(f, "cwd"), text(f, "terminal"), text(f, "res")),
                         ("modprobe tcp_bbr", "/var/home/null/x y", "pts/1", "success"))
        self.assertEqual(text(f, "auid"), "1000")

    def test_avc_words_skipped(self):
        f = fields('AVC avc:  denied  { connectto } for  pid=1376 comm="lsblk" '
                   'scontext=system_u:system_r:bootupd_t:s0 tclass=unix_stream_socket '
                   'permissive=1')
        self.assertEqual((text(f, "comm"), f["tclass"], f["permissive"]),
                         ("lsblk", "unix_stream_socket", "1"))

    def test_decode(self):
        self.assertEqual(decode('"id"'), "id")
        self.assertEqual(decode("7375646F207375"), "sudo su")
        self.assertIsNone(decode("(null)"))
        self.assertIsNone(decode(None))
        self.assertEqual(decode("?"), "?")
        self.assertEqual(decode("5632ba"), "5632ba")      # lower case: not audit hex
        self.assertEqual(decode("ABC"), "ABC")            # odd length: not hex
        self.assertEqual(decode("4142", encoded=False), "4142")
        self.assertEqual(decode('"x"', encoded=False), "x")
        self.assertEqual(decode("FF"), "\ufffd")          # not UTF-8: replaced

    def test_keys(self):
        self.assertEqual(keys(fields("SYSCALL key=(null)")), ())
        self.assertEqual(keys(fields("SYSCALL x=1")), ())
        self.assertEqual(keys(fields("SYSCALL key=6B31016B32")), ("k1", "k2"))   # 0x01 joined


class TestArgv(unittest.TestCase):
    def test_quoted_and_hex(self):
        self.assertEqual(argv(execve('EXECVE argc=3 a0="tr" a1=5C6E a2=20')),
                         ["tr", "\\n", " "])

    def test_chunks_over_records(self):
        """Kernel format (auditsc.c): a<n>_len=, a<n>[i]=, the argument goes on in the next
        record; encoding once per argument. Synthetic: no long argument in the fixtures."""
        long = "x" * 9 + " y"
        h = long.encode().hex().upper()
        recs = execve(f'EXECVE argc=3 a0="cmd" a1_len={len(long)} a1[0]={h[:8]}',
                      f'EXECVE a1[1]={h[8:16]} a1[2]={h[16:]} a2="end"')
        self.assertEqual(argv(recs), ["cmd", long, "end"])

    def test_quoted_chunks_and_missing(self):
        self.assertEqual(argv(execve('EXECVE argc=2 a0="a" a1_len=4 a1[0]="ab" a1[1]="cd"')),
                         ["a", "abcd"])
        self.assertEqual(argv(execve('EXECVE argc=3 a0="a" a2="c"')), ["a", "", "c"])
        self.assertEqual(argv(execve('EXECVE a0="a" a1="b"')), ["a", "b"])    # no argc
        self.assertEqual(argv([]), [])

    def test_proctitle(self):
        self.assertEqual(proctitle("7375646F002D6B"), "sudo -k")
        self.assertEqual(proctitle('"bash"'), "bash")
        self.assertIsNone(proctitle(None))


class TestAssembler(unittest.TestCase):
    def test_sudo_capture(self):
        evs, a = events("sudo")
        self.assertEqual((len(evs), len(a.open), a.bad), (137, 0, 0))    # all complete
        syscalls = [e for e in evs if e.kind == "SYSCALL"]
        self.assertEqual(len(syscalls), 104)                 # = PROCTITLE records
        self.assertTrue(all(e.records[-1].name == "PROCTITLE" for e in syscalls))
        launch = [e.argv for e in syscalls if e.keys == ("user_emulation",)]
        self.assertEqual(launch, [["sudo", "-k"], ["sudo", "id"], ["sudo", "su"]])
        e = next(e for e in syscalls if e.keys == ("root_cmds",) and e.argv == ["id"])
        self.assertEqual((e.get("auid"), e.get("uid"), e.get("euid"), e.get("exe"), e.get("ses")),
                         ("1000", "0", "0", "/usr/bin/id", "18"))
        self.assertEqual((e.cwd, e.proctitle), ("/var/home/null/my-project/sectop", "id"))
        sed = next(e for e in syscalls if e.get("exe") == "/usr/bin/sed")
        self.assertEqual(sed.argv[3], "s/^[[:blank:]]*([[:upper:]_]+)=([[:print:][:digit:]"
                                      "\\._-]+|\"[[:print:][:digit:]\\._-]+\")/export "
                                      "\\1=\\2/;t;d")                 # hex in the record
        cmds = [(e.get("cmd"), e.get("res")) for e in evs if e.kind == "AUDIT1123"]
        self.assertEqual(cmds, [("id", "success"), ("su", "success")])

    def test_failed_execve_has_no_argv(self):
        """PATH search: execve of /usr/local/sbin/cat fails (exit -2), no EXECVE record."""
        evs, _ = events("sudo")
        failed = [e for e in evs if e.kind == "SYSCALL" and e.get("success") == "no"
                  and e.get("exe") == "/usr/bin/xargs"]
        self.assertEqual(len(failed), 4)
        self.assertEqual({(tuple(e.argv), e.get("exit"), text(e.first("PATH").raw, "name"))
                          for e in failed},
                         {((), "-2", "/usr/local/sbin/cat"), ((), "-2", "/usr/local/bin/cat")})

    def test_denied_and_modules(self):
        evs, _ = events("sudo-denied")
        self.assertIn(("id", "failed"), [(e.get("cmd"), e.get("res")) for e in evs
                                         if e.kind == "AUDIT1123"])
        evs, _ = events("module")
        self.assertEqual([e.get("cmd") for e in evs if e.kind == "AUDIT1123"],
                         ["modprobe tcp_bbr", "modprobe -r tcp_bbr", "modprobe sctp"])
        loads = [e for e in evs if e.keys == ("kernel_modules",)]
        self.assertEqual([(e.get("exe"), text(e.first("KERN_MODULE").raw, "name"),
                           e.get("auid")) for e in loads],
                         [("/usr/bin/kmod", "tcp_bbr", "1000")] * 2)   # sctp: blocked, no load

    def test_batches_same_as_one_by_one(self):
        entries = fix("lock")
        a, b = Assembler(), Assembler()
        one = [e for x in entries for e in a.feed([x], 0.0)]
        batches = [e for i in range(0, len(entries), 7) for e in b.feed(entries[i:i + 7], 0.0)]
        ids = lambda evs: [(e.id, len(e.records)) for e in evs]
        self.assertEqual(ids(one), ids(batches))
        self.assertEqual(a.open.keys(), b.open.keys())

    def test_timeout(self):
        a = Assembler()
        self.assertEqual(a.feed([rec(1, 1334, "BPF", "BPF prog-id=1 op=LOAD")], now=10.0), [])
        self.assertEqual(a.flush(11.9), [])
        [e] = a.flush(12.0)                                  # no PROCTITLE ever
        self.assertEqual((e.kind, len(e.records)), ("BPF", 1))
        self.assertEqual(a.open, {})

    def test_split_over_feeds(self):
        a = Assembler()
        a.feed([rec(5, 1300, "SYSCALL", 'SYSCALL syscall=59 key="root_cmds"')], now=0.0)
        [e] = a.feed([rec(5, 1327, "PROCTITLE", "PROCTITLE proctitle=6964")], now=1.0)
        self.assertEqual((e.keys, e.proctitle), (("root_cmds",), "id"))

    def test_user_record_alone(self):
        [e] = Assembler().feed([rec(9, 1123, "AUDIT1123", "AUDIT1123 auid=1000 "
                                    "msg='cmd=\"id\" res=failed'")], 0.0)
        self.assertEqual((e.kind, e.get("cmd"), e.get("res"), e.keys), ("AUDIT1123", "id",
                                                                         "failed", ()))

    def test_limit_boot_and_bad(self):
        a = Assembler(limit=2)
        out = a.feed([rec(1, 1300, "SYSCALL", "SYSCALL a=1"),
                      rec(2, 1300, "SYSCALL", "SYSCALL a=2", _BOOT_ID="b1"),
                      rec(2, 1300, "SYSCALL", "SYSCALL a=3", _BOOT_ID="b2")], 0.0)
        self.assertEqual([e.id for e in out], ["1"])         # oldest open one given out
        self.assertEqual(sorted(a.open), [("b1", "2"), ("b2", "2")])   # ids are per boot
        a.feed([{"_TRANSPORT": "kernel", "MESSAGE": "x"},
                {"_TRANSPORT": "audit", "MESSAGE": "x", "_AUDIT_TYPE": "1300"},
                rec(3, 1300, "SYSCALL", "S", _AUDIT_TYPE="x")], 0.0)
        self.assertEqual(a.bad, 2)
        self.assertEqual(len(a.flush(0.0, all_=True)), 2)


if __name__ == "__main__":
    unittest.main()
