"""sectop home watch: sectop-home@<user>.service (step 8b2, 2026-11-23).

What: the places in the desktop user's home where a program can set itself to run again
(autostart, user units, shell start files, PATH dirs, D-Bus services, ...): every entry's
type, mode, owner, size, mtime, ctime, inode (link: its target). Names and metadata only,
never file content. Stays on the host.

Who reads: system user sectop-home, no capabilities, no network, never the desktop user.
A program running as the desktop user cannot write this report or stop this unit; it can
only take the read access away (ACL) or change a place, and both show (unreadable /
changed). The access is ACL entries the desktop user's own account sets
(silverblue-privacy-hardening homelock section, or by hand: docs/install.md); root never
reads the home here.

Why ctime: a user cannot set it (touch sets mtime only), every write, chmod, chattr and
ACL change moves it, and it needs no read access to the file. A directory's own entry
changes when something is added inside it: new files show even below the walked depth.

Report: /run/sectop-home/<user>/report.json, dir 0750 sectop-home:sectop-feed, file 0640
(core/statefile.py). Collector: posture kind home-watch compares it with the accepted list
/etc/sectop/home-known.txt (root-owned, 0640 root:sectop), written only by the admin:
sudo ./install.sh --home-accept (this file, accept()).

systemd: /usr/bin/python3 -I -B /usr/local/lib/sectop/bin/sectop-home <user>
"""

import grp
import os
import pwd
import re
import signal
import stat
import sys
import time

from core import statefile
from core.config import ConfigError, read_file
from core.module import _is_num
from core.sanitize import display

RUN_DIR = "/run/sectop-home"
FILE = "report.json"
OWNER = "sectop-home"            # the unit's User=
GROUP = "sectop-feed"            # unit Group=: helper -> collector only
KNOWN = "/etc/sectop/home-known.txt"
KNOWN_GROUP = "sectop"           # the collector reads it; the admin is a member
VERSION = 1
INTERVAL = 30.0
MAX_AGE = 180.0                  # older report: unit stopped or stuck
MAX_SIZE = 2 * 1024 * 1024
MAX_ENTRIES = 4000
MAX_PER_SPOT = 500
MAX_PATH = 512
MAX_SIG = 700
USER_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
ABSENT, UNREADABLE = "absent", "unreadable"
FIELDS = ("type", "mode", "uid", "size", "mtime", "ctime", "inode")
TYPE_WORD = {"f": "file", "d": "dir", "l": "link", "o": "other"}

# (path below the home, depth walked below it). Locked by silverblue-privacy-hardening
# (homelock: nothing new can be made there) or in use (watched only): the same here.
SPOTS = (
    # shell start files, read by bash / zsh / X sessions; git config runs hooks, pagers
    (".bashrc", 0), (".bash_profile", 0), (".bash_logout", 0), (".bash_login", 0),
    (".profile", 0), (".inputrc", 0), (".bash_completion", 0), (".pam_environment", 0),
    (".zshrc", 0), (".zshenv", 0), (".zprofile", 0), (".zlogin", 0),
    (".xprofile", 0), (".xsessionrc", 0), (".xinitrc", 0), (".gitconfig", 0),
    (".bashrc.d", 3), ("bin", 3), (".ssh", 2),
    # ~/.config: autostart, user units and manager config, environment, podman (quadlet
    # units in containers/systemd), fish, completion, git, default apps
    (".config/autostart", 3), (".config/systemd/user", 3),
    (".config/systemd/user.control", 3), (".config/systemd/user.conf", 0),
    (".config/systemd/user.conf.d", 3), (".config/environment.d", 3),
    (".config/user-tmpfiles.d", 3), (".config/containers", 3), (".config/fish", 3),
    (".config/bash_completion", 0), (".config/git", 3), (".config/mimeapps.list", 0),
    # ~/.local: PATH, python user site (.pth files run at start), user units, D-Bus
    # activation, GNOME Shell extensions, Files scripts, completions, desktop files, flatpak
    (".local/bin", 3), (".local/lib", 2), (".local/share/systemd/user", 3),
    (".local/share/dbus-1/services", 3), (".local/share/gnome-shell/extensions", 3),
    (".local/share/nautilus/scripts", 3), (".local/share/bash-completion", 3),
    (".local/share/applications", 3), (".local/share/mime", 1),
    (".local/share/flatpak/exports", 3), (".local/share/flatpak/overrides", 3),
)


class Quit(BaseException):
    """Raised by the SIGTERM handler."""


def esc(name: str) -> str:
    """A file name -> printable ASCII, one field: bytes 0x20..0x7e stay (not the
    backslash), every other byte -> \\xHH (tab, newline, UTF-8 of non-ASCII names)."""
    return "".join(chr(b) if 0x20 <= b <= 0x7e and b != 0x5c else f"\\x{b:02x}"
                   for b in os.fsencode(name))


def _type(mode: int) -> str:
    return ("l" if stat.S_ISLNK(mode) else "d" if stat.S_ISDIR(mode)
            else "f" if stat.S_ISREG(mode) else "o")


def sig(st, target: str | None = None) -> str:
    """One entry: type mode uid size mtime_ns ctime_ns inode [-> target]."""
    s = (f"{_type(st.st_mode)} {stat.S_IMODE(st.st_mode):o} {st.st_uid} {st.st_size} "
         f"{st.st_mtime_ns} {st.st_ctime_ns} {st.st_ino}")
    return s if target is None else f"{s} -> {target}"[:MAX_SIG]


def _walk(base: str, rel: str, depth: int, out: list, room: int) -> None:
    """rel's entry, then (directory) its entries, sorted, depth levels down."""
    if len(out) >= room:
        return
    path = os.path.join(base, rel)
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        out.append((esc(rel), ABSENT))
        return
    except OSError:
        out.append((esc(rel), UNREADABLE))
        return
    target = None
    if stat.S_ISLNK(st.st_mode):
        try:
            target = esc(os.readlink(path))
        except OSError:
            target = "?"
    out.append((esc(rel), sig(st, target)))
    if depth <= 0 or not stat.S_ISDIR(st.st_mode):
        return
    try:
        names = sorted(os.listdir(path))
    except OSError:
        out.append((esc(rel) + "/*", UNREADABLE))
        return
    for name in names:
        _walk(base, f"{rel}/{name}", depth - 1, out, room)


def scan(home: str, spots=SPOTS) -> list:
    """[(path below home, sig)] of every spot, at most MAX_PER_SPOT per spot."""
    out = []
    for rel, depth in spots:
        part = []
        _walk(home, rel, depth, part, MAX_PER_SPOT)
        if len(part) >= MAX_PER_SPOT:
            part.append((esc(rel) + "/...", f"more than {MAX_PER_SPOT} entries"))
        out += part
        if len(out) >= MAX_ENTRIES:
            return out[:MAX_ENTRIES]
    return out


def doc(user: str, uid: int, home: str, ts: float, entries: list) -> dict:
    return {"v": VERSION, "user": user, "uid": uid, "home": home, "ts": ts,
            "entries": [[p, s] for p, s in entries]}


def _log(msg: str) -> None:
    print(f"sectop-home: {display(msg)}", file=sys.stderr, flush=True)


def prepare(path: str, uid: int, gid: int) -> None:
    """The runtime dir systemd made (RuntimeDirectory=, User= / Group=): mine, group
    sectop-feed, 0750. OSError / ValueError."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
        raise ValueError(f"{path}: not a directory owned by uid {uid}")
    if st.st_gid != gid:
        raise ValueError(f"{path}: group {st.st_gid}, not {GROUP} ({gid}): check Group=")
    os.chmod(path, 0o750, follow_symlinks=False)


def loop(user: str, uid: int, home: str, path: str, write=statefile.write, wall=time.time,
         sleep=time.sleep, log=_log, stop=lambda: False, scan=scan) -> None:
    problem = None
    while not stop():
        try:
            write(path, doc(user, uid, home, wall(), scan(home)), 0o640)
            err = None
        except (OSError, statefile.StateError) as e:
            err = f"{path}: {type(e).__name__}: {e}"
        if err != problem:
            log(err or "writing again")
            problem = err
        sleep(INTERVAL)


def _term(signum, frame):
    raise Quit


def watched(name: str, getpw=pwd.getpwnam) -> tuple:
    """The desktop user -> (uid, home). ValueError."""
    if not USER_RE.fullmatch(name) or name == "root":
        raise ValueError(f"user name {name!r} not supported")
    try:
        pw = getpw(name)
    except KeyError:
        raise ValueError(f"no user {name}") from None
    if pw.pw_uid < 1000:
        raise ValueError(f"{name}: system user (uid {pw.pw_uid})")
    home = pw.pw_dir
    if not home.startswith("/") or home == "/" or ".." in home.split("/"):
        raise ValueError(f"{name}: home {home!r} not an absolute path")
    return pw.pw_uid, home


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--accept"]:
        return accept()
    if len(argv) != 1 or argv[0].startswith("-"):
        print("usage: sectop-home USER   (run by sectop-home@USER.service)\n"
              "       sectop-home --accept  (root: install.sh --home-accept)", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        _log("refusing to run as root: runs as user sectop-home (sectop-home@<user>.service)")
        return 2
    try:
        me = pwd.getpwuid(os.getuid()).pw_name
        gid = grp.getgrnam(GROUP).gr_gid
        uid, home = watched(argv[0])
    except (KeyError, ValueError) as e:
        _log(str(e))
        return 2
    if me != OWNER or gid != os.getgid():
        _log(f"runs as {OWNER}:{GROUP} (User= / Group= of sectop-home@.service)")
        return 2
    d = os.path.join(RUN_DIR, argv[0])
    try:
        prepare(d, os.getuid(), gid)
    except (OSError, ValueError) as e:
        _log(f"{d}: {e} (RuntimeDirectory=sectop-home/%i in the unit)")
        return 2
    signal.signal(signal.SIGTERM, _term)
    try:
        loop(argv[0], uid, home, os.path.join(d, FILE))
    except (KeyboardInterrupt, Quit):
        pass
    return 0


# --- reader side (collector posture, accept) ------------------------------------------

def check(d, user: str) -> tuple:
    """report.json -> ({path: sig}, ts, home). Wrong -> ValueError."""
    if not isinstance(d, dict) or type(d.get("v")) is not int or d["v"] != VERSION:
        raise ValueError(f"v: {VERSION} required")
    if d.get("user") != user:
        raise ValueError(f"user: not {user}")
    ts, home, entries = d.get("ts"), d.get("home"), d.get("entries")
    if not _is_num(ts) or ts < 0:
        raise ValueError("ts: epoch seconds required")
    if not isinstance(home, str) or not home.startswith("/") or len(home) > MAX_PATH:
        raise ValueError("home: absolute path required")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES + len(SPOTS):
        raise ValueError(f"entries: list of max {MAX_ENTRIES} required")
    out = {}
    for i, e in enumerate(entries):
        if (not isinstance(e, list) or len(e) != 2 or not all(isinstance(x, str) for x in e)
                or not e[0] or len(e[0]) > MAX_PATH or len(e[1]) > MAX_SIG
                or not (e[0] + e[1]).isascii() or not (e[0] + e[1]).isprintable()
                or "\t" in e[0] + e[1]):
            raise ValueError(f"entries[{i}]: [path, sig] printable ASCII required")
        out[e[0]] = e[1]
    return out, float(ts), home


def owner_uid(getpw=pwd.getpwnam) -> int:
    try:
        return getpw(OWNER).pw_uid
    except KeyError:
        raise ValueError(f"no user {OWNER} (sectop install.sh makes it)") from None


def load_report(user: str, base: str = RUN_DIR, wall=time.time, getpw=pwd.getpwnam) -> tuple:
    """-> ({path: sig}, home). Missing, unsafe, wrong or old -> ValueError."""
    if not USER_RE.fullmatch(user):
        raise ValueError(f"user name {user!r} not supported")
    path = os.path.join(base, user, FILE)
    try:
        d = statefile.load(path, owner_uid(getpw), MAX_SIZE)
    except statefile.StateError as e:
        raise ValueError(str(e)) from None
    if d is None:
        raise ValueError(f"{path}: no report (sectop-home@{user}.service running?)")
    entries, ts, home = check(d, user)
    age = wall() - ts
    if age > MAX_AGE:
        raise ValueError(f"report {int(age)} s old (sectop-home@{user}.service stuck?)")
    return entries, home


def parse_known(text: str) -> tuple:
    """home-known.txt -> (user, {path: sig}). Lines: `user<TAB>name`,
    `entry<TAB>path<TAB>sig`, # comments. ValueError."""
    user, known = None, {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split("\t")
        if f[0] == "user" and len(f) == 2 and USER_RE.fullmatch(f[1]):
            user = f[1]
        elif f[0] == "entry" and len(f) == 3 and f[1]:
            known[f[1]] = f[2]
        else:
            raise ValueError(f"line {n}: not understood")
    if user is None:
        raise ValueError("no user line")
    return user, known


def render_known(user: str, entries: dict, when: str) -> str:
    lines = ["# sectop home watch: accepted state of the places a program can set itself to",
             f"# run again from, in {user}'s home (posture home-watch). {when}",
             "# Written by: sudo ./install.sh --home-accept (admin). Fields: type mode uid size",
             "# mtime_ns ctime_ns inode [-> link target]; absent / unreadable.",
             f"user\t{user}"]
    lines += [f"entry\t{p}\t{s}" for p, s in sorted(entries.items())]
    return "\n".join(lines) + "\n"


def _word(s: str) -> str:
    return s if " " not in s else TYPE_WORD.get(s.split(" ", 1)[0], "other")


def what_changed(old: str, new: str) -> str:
    """Which fields differ, in words (no numbers: inode / time values say nothing)."""
    if " " not in old or " " not in new or old[0] != new[0]:
        return f"{_word(old)} -> {_word(new)}"
    a, b = old.split(" -> ", 1), new.split(" -> ", 1)
    fa, fb = a[0].split(), b[0].split()
    diff = [FIELDS[i] for i in range(min(len(fa), len(fb), len(FIELDS))) if fa[i] != fb[i]]
    if len(a) != len(b) or (len(a) == 2 and a[1] != b[1]):
        diff.append("link target")
    if "mode" in diff:
        diff[diff.index("mode")] = f"mode {fa[1]} -> {fb[1]}"
    return ", ".join(diff) or "same"


def diff(known: dict, now: dict) -> list:
    """-> [(kind, path, detail)], kind: new | gone | changed. 'absent' counts as not
    there: an absent spot that appears is new."""
    out = []
    for p in sorted(set(known) | set(now)):
        old, new = known.get(p, ABSENT), now.get(p, ABSENT)
        if old == new:
            continue
        if old == ABSENT:
            out.append(("new", p, _word(new)))
        elif new == ABSENT:
            out.append(("gone", p, ""))
        else:
            out.append(("changed", p, what_changed(old, new)))
    return out


def line(kind: str, path: str, detail: str) -> str:
    return display(f"{kind:7} ~/{path}" + (f"  ({detail})" if detail else ""))


# --- accept (root, install.sh --home-accept) --------------------------------------------

def _known_now(path: str) -> tuple:
    data = read_file(path, 0, MAX_SIZE)       # root-owned, not group / other writable
    if data is None:
        return None, {}
    return parse_known(data.decode("ascii", errors="replace"))


def _users(base: str) -> list:
    try:
        return sorted(n for n in os.listdir(base) if USER_RE.fullmatch(n))
    except OSError:
        return []


def accept(base: str = RUN_DIR, known_path: str = KNOWN, tty: str = "/dev/tty",
           wall=time.time, getpw=pwd.getpwnam, getgr=grp.getgrnam) -> int:
    """Show what differs from the accepted list, y = the list is the report now."""
    if os.geteuid() != 0:
        print("sectop-home --accept: run as root (sudo ./install.sh --home-accept)",
              file=sys.stderr)
        return 2
    users = _users(base)
    if len(users) != 1:
        print(f"sectop-home --accept: {len(users)} reports in {base} (one desktop user "
              "expected: sectop-home@<user>.service)", file=sys.stderr)
        return 1
    user = users[0]
    try:
        now, home = load_report(user, base, wall, getpw)
        kuser, known = _known_now(known_path)
    except (ValueError, ConfigError) as e:
        print(f"sectop-home --accept: {display(str(e))}", file=sys.stderr)
        return 1
    if kuser not in (None, user):
        print(f"accepted list is for {kuser}, report for {user}: the whole list is new")
        known = {}
    changes = diff(known, now)
    if kuser is not None and not changes:
        print(f"home watch: nothing new ({len(now)} entries in {home} as accepted)")
        return 0
    first = kuser is None
    print(f"home watch, {home}: " + ("first list" if first else f"{len(changes)} difference(s)"))
    for kind, path, detail in (diff({}, now) if first else changes):
        print("  " + line(kind, path, detail))
    try:
        with open(tty) as t:
            print(f"accept: the list = these {len(now)} entries? [y/N] ", end="", flush=True)
            ans = t.readline().strip()
    except OSError:
        ans = "n"
    if ans not in ("y", "Y"):
        print("home watch list: not changed")
        return 0
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(wall()))
    text = render_known(user, now, when).encode("ascii")
    try:
        gid = getgr(KNOWN_GROUP).gr_gid
    except KeyError:
        gid = 0
    d = os.path.dirname(known_path)
    tmp = os.path.join(d, ".home-known.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o640)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, 0o640)
        view = memoryview(text)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, known_path)
    print(f"home watch list: {known_path} written ({len(now)} entries; sectop reads it at "
          "the next posture collect, every 5 min)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
