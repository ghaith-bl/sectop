"""Run external commands for modules. Fixed argv, no shell, hard limits.

sectop v1 runs as root, so every command here runs as root.
"""

import os
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass

ENV = {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}
MAX_OUT = 1024 * 1024        # bytes per stream
MAX_TIMEOUT = 30.0
CHUNK = 65536


@dataclass(frozen=True, slots=True)
class Result:
    rc: int                  # exit code; -9 if killed; 126 refused; 127 not found
    out: str
    err: str
    timed_out: bool = False
    truncated: bool = False  # a stream hit the limit, process killed


def _check_argv(argv) -> None:
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv must be a non-empty list")
    if not all(isinstance(a, str) for a in argv):
        raise ValueError("argv items must be str")
    if not os.path.isabs(argv[0]):
        raise ValueError(f"argv[0] must be an absolute path: {argv[0]!r}")


def _unsafe(path: str) -> str | None:
    """Refuse binaries root should not run: not root-owned, or group/other writable."""
    st = os.stat(path)  # follows symlinks: checks the real file
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    if st.st_uid != 0:
        return "not owned by root"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "group/other writable"
    return None


def _kill(proc: subprocess.Popen) -> None:
    """Kill the whole process group (start_new_session=True -> pgid == pid)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run(argv, timeout: float = 1.5, limit: int = MAX_OUT) -> Result:
    _check_argv(argv)
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be in (0, {MAX_TIMEOUT}]")

    try:
        reason = _unsafe(argv[0])
    except FileNotFoundError:
        return Result(127, "", f"not found: {argv[0]}")
    if reason:
        return Result(126, "", f"refused: {argv[0]}: {reason}")

    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENV,
            cwd="/",
            close_fds=True,
            start_new_session=True,
        )
    except PermissionError as e:
        return Result(126, "", f"refused: {argv[0]}: {e.strerror}")

    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    bufs = {out_fd: bytearray(), err_fd: bytearray()}
    timed_out = truncated = False
    sel = selectors.DefaultSelector()
    try:
        for fd in bufs:
            sel.register(fd, selectors.EVENT_READ)
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            for key, _ in sel.select(left):
                data = os.read(key.fd, CHUNK)
                if not data:
                    sel.unregister(key.fd)
                    continue
                buf = bufs[key.fd]
                room = limit - len(buf)
                buf += data[:room]
                if len(data) > room:
                    truncated = True
            if truncated:
                break

        if timed_out or truncated:
            _kill(proc)
        else:
            # Pipes closed, but the process may still run.
            try:
                proc.wait(max(deadline - time.monotonic(), 0.001))
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill(proc)
        proc.wait()
    finally:
        sel.close()
        proc.stdout.close()
        proc.stderr.close()
        if proc.returncode is None:
            _kill(proc)
            proc.wait()

    return Result(
        rc=proc.returncode,
        out=bufs[out_fd].decode("utf-8", errors="replace"),
        err=bufs[err_fd].decode("utf-8", errors="replace"),
        timed_out=timed_out,
        truncated=truncated,
    )
