"""Small shared helpers: process, files, formatting, safety."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable, Sequence


class LcmError(RuntimeError):
    """A fatal, user-facing error.  The CLI turns this into exit code 1."""


# --------------------------------------------------------------------------
# process helpers
# --------------------------------------------------------------------------

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(
    cmd: str | Sequence[str],
    *,
    check: bool = True,
    capture: bool = True,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess:
    argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    try:
        proc = subprocess.run(
            argv,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
    except FileNotFoundError as exc:
        raise LcmError(f"missing command: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise LcmError(f"command timed out: {shlex.join(argv)}") from exc

    if check and proc.returncode != 0:
        err = (proc.stderr or "").strip()
        detail = f"\n{err}" if err else ""
        raise LcmError(
            f"command failed ({proc.returncode}): {shlex.join(argv)}{detail}"
        )
    return proc


def run_ok(cmd: str | Sequence[str], **kwargs) -> tuple[bool, str, str]:
    """Run a command without raising.  Returns (ok, stdout, stderr)."""
    try:
        proc = run(cmd, check=False, **kwargs)
        return proc.returncode == 0, (proc.stdout or ""), (proc.stderr or "")
    except LcmError as exc:
        return False, "", str(exc)


def require_root(action: str = "this operation") -> None:
    if os.geteuid() != 0:
        raise LcmError(f"{action} must run as root (try: sudo lcm ...)")


def confirm(prompt: str, *, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise LcmError(f"{prompt} -- refusing in a non-interactive shell; pass --yes")
    answer = input(f"{prompt} [y/N] ").strip().lower()
    return answer in {"y", "yes"}


# --------------------------------------------------------------------------
# filesystem helpers
# --------------------------------------------------------------------------

def atomic_write(path: str | Path, text: str, mode: int | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".lcm-tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path


def read_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | Path, data: dict, mode: int | None = None) -> Path:
    return atomic_write(path, json.dumps(data, indent=2, sort_keys=True) + "\n", mode)


def safe_join(root: Path, name: str) -> Path:
    """Join a tar member name to root, refusing traversal and absolutes."""
    if name.startswith("/") or name.startswith("\\"):
        raise LcmError(f"refusing absolute path in archive: {name}")
    parts = Path(name).parts
    if any(part == ".." for part in parts):
        raise LcmError(f"refusing path traversal in archive: {name}")
    dest = (root / name).resolve()
    base = root.resolve()
    if dest != base and base not in dest.parents:
        raise LcmError(f"refusing path escape in archive: {name}")
    return dest


def is_mountpoint(path: str | Path) -> bool:
    ok, out, _ = run_ok(["findmnt", "-n", "-o", "TARGET", "--mountpoint", str(path)])
    return ok and out.strip() != ""


def mountpoint_of(path: str | Path) -> str | None:
    ok, out, _ = run_ok(["findmnt", "-n", "-o", "TARGET", "--target", str(path)])
    if ok and out.strip():
        return out.strip().splitlines()[0]
    return None


def du_bytes(path: str | Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------
# formatting
# --------------------------------------------------------------------------

def human_duration(value: float | None) -> str:
    """Compact, readable duration: 400ms, 4.2s, 18m 42s, 1h 02m 05s."""
    if value is None:
        return "?"
    seconds = max(0.0, float(value))
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 10:
        return f"{seconds:.1f}s"
    total = int(round(seconds))
    if total < 60:
        return f"{total}s"
    minutes, sec = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {sec:02d}s"


def human_bytes(value: int | float | None) -> str:
    if value is None:
        return "?"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    number = float(value)
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024
        index += 1
    if index == 0:
        return f"{int(number)} B"
    return f"{number:.1f} {units[index]}"


_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]*)\s*$")

_SIZE_UNITS = {
    "": 1,
    "B": 1,
    "K": 1024,
    "KB": 1000,
    "KIB": 1024,
    "M": 1024**2,
    "MB": 1000**2,
    "MIB": 1024**2,
    "G": 1024**3,
    "GB": 1000**3,
    "GIB": 1024**3,
    "T": 1024**4,
    "TB": 1000**4,
    "TIB": 1024**4,
}


def parse_size(text: str) -> int:
    match = _SIZE_RE.match(text)
    if not match:
        raise LcmError(f"cannot parse size: {text!r}")
    number = float(match.group(1))
    unit = match.group(2).upper()
    if unit not in _SIZE_UNITS:
        raise LcmError(f"unknown size unit: {unit!r}")
    return int(number * _SIZE_UNITS[unit])


class Style:
    """Minimal ANSI styling that becomes a no-op when disabled."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def blue(self, text: str) -> str:
        return self._wrap("34", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


def indent(text: str, prefix: str = "  ") -> str:
    return "\n".join(prefix + line if line else line for line in text.splitlines())


def bullet(items: Iterable[str], prefix: str = "  - ") -> str:
    return "\n".join(prefix + item for item in items)
