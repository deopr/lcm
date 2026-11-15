"""`.lcmb` bundles: a portable, verifiable snapshot of state.

A bundle is a gzipped tar containing a profile, resolved package metadata,
hardware notes and two payload tars (home config and /etc allowlist).  It
contains no executable code and extraction refuses traversal, devices and
fifos.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shutil
import stat as stat_mod
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from lcm import __version__
from lcm.profile import Profile
from lcm.util import (
    LcmError,
    human_bytes,
    run_ok,
    safe_join,
    timestamp,
    utc_now,
)

BUNDLE_FORMAT = 1
MANIFEST = "manifest.json"
PROFILE = "profile.yaml"
PACKAGES = "packages.json"
CHECKSUMS = "checksums.sha256"

@dataclass(frozen=True)
class ProgressEvent:
    """One progress sample from a bundle-building phase.

    ``done`` and ``total`` are bytes.  For compression, ``done`` counts input
    bytes read and ``output`` is the compressed file size so far.
    """

    phase: str
    label: str
    done: int
    total: int | None = None
    files: int = 0
    total_files: int | None = None
    elapsed: float = 0.0
    detail: str | None = None
    output: int | None = None
    finished: bool = False


ProgressCallback = Callable[[ProgressEvent], None]
CaptureReporter = Callable[[int, int, str | None], None]

# Cache names that are unambiguous at any depth.  Generic names such as
# "cache" or "Cache" are deliberately absent: a project directory often uses
# those names, and skipping it would silently drop real data.
BUILTIN_EXCLUDES = {
    ".cache",
    ".lcm-backup",
    ".lcm-staging-*",
    "CachedData",
    "GPUCache",
    "Code Cache",
    "CacheStorage",
    "ShaderCache",
    "GrShaderCache",
    "DawnCache",
    "Crashpad",
    "blob_storage",
    "SingletonLock",
    "SingletonCookie",
    "SingletonSocket",
    # Browser and editor caches use a generic "Cache" directory, but only
    # inside their own configuration trees.
    ".config/*/Cache",
    ".config/*/CachedData",
    ".config/*/*/Cache",
    ".config/*/*/CachedData",
    ".local/share/*/Cache",
    ".mozilla/firefox/*/cache2",
    ".mozilla/firefox/*/startupCache",
    ".thunderbird/*/cache2",
}


@dataclass
class Bundle:
    root: Path
    manifest: dict
    profile: Profile
    packages: dict
    temporary: bool = True

    @property
    def user(self) -> str | None:
        return self.manifest.get("user")

    def payload_home(self, user: str | None = None) -> Path | None:
        name = user or self.user
        if not name:
            return None
        path = self.root / "payload" / f"home-{name}.tar"
        return path if path.exists() else None

    @property
    def payload_etc(self) -> Path | None:
        path = self.root / "payload" / "etc.tar"
        return path if path.exists() else None

    def cleanup(self) -> None:
        if self.temporary:
            shutil.rmtree(self.root, ignore_errors=True)


# --------------------------------------------------------------------------
# creation
# --------------------------------------------------------------------------

def _sha256(
    path: Path, on_progress: Callable[[int], None] | None = None
) -> str:
    digest = hashlib.sha256()
    read = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            read += len(chunk)
            if on_progress is not None:
                on_progress(read)
    return digest.hexdigest()


def _excluded(relative: str, patterns: list[str]) -> bool:
    """Match a path and each of its components against the patterns.

    Single-component patterns such as `Cache` apply at any depth, while
    multi-component patterns such as `.local/share/Steam` must match a path
    prefix so the directory and all of its descendants are pruned.
    """
    parts = Path(relative).parts
    for pattern in patterns:
        prefix = ""
        for part in parts:
            prefix = f"{prefix}/{part}" if prefix else part
            if fnmatch.fnmatch(part, pattern) or fnmatch.fnmatch(prefix, pattern):
                return True
    return False


def _make_filter(patterns: list[str]):
    seen: set[str] = set()

    def _filter(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
        if member.isdev() or member.isfifo():
            return None
        if member.name in seen or _excluded(member.name, patterns):
            return None
        seen.add(member.name)
        return member

    return _filter


@dataclass
class _CaptureStats:
    files: int = 0
    bytes: int = 0


class _CountingReader:
    """File wrapper that reports how much tarfile has read.

    tarfile reads in small blocks.  Reporting every block would create
    millions of events on a large payload, so samples are limited to one per
    ``interval`` bytes.  The caller still emits an exact final sample when the
    member is complete.
    """

    def __init__(
        self,
        handle,
        on_read: Callable[[int], None] | None = None,
        interval: int = 4 * 1024 * 1024,
    ) -> None:
        self.handle = handle
        self.on_read = on_read
        self.interval = interval
        self.count = 0
        self.reported = 0

    def read(self, size: int = -1) -> bytes:
        data = self.handle.read(size)
        self.count += len(data)
        if (
            self.on_read is not None
            and self.count - self.reported >= self.interval
        ):
            self.reported = self.count
            self.on_read(self.count)
        return data

    def __getattr__(self, name):
        return getattr(self.handle, name)


def _add_member(
    archive: tarfile.TarFile,
    path: Path,
    arcname: str,
    member_filter,
    on_read: Callable[[int], None] | None = None,
) -> tarfile.TarInfo | None:
    try:
        info = archive.gettarinfo(str(path), arcname)
    except OSError:
        return None
    if info is None:
        return None
    if member_filter is not None and member_filter(info) is None:
        return None
    if info.isreg():
        try:
            handle = open(path, "rb")
        except OSError:
            # Unreadable file (for example a root-only secret while exporting
            # unprivileged): skip it instead of aborting the whole bundle.
            return None
        try:
            source = (
                _CountingReader(handle, on_read)
                if on_read is not None
                else handle
            )
            archive.addfile(info, source)
        finally:
            handle.close()
    else:
        archive.addfile(info)
    return info


def _walk_into(
    archive: tarfile.TarFile,
    path: Path,
    arcname: str,
    member_filter,
    stats: _CaptureStats,
    report: CaptureReporter | None,
) -> None:
    def on_read(read: int) -> None:
        if report is not None:
            report(stats.bytes + read, stats.files, arcname)

    info = _add_member(
        archive,
        path,
        arcname,
        member_filter,
        on_read=on_read if report is not None else None,
    )
    if info is None:
        return
    stats.files += 1
    if info.isreg():
        stats.bytes += max(info.size, 0)
    if report is not None:
        report(stats.bytes, stats.files, arcname)
    if path.is_symlink() or not path.is_dir():
        return
    try:
        children = sorted(path.iterdir())
    except OSError:
        return
    for child in children:
        _walk_into(
            archive,
            child,
            f"{arcname}/{child.name}",
            member_filter,
            stats,
            report,
        )


def _measure_tree(
    source_root: Path,
    patterns: list[str],
    excludes: list[str],
) -> _CaptureStats:
    """Count what `_tar_tree` will add, so capture can show an ETA.

    This only stats paths; it does not read file contents.  It mirrors the
    traversal and exclusion rules in `_tar_tree`, including the duplicate
    suppression used when allowlist entries overlap.
    """
    blocked = excludes + sorted(BUILTIN_EXCLUDES)
    seen: set[str] = set()
    stats = _CaptureStats()

    def visit(path: Path, arcname: str) -> None:
        if arcname in seen or _excluded(arcname, blocked):
            return
        try:
            st = path.lstat()
        except OSError:
            return
        if (
            stat_mod.S_ISCHR(st.st_mode)
            or stat_mod.S_ISBLK(st.st_mode)
            or stat_mod.S_ISFIFO(st.st_mode)
            or stat_mod.S_ISSOCK(st.st_mode)
        ):
            return
        seen.add(arcname)
        stats.files += 1
        if stat_mod.S_ISREG(st.st_mode):
            stats.bytes += max(st.st_size, 0)
        if not stat_mod.S_ISDIR(st.st_mode):
            return
        try:
            children = sorted(path.iterdir())
        except OSError:
            return
        for child in children:
            visit(child, f"{arcname}/{child.name}")

    for pattern in patterns:
        candidate = source_root / pattern
        if not candidate.exists():
            continue
        if not candidate.is_symlink() and candidate.is_dir():
            try:
                children = sorted(candidate.iterdir())
            except OSError:
                continue
            for child in children:
                visit(child, str(Path(pattern) / child.name))
        else:
            visit(candidate, pattern)
    return stats


def _tar_tree(
    source_root: Path,
    patterns: list[str],
    excludes: list[str],
    out: Path,
    *,
    label: str | None = None,
    progress: ProgressCallback | None = None,
) -> _CaptureStats:
    out.parent.mkdir(parents=True, exist_ok=True)
    phase_label = label or out.stem
    started = time.monotonic()
    measured = _measure_tree(source_root, patterns, excludes)

    def emit(
        done: int,
        files: int,
        detail: str | None = None,
        *,
        finished: bool = False,
    ) -> None:
        if progress is not None:
            progress(
                ProgressEvent(
                    phase="capture",
                    label=phase_label,
                    done=done,
                    total=measured.bytes,
                    files=files,
                    total_files=measured.files,
                    elapsed=time.monotonic() - started,
                    detail=detail,
                    finished=finished,
                )
            )

    emit(0, 0)
    member_filter = _make_filter(excludes + sorted(BUILTIN_EXCLUDES))
    stats = _CaptureStats()
    with tarfile.open(out, "w") as archive:
        for pattern in patterns:
            candidate = source_root / pattern
            if not candidate.exists():
                continue
            if not candidate.is_symlink() and candidate.is_dir():
                try:
                    children = sorted(candidate.iterdir())
                except OSError:
                    continue
                for child in children:
                    _walk_into(
                        archive,
                        child,
                        str(Path(pattern) / child.name),
                        member_filter,
                        stats,
                        emit,
                    )
            else:
                _walk_into(
                    archive,
                    candidate,
                    pattern,
                    member_filter,
                    stats,
                    emit,
                )
    emit(stats.bytes, stats.files, finished=True)
    return stats


def _checksums(
    root: Path, progress: ProgressCallback | None = None
) -> str:
    paths = [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != CHECKSUMS
    ]
    total = sum(path.stat().st_size for path in paths)
    started = time.monotonic()

    def emit(
        done: int,
        files: int,
        detail: str | None = None,
        *,
        finished: bool = False,
    ) -> None:
        if progress is not None:
            progress(
                ProgressEvent(
                    phase="checksums",
                    label="payload",
                    done=done,
                    total=total,
                    files=files,
                    total_files=len(paths),
                    elapsed=time.monotonic() - started,
                    detail=detail,
                    finished=finished,
                )
            )

    emit(0, 0)
    lines = []
    done = 0
    for index, path in enumerate(paths, 1):
        relative = path.relative_to(root).as_posix()
        base = done

        def on_read(
            read: int,
            base: int = base,
            relative: str = relative,
            index: int = index,
        ) -> None:
            emit(base + read, index - 1, relative)

        digest = _sha256(path, on_progress=on_read)
        done += path.stat().st_size
        lines.append(f"{digest}  {relative}")
        emit(done, index, relative)
    emit(done, len(paths), finished=True)
    return "\n".join(lines) + "\n"


def _skip_patterns(root: Path, paths: set[Path]) -> list[str]:
    """Exclude our own staging/output paths when they sit inside a capture root."""
    root_abs = Path(os.path.abspath(root))
    patterns: list[str] = []
    for path in paths:
        try:
            relative = Path(os.path.abspath(path)).relative_to(root_abs)
        except ValueError:
            continue
        if relative.parts:
            patterns.append(relative.as_posix())
    return patterns


def _add_staged_member(
    archive: tarfile.TarFile,
    path: Path,
    arcname: str,
    on_read: Callable[[int], None] | None = None,
) -> tarfile.TarInfo | None:
    info = archive.gettarinfo(str(path), arcname)
    if info is None:
        return None
    if info.isreg():
        with open(path, "rb") as handle:
            source = (
                _CountingReader(handle, on_read)
                if on_read is not None
                else handle
            )
            archive.addfile(info, source)
    else:
        archive.addfile(info)
    return info


def _compress_staging(
    staging: Path,
    partial: Path,
    *,
    progress: ProgressCallback | None = None,
) -> None:
    """Write the outer gzipped tar and report input bytes and output size."""
    paths = sorted(staging.rglob("*"))
    files = [path for path in paths if path.is_file()]
    total = sum(path.stat().st_size for path in files)
    total_files = len(files)
    started = time.monotonic()

    def emit(
        done: int,
        count: int,
        detail: str | None = None,
        *,
        finished: bool = False,
    ) -> None:
        if progress is None:
            return
        try:
            output = partial.stat().st_size
        except OSError:
            output = None
        progress(
            ProgressEvent(
                phase="compress",
                label="bundle",
                done=done,
                total=total,
                files=count,
                total_files=total_files,
                elapsed=time.monotonic() - started,
                detail=detail,
                output=output,
                finished=finished,
            )
        )

    emit(0, 0)
    done = 0
    count = 0
    with tarfile.open(partial, "w:gz", compresslevel=6) as archive:
        for path in paths:
            arcname = path.relative_to(staging).as_posix()
            info = archive.gettarinfo(str(path), arcname)
            if info is None:
                continue
            if info.isreg():
                base = done

                def on_read(
                    read: int,
                    base: int = base,
                    arcname: str = arcname,
                    count: int = count,
                ) -> None:
                    emit(base + read, count, arcname)

                _add_staged_member(archive, path, arcname, on_read)
                done += info.size
                count += 1
                emit(done, count, arcname)
            else:
                archive.addfile(info)
    emit(done, count, finished=True)


def create(
    out_path: str | Path,
    profile: Profile,
    packages: dict,
    system,
    *,
    include_payload: bool = True,
    staging_dir: str | Path | None = None,
    progress: ProgressCallback | None = None,
) -> Path:
    """Build a `.lcmb` from a profile and captured state.

    Payload tars are staged next to the output by default, so a large export
    goes to the disk or NAS the user chose instead of a small `/tmp` tmpfs.
    `staging_dir` moves only the scratch space, not the final bundle.
    """
    out_path = Path(out_path).expanduser()
    if out_path.suffix.lower() != ".lcmb":
        out_path = out_path.with_name(out_path.name + ".lcmb")
    out_path = Path(os.path.abspath(out_path))
    staging_parent = (
        Path(os.path.abspath(Path(staging_dir).expanduser()))
        if staging_dir
        else out_path.parent
    )
    partial = out_path.with_name(out_path.name + ".partial")
    staging: Path | None = None

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        staging_parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=".lcm-staging-", dir=staging_parent)
        )
        (staging / "payload").mkdir(parents=True, exist_ok=True)
        (staging / "hardware").mkdir(parents=True, exist_ok=True)

        (staging / PROFILE).write_text(profile.to_yaml(), encoding="utf-8")

        for name, command in (
            ("lspci.txt", ["lspci", "-nn"]),
            ("lsusb.txt", ["lsusb"]),
            ("lsblk.txt", ["lsblk", "-f"]),
        ):
            ok, text, _ = run_ok(command)
            if ok and text:
                (staging / "hardware" / name).write_text(text, encoding="utf-8")

        manifest = {
            "format": BUNDLE_FORMAT,
            "tool": f"lcm {__version__}",
            "created": utc_now(),
            "hostname": os.uname().nodename,
            "kernel": system.hardware.kernel,
            "source": profile.source,
            "target": profile.target,
            "user": profile.users[0].name if profile.users else None,
            "fidelity": packages.get("capture", {}).get("fidelity", "unknown"),
            "counts": {
                "native": len(profile.packages.native),
                "raw": len(profile.packages.raw),
                "flatpak": len(profile.packages.flatpak),
                "etc": len(profile.config.etc),
                "home": len(profile.config.home),
            },
            "hardware": {
                "cpu": system.hardware.cpu,
                "gpus": system.hardware.gpus,
                "gpu_vendors": system.hardware.gpu_vendors,
                "wifi": system.hardware.wifi,
                "out_of_tree_modules": system.hardware.out_of_tree_modules,
            },
        }
        (staging / PACKAGES).write_text(
            json.dumps(packages, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        payload_info: dict[str, dict] = {}
        if include_payload:
            home = Path(profile.users[0].home) if profile.users and profile.users[0].home else Path.home()
            etc = Path("/etc")
            own_paths = {out_path, partial, staging}
            for user in profile.users:
                user_home = Path(user.home) if user.home else home
                tar_path = staging / "payload" / f"home-{user.name}.tar"
                stats = _tar_tree(
                    user_home,
                    profile.config.home,
                    [
                        *profile.config.never,
                        *_skip_patterns(user_home, own_paths),
                    ],
                    tar_path,
                    label=f"home:{user.name}",
                    progress=progress,
                )
                payload_info[f"home:{user.name}"] = {
                    "files": stats.files,
                    "bytes": stats.bytes,
                }
            stats = _tar_tree(
                etc,
                profile.config.etc,
                _skip_patterns(etc, own_paths),
                staging / "payload" / "etc.tar",
                label="etc",
                progress=progress,
            )
            payload_info["etc"] = {"files": stats.files, "bytes": stats.bytes}

        manifest["payload"] = payload_info
        manifest["staging_bytes"] = sum(
            path.stat().st_size for path in staging.rglob("*") if path.is_file()
        )
        (staging / MANIFEST).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        (staging / CHECKSUMS).write_text(
            _checksums(staging, progress=progress), encoding="utf-8"
        )

        _compress_staging(staging, partial, progress=progress)
        os.replace(partial, out_path)
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        return out_path
    except OSError as exc:
        raise LcmError(
            f"could not create bundle at {out_path}: {exc}\n"
            f"staging directory: {staging or staging_parent}\n"
            "check free space and write permissions"
        ) from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        try:
            partial.unlink()
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

def _safe_extract(archive: tarfile.TarFile, destination: Path, members=None) -> None:
    selected = members if members is not None else archive.getmembers()
    destination.mkdir(parents=True, exist_ok=True)
    for member in selected:
        # The bundle's own layout contains only regular files and directories.
        # Reject links outright: a link followed by a file with the same prefix
        # is the classic tar escape, and no legitimate bundle needs one here.
        if not (member.isdir() or member.isreg()):
            raise LcmError(f"refusing special file in bundle: {member.name}")
        safe_join(destination, member.name)
    for member in selected:
        target = safe_join(destination, member.name)
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            target.unlink()
        try:
            archive.extract(member, destination, set_attrs=True, filter="data")
        except TypeError:  # Python < 3.12
            archive.extract(member, destination, set_attrs=True)


def _open_bundle(path: Path) -> tarfile.TarFile:
    try:
        return tarfile.open(path, "r:*")
    except (OSError, tarfile.TarError) as exc:
        raise LcmError(f"cannot open bundle: {path}: {exc}") from exc


def _verify_extracted(root: Path) -> list[str]:
    """Check a freshly unpacked bundle against its checksum file."""
    try:
        text = (root / CHECKSUMS).read_text(encoding="utf-8")
    except OSError:
        return ["bundle has no checksums.sha256"]

    problems: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, _, relative = line.partition("  ")
        if not relative:
            problems.append(f"malformed checksum line: {line!r}")
            continue
        try:
            path = safe_join(root, relative)
        except LcmError as exc:
            problems.append(f"unsafe checksum path: {relative}: {exc}")
            continue
        if not path.is_file():
            problems.append(f"missing file: {relative}")
            continue
        if _sha256(path) != digest:
            problems.append(f"checksum mismatch: {relative}")
    return problems


def verify(path: str | Path) -> list[str]:
    """Verify checksums by streaming members out of the archive.

    Nothing is written to disk, so this works for bundles with huge payloads.
    """
    path = Path(path)
    problems: list[str] = []
    with _open_bundle(path) as archive:
        members = {
            member.name: member for member in archive.getmembers() if member.isfile()
        }
        if CHECKSUMS not in members:
            return ["bundle has no checksums.sha256"]
        handle = archive.extractfile(members[CHECKSUMS])
        if handle is None:
            return ["cannot read checksums.sha256"]
        text = handle.read().decode("utf-8", "replace")

        for line in text.splitlines():
            if not line.strip():
                continue
            digest, _, relative = line.partition("  ")
            if not relative:
                problems.append(f"malformed checksum line: {line!r}")
                continue
            member = members.get(relative)
            if member is None:
                problems.append(f"missing file: {relative}")
                continue
            stream = archive.extractfile(member)
            if stream is None:
                problems.append(f"cannot read: {relative}")
                continue
            hasher = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
            if hasher.hexdigest() != digest:
                problems.append(f"checksum mismatch: {relative}")
    return problems


def _peek_manifest(path: Path) -> dict | None:
    """Read manifest.json without decompressing the payload.

    Streaming mode stops as soon as the payload directory is reached, so this
    costs a few megabytes even for a bundle that is tens of gigabytes.
    """
    try:
        with tarfile.open(path, "r|*") as archive:
            for member in archive:
                if member.name == MANIFEST and member.isfile():
                    handle = archive.extractfile(member)
                    if handle is None:
                        return None
                    return json.loads(handle.read().decode("utf-8"))
                if member.name.startswith("payload/"):
                    return None
    except (OSError, tarfile.TarError, ValueError):
        return None
    return None


def _workspace_need(path: Path, manifest: dict | None) -> int:
    """Estimate the disk space needed to unpack a bundle.

    New bundles record the exact staged size.  Older bundles fall back to
    twice the compressed size, which is conservative for home directories
    containing a mix of text and media.
    """
    if isinstance(manifest, dict):
        staged = manifest.get("staging_bytes")
        if isinstance(staged, int) and staged > 0:
            return staged + 128 * 1024 * 1024
        payload = manifest.get("payload")
        if isinstance(payload, dict):
            total = sum(
                int(item.get("bytes", 0))
                for item in payload.values()
                if isinstance(item, dict)
            )
            if total > 0:
                return total + 128 * 1024 * 1024
    try:
        compressed = path.stat().st_size
    except OSError:
        compressed = 0
    return max(compressed * 2, 64 * 1024 * 1024)


def _workspace_candidates(
    path: Path, work_dir: str | Path | None
) -> list[Path]:
    if work_dir is not None:
        return [Path(os.path.abspath(Path(work_dir).expanduser()))]
    candidates: list[Path] = []
    tmpdir = os.environ.get("TMPDIR")
    for item in (tmpdir, "/var/tmp", str(path.parent), "/tmp"):
        if not item:
            continue
        candidate = Path(os.path.abspath(os.path.expanduser(item)))
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _choose_workspace(
    path: Path, work_dir: str | Path | None, need: int
) -> Path:
    """Pick a disk-backed workspace before unpacking a large bundle.

    The system /tmp is commonly a RAM-backed tmpfs.  Defaulting to it can
    exhaust memory or fail halfway through a full-home restore, so candidates
    are checked for free space and /var/tmp or the bundle's own filesystem are
    preferred over /tmp.
    """
    explicit = work_dir is not None
    checked: list[str] = []
    for candidate in _workspace_candidates(path, work_dir):
        try:
            if not candidate.exists():
                if explicit:
                    candidate.mkdir(parents=True, exist_ok=True)
                else:
                    checked.append(f"{candidate}: missing")
                    continue
            if not candidate.is_dir():
                checked.append(f"{candidate}: not a directory")
                continue
            if not os.access(candidate, os.W_OK):
                checked.append(f"{candidate}: not writable")
                continue
            free = shutil.disk_usage(candidate).free
        except OSError as exc:
            checked.append(f"{candidate}: {exc}")
            continue
        checked.append(f"{candidate}: {human_bytes(free)} free")
        if free >= need:
            return candidate

    detail = "\n".join(f"  - {line}" for line in checked) or "  - no candidates"
    raise LcmError(
        "not enough space to unpack this bundle\n"
        f"  needed: {human_bytes(need)}\n"
        f"  checked:\n{detail}\n"
        "Choose a workspace with enough free space:\n"
        "  lcm restore <bundle> --work-dir /path/with/space\n"
        "or set TMPDIR to such a directory before running the command."
    )


def load(
    path: str | Path,
    *,
    verify_checksums: bool = True,
    work_dir: str | Path | None = None,
) -> Bundle:
    path = Path(path)
    manifest_hint = _peek_manifest(path)
    need = _workspace_need(path, manifest_hint)
    workspace = _choose_workspace(path, work_dir, need)

    staging = Path(tempfile.mkdtemp(prefix="lcm-load-", dir=workspace))
    try:
        with _open_bundle(path) as archive:
            _safe_extract(archive, staging)
        if verify_checksums:
            problems = _verify_extracted(staging)
            if problems:
                raise LcmError(
                    "bundle verification failed:\n  " + "\n  ".join(problems)
                )
        manifest = json.loads((staging / MANIFEST).read_text(encoding="utf-8"))
        packages = json.loads((staging / PACKAGES).read_text(encoding="utf-8"))
        profile = Profile.load(staging / PROFILE)
    except LcmError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except (OSError, tarfile.TarError) as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise LcmError(
            f"could not unpack bundle into {workspace}: {exc}\n"
            "check free space and permissions; choose another location with\n"
            "  lcm restore <bundle> --work-dir /path/with/space"
        ) from exc
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return Bundle(
        root=staging,
        manifest=manifest,
        profile=profile,
        packages=packages,
        temporary=True,
    )


def inspect(path: str | Path) -> dict:
    path = Path(path)
    staging = Path(tempfile.mkdtemp(prefix="lcm-inspect-"))
    try:
        with _open_bundle(path) as archive:
            wanted = {MANIFEST, PROFILE, PACKAGES, CHECKSUMS}
            members = [member for member in archive.getmembers() if member.name in wanted]
            _safe_extract(archive, staging, members)
        manifest = json.loads((staging / MANIFEST).read_text(encoding="utf-8"))
        packages = json.loads((staging / PACKAGES).read_text(encoding="utf-8"))
        profile = Profile.load(staging / PROFILE)
        return {
            "path": str(path),
            "size": path.stat().st_size,
            "manifest": manifest,
            "packages": packages.get("stats", {}),
            "profile": profile.to_dict(),
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def suggested_name(profile: Profile) -> str:
    base = profile.name or "workstation"
    return f"{base}-{timestamp()}.lcmb"
