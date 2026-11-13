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
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from lcm import __version__
from lcm.profile import Profile
from lcm.util import LcmError, run_ok, safe_join, timestamp, utc_now

BUNDLE_FORMAT = 1
MANIFEST = "manifest.json"
PROFILE = "profile.yaml"
PACKAGES = "packages.json"
CHECKSUMS = "checksums.sha256"

BUILTIN_EXCLUDES = {
    ".cache",
    ".lcm-backup",
    "Cache",
    "cache",
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

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
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


def _add_member(
    archive: tarfile.TarFile,
    path: Path,
    arcname: str,
    member_filter,
) -> bool:
    try:
        info = archive.gettarinfo(str(path), arcname)
    except OSError:
        return False
    if info is None:
        return False
    if member_filter is not None and member_filter(info) is None:
        return False
    if info.isreg():
        try:
            handle = open(path, "rb")
        except OSError:
            # Unreadable file (for example a root-only secret while exporting
            # unprivileged): skip it instead of aborting the whole bundle.
            return False
        try:
            archive.addfile(info, handle)
        finally:
            handle.close()
    else:
        archive.addfile(info)
    return True


def _walk_into(
    archive: tarfile.TarFile,
    path: Path,
    arcname: str,
    member_filter,
) -> None:
    if not _add_member(archive, path, arcname, member_filter):
        return
    if path.is_symlink() or not path.is_dir():
        return
    try:
        children = sorted(path.iterdir())
    except OSError:
        return
    for child in children:
        _walk_into(archive, child, f"{arcname}/{child.name}", member_filter)


def _tar_tree(
    source_root: Path,
    patterns: list[str],
    excludes: list[str],
    out: Path,
) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    member_filter = _make_filter(excludes + sorted(BUILTIN_EXCLUDES))
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
                    )
            else:
                _walk_into(archive, candidate, pattern, member_filter)


def _checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == CHECKSUMS:
            continue
        relative = path.relative_to(root).as_posix()
        lines.append(f"{_sha256(path)}  {relative}")
    return "\n".join(lines) + "\n"


def create(
    out_path: str | Path,
    profile: Profile,
    packages: dict,
    system,
    *,
    include_payload: bool = True,
) -> Path:
    """Build a `.lcmb` from a profile and captured state."""
    out_path = Path(out_path)
    if out_path.suffix != ".lcmb":
        out_path = out_path.with_suffix(".lcmb")

    staging = Path(tempfile.mkdtemp(prefix="lcm-bundle-"))
    try:
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
        (staging / MANIFEST).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (staging / PACKAGES).write_text(
            json.dumps(packages, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        if include_payload:
            home = Path(profile.users[0].home) if profile.users and profile.users[0].home else Path.home()
            etc = Path("/etc")
            for user in profile.users:
                user_home = Path(user.home) if user.home else home
                tar_path = staging / "payload" / f"home-{user.name}.tar"
                _tar_tree(
                    user_home,
                    profile.config.home,
                    profile.config.never,
                    tar_path,
                )
            _tar_tree(etc, profile.config.etc, [], staging / "payload" / "etc.tar")

        (staging / CHECKSUMS).write_text(_checksums(staging), encoding="utf-8")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name = out_path.with_name(out_path.name + ".partial")
        with tarfile.open(temporary_name, "w:gz", compresslevel=6) as archive:
            for path in sorted(staging.rglob("*")):
                archive.add(
                    path,
                    arcname=path.relative_to(staging).as_posix(),
                    recursive=False,
                )
        os.replace(temporary_name, out_path)
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        return out_path
    finally:
        shutil.rmtree(staging, ignore_errors=True)


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


def load(path: str | Path, *, verify_checksums: bool = True) -> Bundle:
    path = Path(path)
    problems = verify(path) if verify_checksums else []
    if problems:
        raise LcmError("bundle verification failed:\n  " + "\n  ".join(problems))

    staging = Path(tempfile.mkdtemp(prefix="lcm-load-"))
    try:
        with _open_bundle(path) as archive:
            _safe_extract(archive, staging)
        manifest = json.loads((staging / MANIFEST).read_text(encoding="utf-8"))
        packages = json.loads((staging / PACKAGES).read_text(encoding="utf-8"))
        profile = Profile.load(staging / PROFILE)
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
