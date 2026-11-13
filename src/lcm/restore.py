"""Apply a bundle or profile to an already-installed system.

This is the safe half of the project: it does not partition, does not touch
boot, and writes only inside the user's home and an explicit /etc allowlist.
Every overwritten file is copied to a timestamped backup first.
"""

from __future__ import annotations

import fnmatch
import os
import pwd
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from lcm import pkgs
from lcm.bundle import Bundle
from lcm.detect import detect_distro, family_of
from lcm.mapping import Database
from lcm.profile import Profile
from lcm.util import (
    LcmError,
    Style,
    confirm,
    require_root,
    run_ok,
    safe_join,
    timestamp,
)

STEPS = ("packages", "config", "services")


@dataclass
class RestoreReport:
    family: str
    native: list[str] = field(default_factory=list)
    flatpak: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    raw_attempts: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    created_users: list[str] = field(default_factory=list)
    etc_files: int = 0
    home_files: int = 0
    backup_root: Path | None = None
    notes: list[str] = field(default_factory=list)
    applied: bool = False


def _parse_steps(value: str | None) -> tuple[str, ...]:
    if not value:
        return STEPS
    parts = tuple(part.strip() for part in value.split(",") if part.strip())
    for part in parts:
        if part not in STEPS:
            raise LcmError(f"unknown step: {part} (choose from {', '.join(STEPS)})")
    return parts


def _never(name: str, patterns: list[str]) -> bool:
    """Match a path and each of its components against the patterns.

    Single-component patterns such as `Cache` apply at any depth, while
    multi-component patterns such as `.local/share/Steam` must match a path
    prefix so every file below that directory is skipped.
    """
    parts = Path(name).parts
    for pattern in patterns:
        prefix = ""
        for part in parts:
            prefix = f"{prefix}/{part}" if prefix else part
            if fnmatch.fnmatch(part, pattern) or fnmatch.fnmatch(prefix, pattern):
                return True
    return False


def _backup_file(dest: Path, root: Path, relative: str) -> None:
    if not dest.exists() and not dest.is_symlink():
        return
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or target.exists():
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target, ignore_errors=True)
        else:
            target.unlink()
    if dest.is_symlink():
        os.symlink(os.readlink(dest), target)
    elif dest.is_file():
        shutil.copy2(dest, target)


def _lexical_path(root: Path, name: str) -> Path:
    """Join a member name without following symlinks in the final component.

    The parent is still resolved: creating a link through an existing symlinked
    directory could otherwise write outside the destination root.
    """
    if name.startswith("/") or name.startswith("\\"):
        raise LcmError(f"refusing absolute path in archive: {name}")
    relative = Path(name)
    parts = relative.parts
    if any(part == ".." for part in parts):
        raise LcmError(f"refusing path traversal in archive: {name}")
    parent_name = str(relative.parent)
    if parent_name in {"", "."}:
        parent = root.resolve()
    else:
        parent = safe_join(root, parent_name)
    return parent / relative.name


def _remove_for_member(dest: Path, member: tarfile.TarInfo) -> None:
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        dest.unlink()
    elif dest.is_dir() and not member.isdir():
        # Do not silently replace a directory with a file or a link.
        raise LcmError(f"refusing to replace a directory with {member.name}")


def _extract_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    dest_root: Path,
    backup_root: Path,
    owner: tuple[int, int] | None,
) -> None:
    dest = _lexical_path(dest_root, member.name)

    if member.issym():
        link = member.linkname or ""
        if link.startswith("/") or ".." in Path(link).parts:
            raise LcmError(f"unsafe symlink target: {member.name} -> {link}")
        if dest.exists() or dest.is_symlink():
            _backup_file(dest, backup_root, member.name)
            _remove_for_member(dest, member)
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(link, dest)
        if owner is not None:
            try:
                os.lchown(dest, owner[0], owner[1])
            except OSError:
                pass
        return

    if member.islnk():
        link = member.linkname or ""
        target = safe_join(dest_root, link)
        if not target.exists():
            raise LcmError(f"hardlink target is missing: {member.name} -> {link}")
        if dest.exists() or dest.is_symlink():
            _backup_file(dest, backup_root, member.name)
            _remove_for_member(dest, member)
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.link(target, dest)
        return

    # Regular files and directories: resolving here rejects writes through an
    # existing symlink that points outside the destination root.
    dest = safe_join(dest_root, member.name)
    if dest.exists() or dest.is_symlink():
        _backup_file(dest, backup_root, member.name)
        _remove_for_member(dest, member)
    dest_root.mkdir(parents=True, exist_ok=True)
    try:
        archive.extract(member, dest_root, set_attrs=True, filter="data")
    except TypeError:  # Python < 3.12
        archive.extract(member, dest_root, set_attrs=True)
    if owner is not None:
        try:
            os.chown(dest, owner[0], owner[1], follow_symlinks=False)
        except OSError:
            pass


def _extract(
    tar_path: Path,
    dest_root: Path,
    backup_root: Path,
    never: list[str],
    *,
    apply: bool,
    owner: tuple[int, int] | None = None,
) -> tuple[int, list[str]]:
    count = 0
    notes: list[str] = []
    with tarfile.open(tar_path, "r:*") as archive:
        for member in archive.getmembers():
            if member.isdev() or member.isfifo():
                notes.append(f"skipped special file: {member.name}")
                continue
            if _never(member.name, never):
                continue
            if not apply:
                count += 1
                continue
            try:
                _extract_member(archive, member, dest_root, backup_root, owner)
            except LcmError as exc:
                notes.append(f"skipped {member.name}: {exc}")
                continue
            count += 1
    return count, notes


def _resolve(
    profile: Profile, family: str, distro_id: str, *, try_raw: bool = False
) -> tuple[list[str], list[str], list[str], list[str]]:
    database = Database()
    native: list[str] = []
    flatpak: list[str] = []
    unknown: list[str] = []
    attempted: list[str] = []
    excluded = {str(item) for item in profile.packages.exclude}

    for canonical in profile.packages.native:
        if canonical in excluded:
            continue
        resolution = database.resolve(canonical, family, distro_id)
        if resolution.native:
            native.append(resolution.native)
        elif resolution.flatpak:
            flatpak.append(resolution.flatpak)
        else:
            unknown.append(canonical)

    for item in profile.packages.raw:
        name = str(item.get("name", ""))
        if not name or name in excluded:
            continue
        source_family = str(item.get("family") or profile.source.get("family") or "")
        resolution = database.resolve_raw(
            name,
            source_family,
            family,
            source_distro=profile.source.get("distro"),
            target_distro=distro_id,
        )
        if resolution.native:
            native.append(resolution.native)
        elif resolution.flatpak:
            flatpak.append(resolution.flatpak)
        elif try_raw:
            # Opt-in best effort: the target may use the same name even when
            # there is no canonical mapping.  Missing names are reported by
            # the package installer, never guessed silently.
            native.append(name)
            attempted.append(name)
        else:
            unknown.append(name)

    flatpak.extend(profile.packages.flatpak)
    return (
        sorted(set(native)),
        sorted(set(flatpak)),
        sorted(set(unknown)),
        sorted(set(attempted)),
    )


def _human_users() -> list[pwd.struct_passwd]:
    users = []
    for entry in pwd.getpwall():
        if 1000 <= entry.pw_uid < 60000 and not entry.pw_shell.endswith(
            ("nologin", "false")
        ):
            users.append(entry)
    return users


def _home_plan(
    profile: Profile, *, apply: bool, report: RestoreReport
) -> dict[str, tuple[pwd.struct_passwd, Path]]:
    """Map profile users onto real accounts and home directories.

    A bundle often comes from a machine where the account name differs from
    the fresh target.  Rather than creating a second, password-less account,
    dotfiles go to the single existing human user when there is exactly one.
    """
    plan: dict[str, tuple[pwd.struct_passwd, Path]] = {}
    humans = _human_users()
    for user in profile.users:
        try:
            entry = pwd.getpwnam(user.name)
            plan[user.name] = (entry, Path(entry.pw_dir))
            continue
        except KeyError:
            pass

        if len(humans) == 1:
            entry = humans[0]
            report.notes.append(
                f"user {user.name} does not exist; restoring its files into "
                f"{entry.pw_name}'s home ({entry.pw_dir})"
            )
            plan[user.name] = (entry, Path(entry.pw_dir))
            continue

        home = Path(user.home or f"/home/{user.name}")
        if not apply:
            report.notes.append(
                f"user {user.name} does not exist (would be created with {home})"
            )
            continue
        argv = ["useradd", "-m", "-U", "-s", user.shell or "/bin/bash"]
        if user.uid is not None:
            try:
                pwd.getpwuid(user.uid)
            except KeyError:
                argv += ["-u", str(user.uid)]
        argv.append(user.name)
        ok, _, err = run_ok(argv)
        if not ok:
            report.notes.append(f"could not create user {user.name}: {err.strip()}")
            continue
        report.created_users.append(user.name)
        entry = pwd.getpwnam(user.name)
        if (
            user.home
            and Path(user.home).is_absolute()
            and Path(user.home) != Path(entry.pw_dir)
        ):
            target_home = Path(user.home)
            try:
                target_home.parent.mkdir(parents=True, exist_ok=True)
                ok, _, _ = run_ok(
                    ["usermod", "-d", str(target_home), "-m", user.name]
                )
                if ok:
                    entry = pwd.getpwnam(user.name)
            except OSError as exc:
                report.notes.append(
                    f"could not move {user.name}'s home to {target_home}: {exc}"
                )
        plan[user.name] = (entry, Path(entry.pw_dir))
    return plan


SERVICE_ALIASES = {
    "sshd": ("sshd.service", "ssh.service"),
    "ssh": ("ssh.service", "sshd.service"),
}


def _enable_services(
    services: list[str], *, apply: bool
) -> tuple[list[str], list[str], list[str]]:
    enabled: list[str] = []
    missing: list[str] = []
    failed: list[str] = []
    for service in services:
        chosen = None
        for candidate in SERVICE_ALIASES.get(service, (service,)):
            ok, out, _ = run_ok(["systemctl", "list-unit-files", candidate])
            if ok and candidate in out:
                chosen = candidate
                break
        if chosen is None:
            missing.append(service)
            continue
        if apply:
            ok, _, err = run_ok(["systemctl", "enable", chosen])
            if not ok:
                failed.append(f"{chosen}: {err.strip() or 'enable failed'}")
                continue
        enabled.append(chosen)
    return enabled, missing, failed


def _restore(
    profile: Profile,
    *,
    label: str,
    apply: bool,
    steps: str | None,
    assume_yes: bool,
    etc_tar: Path | None = None,
    home_tars: dict[str, Path] | None = None,
    include_flatpak: bool = True,
    try_raw: bool = False,
) -> RestoreReport:
    selected = _parse_steps(steps)
    distro = detect_distro()
    family = family_of(distro.id, *distro.id_like)
    report = RestoreReport(family=family, applied=apply)
    home_tars = home_tars or {}

    if apply and ("config" in selected or "services" in selected):
        require_root("restoring /etc, users and services")
    if apply and "packages" in selected:
        require_root("installing packages")

    if apply and not assume_yes:
        if not confirm(f"Apply {label} to {distro.pretty}?", assume_yes=False):
            raise LcmError("aborted")

    if "packages" in selected:
        native, flatpak, unknown, attempted = _resolve(
            profile, family, distro.id, try_raw=try_raw
        )
        if not include_flatpak and flatpak:
            report.notes.append(
                f"{len(flatpak)} Flatpak app(s) skipped (--no-flatpak)"
            )
            flatpak = []
        report.native = native
        report.flatpak = flatpak
        report.unknown = unknown
        report.raw_attempts = attempted
        if attempted:
            verb = "attempted" if apply else "would be attempted"
            report.notes.append(
                f"{len(attempted)} unmapped raw package name(s) {verb} "
                "unchanged (--try-raw); names missing from the target are "
                "reported as failures"
            )
        if apply:
            report.failed.extend(pkgs.install(family, native))
            if flatpak and not pkgs.is_installed(family, "flatpak"):
                report.failed.extend(pkgs.install(family, ["flatpak"]))
            report.failed.extend(pkgs.install_flatpak(flatpak))

    stamp = timestamp()
    if "config" in selected:
        # A profile-only restore has no dotfile payload, so there is no reason
        # to create accounts or touch home directories.
        plan = _home_plan(profile, apply=apply, report=report) if home_tars else {}

        if etc_tar is not None:
            backup = Path("/var/lib/lcm/backup") / stamp / "etc"
            count, notes = _extract(
                etc_tar,
                Path("/etc"),
                backup,
                profile.config.never,
                apply=apply,
            )
            report.etc_files = count
            report.notes.extend(notes)
            if apply:
                report.backup_root = backup
        elif not any(profile.config.etc):
            pass
        else:
            report.notes.append(
                "profile has no /etc payload; run `lcm export` to include one"
            )

        for user in profile.users:
            tar_path = home_tars.get(user.name)
            mapped = plan.get(user.name)
            if tar_path is None or mapped is None:
                continue
            entry, home = mapped
            if not home.exists():
                report.notes.append(f"home for {entry.pw_name} does not exist; skipped")
                continue
            backup = home / ".lcm-backup" / stamp
            count, notes = _extract(
                tar_path,
                home,
                backup,
                profile.config.never,
                apply=apply,
                owner=(entry.pw_uid, entry.pw_gid),
            )
            report.home_files += count
            report.notes.extend(notes)
            if apply:
                report.backup_root = backup.parent

    if "services" in selected:
        enabled, missing, failed = _enable_services(
            profile.services.get("enable") or [], apply=apply
        )
        if enabled:
            report.notes.append("services enabled: " + ", ".join(enabled))
        if missing:
            report.notes.append(
                "services not present on target: " + ", ".join(missing)
            )
        if failed:
            report.notes.append(
                "services that could not be enabled: " + "; ".join(failed)
            )

    if report.failed:
        report.notes.append(
            f"{len(report.failed)} package(s) could not be installed; "
            "they are listed below. Install them by hand if you need them."
        )

    return report


def run(
    bundle: Bundle,
    *,
    apply: bool = False,
    steps: str | None = None,
    assume_yes: bool = False,
    include_flatpak: bool = True,
    try_raw: bool = False,
) -> RestoreReport:
    home_tars: dict[str, Path] = {}
    for user in bundle.profile.users:
        path = bundle.payload_home(user.name)
        if path is not None:
            home_tars[user.name] = path
    return _restore(
        bundle.profile,
        label=bundle.manifest.get("tool", "this bundle"),
        apply=apply,
        steps=steps,
        assume_yes=assume_yes,
        etc_tar=bundle.payload_etc,
        home_tars=home_tars,
        include_flatpak=include_flatpak,
        try_raw=try_raw,
    )


def run_profile(
    profile: Profile,
    *,
    apply: bool = False,
    steps: str | None = None,
    assume_yes: bool = False,
    include_flatpak: bool = True,
    try_raw: bool = False,
) -> RestoreReport:
    """Apply a bare `.lcm.yaml` (packages and services, no file payload)."""
    return _restore(
        profile,
        label=f"profile {profile.name}",
        apply=apply,
        steps=steps,
        assume_yes=assume_yes,
        etc_tar=None,
        home_tars={},
        include_flatpak=include_flatpak,
        try_raw=try_raw,
    )


def render(report: RestoreReport, style: Style | None = None) -> str:
    style = style or Style(False)
    lines = [
        style.bold("LCM restore" + (" (applied)" if report.applied else " (dry run)")),
        f"Target family: {report.family}",
        "",
    ]
    if report.native:
        lines.append(style.bold(f"Native packages ({len(report.native)})"))
        lines.append("  " + " ".join(report.native))
    if report.flatpak:
        lines.append(style.bold(f"Flatpak ({len(report.flatpak)})"))
        lines.append("  " + " ".join(report.flatpak))
    if report.unknown:
        lines.append(style.yellow(f"Unmapped ({len(report.unknown)})"))
        lines.append("  " + ", ".join(report.unknown))
    if report.failed:
        lines.append(style.red(f"Failed to install ({len(report.failed)})"))
        lines.append("  " + ", ".join(report.failed))
    if report.created_users:
        lines.append(f"Users created: {', '.join(report.created_users)}")
    if report.etc_files:
        lines.append(f"/etc entries: {report.etc_files}")
    if report.home_files:
        lines.append(f"home entries: {report.home_files}")
    if report.notes:
        lines.append("")
        lines.append(style.bold("Notes"))
        for note in report.notes:
            lines.append(f"  - {note}")
    if report.backup_root:
        lines.append("")
        lines.append(f"Backups: {report.backup_root}")
    if not report.applied:
        lines.append("")
        lines.append(
            style.yellow("Dry run only. Re-run with --apply to write changes.")
        )
    return "\n".join(lines)
