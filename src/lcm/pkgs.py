"""Package manager backends: capture the explicit set, install a target set.

Capture fidelity matters.  `apt-mark showmanual` and `pacman -Qqe` give a
clean "user asked for this" list.  RPM systems are messier; dnf can do it,
and we fall back to `rpm -qa` with a loud warning when it cannot.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from lcm.util import LcmError, run_ok

FAMILY_MANAGER = {
    "fedora": "dnf",
    "debian": "apt",
    "arch": "pacman",
    "suse": "zypper",
}

MANAGER_FAMILY = {value: key for key, value in FAMILY_MANAGER.items()}


@dataclass
class Capture:
    manager: str
    family: str
    names: list[str] = field(default_factory=list)
    fidelity: str = "high"  # high | low
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def manager_for(family: str) -> str | None:
    return FAMILY_MANAGER.get(family)


def _clean(names: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for name in names:
        value = name.strip()
        if not value or value.startswith("#") or value.startswith("Installed"):
            continue
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return sorted(result)


def _capture_dnf() -> Capture:
    # `--qf '%{name}\n'` is passed as a literal backslash-n to dnf; dnf expands
    # it into a real newline.  Without it dnf returns one giant concatenated
    # string, which looks like a single package name.
    ok, out, _ = run_ok(
        ["dnf", "-q", "repoquery", "--userinstalled", "--qf", "%{name}\\n"]
    )
    if ok and out.strip():
        return Capture("dnf", "fedora", _clean(out.splitlines()))

    ok, out, _ = run_ok(["dnf", "-q", "history", "userinstalled"])
    if ok and out.strip():
        return Capture("dnf", "fedora", _clean(out.splitlines()))

    ok, out, _ = run_ok(["rpm", "-qa", "--qf", "%{NAME}\n"])
    if ok:
        return Capture(
            "rpm",
            "fedora",
            _clean(out.splitlines()),
            fidelity="low",
            notes=["dnf could not list user-installed packages; captured every RPM"],
        )
    raise LcmError("cannot capture packages: dnf and rpm both failed")


def _capture_apt() -> Capture:
    ok, out, _ = run_ok(["apt-mark", "showmanual"])
    if ok:
        return Capture("apt", "debian", _clean(out.splitlines()))
    raise LcmError("cannot capture packages: apt-mark failed")


def _capture_pacman() -> Capture:
    ok, out, _ = run_ok(["pacman", "-Qqe"])
    if ok:
        return Capture("pacman", "arch", _clean(out.splitlines()))
    raise LcmError("cannot capture packages: pacman failed")


def _capture_zypper() -> Capture:
    ok, out, _ = run_ok(
        ["zypper", "--porcelain", "packages", "--installed-only", "--type", "package"]
    )
    if ok and out.strip():
        names = []
        for line in out.splitlines():
            fields = [field.strip() for field in line.split("|")]
            if len(fields) >= 3:
                names.append(fields[2])
        if names:
            return Capture("zypper", "suse", _clean(names))

    ok, out, _ = run_ok(["rpm", "-qa", "--qf", "%{NAME}\n"])
    if ok:
        return Capture(
            "rpm",
            "suse",
            _clean(out.splitlines()),
            fidelity="low",
            notes=["zypper query failed; captured every RPM"],
        )
    raise LcmError("cannot capture packages: zypper and rpm both failed")


def capture(family: str) -> Capture:
    if family == "fedora":
        return _capture_dnf()
    if family == "debian":
        return _capture_apt()
    if family == "arch":
        return _capture_pacman()
    if family == "suse":
        return _capture_zypper()
    raise LcmError(f"no package backend for family: {family}")


def capture_flatpak() -> list[str]:
    ok, out, _ = run_ok(["flatpak", "list", "--app", "--columns=application"])
    if not ok:
        return []
    return _clean(out.splitlines())


def install_command(family: str, names: list[str]) -> list[str]:
    if not names:
        raise LcmError("nothing to install")
    if family == "fedora":
        return ["dnf", "install", "-y", "--setopt=install_weak_deps=False", *names]
    if family == "debian":
        return ["apt-get", "install", "-y", *names]
    if family == "arch":
        return ["pacman", "-S", "--needed", "--noconfirm", *names]
    if family == "suse":
        return ["zypper", "--non-interactive", "install", *names]
    raise LcmError(f"no package backend for family: {family}")


def update_command(family: str) -> list[str] | None:
    if family == "debian":
        return ["apt-get", "update"]
    if family == "arch":
        # Arch does not support partial upgrades: sync and upgrade together
        # before installing anything new.
        return ["pacman", "-Syu", "--noconfirm"]
    if family == "suse":
        return ["zypper", "--non-interactive", "refresh"]
    return None


def flatpak_install_command(app_ids: list[str], remote: str = "flathub") -> list[str]:
    return ["flatpak", "install", "-y", "--noninteractive", remote, *app_ids]


def _root_prefix() -> list[str]:
    return [] if os.geteuid() == 0 else ["sudo"]


def install(family: str, names: list[str], *, dry_run: bool = False) -> list[str]:
    """Install packages, tolerating individually missing ones.

    A cross-distro profile routinely names a package that the target does not
    carry (or carries only in a component that is not enabled).  Failing the
    whole restore for one missing name would make the bundle useless, so the
    batch is attempted first and then retried one package at a time.  Returns
    the names that could not be installed.
    """
    if not names:
        return []
    if dry_run:
        return []
    update = update_command(family)
    env = dict(os.environ)
    if family == "debian":
        env["DEBIAN_FRONTEND"] = "noninteractive"
    if update is not None:
        run_ok([*_root_prefix(), *update], env=env)

    ok, _, _ = run_ok([*_root_prefix(), *install_command(family, names)], env=env)
    if ok:
        return []

    failed: list[str] = []
    for name in names:
        ok, _, _ = run_ok(
            [*_root_prefix(), *install_command(family, [name])], env=env
        )
        if not ok:
            failed.append(name)
    return failed


def install_flatpak(app_ids: list[str], *, dry_run: bool = False) -> list[str]:
    if not app_ids or dry_run:
        return []
    run_ok(
        [
            *_root_prefix(),
            "flatpak",
            "remote-add",
            "--if-not-exists",
            "flathub",
            "https://flathub.org/repo/flathub.flatpakrepo",
        ]
    )
    ok, _, _ = run_ok([*_root_prefix(), *flatpak_install_command(app_ids)])
    if ok:
        return []
    failed: list[str] = []
    for app_id in app_ids:
        ok, _, _ = run_ok([*_root_prefix(), *flatpak_install_command([app_id])])
        if not ok:
            failed.append(app_id)
    return failed


def is_installed(family: str, name: str) -> bool:
    if family == "fedora":
        ok, _, _ = run_ok(["rpm", "-q", name])
    elif family == "debian":
        ok, _, _ = run_ok(["dpkg", "-s", name])
    elif family == "arch":
        ok, _, _ = run_ok(["pacman", "-Q", name])
    elif family == "suse":
        ok, _, _ = run_ok(["rpm", "-q", name])
    else:
        return False
    return ok


def normalize_version(text: str) -> str:
    return re.sub(r"^[0-9]*:", "", text.strip())
