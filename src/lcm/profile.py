"""The `.lcm.yaml` profile: a distro-neutral description of desired state.

Profiles are data.  They contain no hooks, no scripts and no shell snippets.
That is a deliberate safety property: a profile can be shared, reviewed and
diffed without granting its author code execution on your machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from lcm.detect import Distro, SystemInfo
from lcm.util import LcmError, run_ok

PROFILE_VERSION = 1

DEFAULT_HOME = [
    ".config",
    ".local/share/fonts",
    ".local/share/applications",
    ".local/share/icons",
    ".local/share/themes",
    ".ssh",
    ".mozilla",
    ".pki",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".gitconfig",
    ".gitignore_global",
    ".inputrc",
    ".Xresources",
    ".xinitrc",
    ".gtkrc-2.0",
]

DEFAULT_NEVER = [
    ".cache",
    ".local/share/Trash",
    ".local/share/Steam",
    ".local/share/lutris",
    "Downloads",
    "Games",
]

# Packages that belong to the distribution, not the user.  Migrating them is
# either meaningless (the target has its own) or actively harmful.
SYSTEM_EXACT = {
    "kernel",
    "kernel-core",
    "kernel-modules",
    "kernel-devel",
    "linux",
    "linux-firmware",
    "systemd",
    "dnf",
    "rpm",
    "bash",
    "coreutils",
    "glibc",
    "grub2",
    "grub2-efi-x64",
    "shim-x64",
}

SYSTEM_PREFIXES = (
    "fedora-release",
    "fedora-repos",
    "fedora-workstation",
    "rpmfusion-",
    "akmod-",
    "kmod-",
    "kernel-",
    "linux-image",
    "linux-headers",
    "grub2-",
    "shim-",
    "systemd-",
    "pikaos-desktop",
    # base desktop / plumbing that the target's own meta package recreates
    "NetworkManager-",
    "PackageKit-",
    "abrt-",
    "anaconda-",
    "plasma-",
    "kf5-",
    "kf6-",
    "gnome-",
    "xorg-x11-",
    "pipewire-",
    "wireplumber-",
    "glibc-",
    "fonts-",
    "fontawesome-",
    "google-",
    "intel-",
    "amd-",
    "nvidia-",
    "atheros-",
    "brcmfmac-",
    "cirrus-",
    "b43-",
    "alsa-",
    "sof-",
)

# Suffix rules catch packages like `aubio-devel`, `amd-gpu-firmware` and
# `aajohan-comfortaa-fonts`, which prefix matching cannot express.
SYSTEM_SUFFIXES = (
    "-firmware",
    "-ucode",
    "-devel",
    "-libs",
    "-lib",
    "-static",
    "-doc",
    "-fonts",
    "-font",
    "-theme",
    "-themes",
    "-icons",
)

SYSTEM_EXACT.update(
    {
        "acl",
        "at",
        "at-spi2-atk",
        "at-spi2-core",
        "attr",
        "audit",
        "authselect",
        "avahi",
        "basesystem",
        "bind-utils",
        "bzip2",
        "chrony",
        "cifs-utils",
        "cryptsetup",
        "cups-filters",
        "dbus",
        "dbus-broker",
        "dracut",
        "e2fsprogs",
        "efibootmgr",
        "firewalld",
        "fuse",
        "gdbm",
        "grep",
        "grubby",
        "gssproxy",
        "hostname",
        "iproute",
        "iputils",
        "kbd",
        "kmod",
        "kexec-tools",
        "less",
        "libselinux",
        "libuser",
        "logrotate",
        "lvm2",
        "man-db",
        "microcode_ctl",
        "ncurses",
        "nfs-utils",
        "nss",
        "openssl",
        "pam",
        "passwd",
        "pciutils",
        "pkgconf",
        "polkit",
        "procps-ng",
        "psmisc",
        "python3",
        "python3-libs",
        "rpm",
        "rsync",
        "sed",
        "selinux-policy",
        "setup",
        "shadow-utils",
        "sssd",
        "sudo",
        "systemd",
        "tar",
        "tuned",
        "tzdata",
        "util-linux",
        "which",
        "xfsprogs",
        "xz",
        "zram-generator",
    }
)

SERVICE_CANDIDATES = (
    "sshd",
    "docker",
    "podman.socket",
    "libvirtd",
    "tailscaled",
    "syncthing@",
    "bluetooth",
    "firewalld",
    "ufw",
    "NetworkManager",
    "chronyd",
    "fstrim.timer",
    "earlyoom",
    "thermald",
    "tuned",
    "power-profiles-daemon",
    "fail2ban",
    "cups",
)


@dataclass
class UserSpec:
    name: str
    uid: int | None = None
    gid: int | None = None
    groups: list[str] = field(default_factory=list)
    shell: str = "/bin/bash"
    home: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "uid": self.uid,
            "gid": self.gid,
            "groups": list(self.groups),
            "shell": self.shell,
            **({"home": self.home} if self.home else {}),
        }


@dataclass
class PackageSpec:
    native: list[str] = field(default_factory=list)
    flatpak: list[str] = field(default_factory=list)
    raw: list[dict] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "native": list(self.native),
            "flatpak": list(self.flatpak),
            "raw": [dict(item) for item in self.raw],
            "exclude": list(self.exclude),
        }


@dataclass
class ConfigSpec:
    etc: list[str] = field(default_factory=list)
    home: list[str] = field(default_factory=list)
    never: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "etc": list(self.etc),
            "home": list(self.home),
            "never": list(self.never),
        }


@dataclass
class ValidationSpec:
    require_gpu: bool = True
    require_audio: bool = True
    max_failed_units: int = 0

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Profile:
    lcm: int = PROFILE_VERSION
    name: str = "workstation"
    description: str = ""
    source: dict = field(default_factory=dict)
    target: dict = field(default_factory=dict)
    users: list[UserSpec] = field(default_factory=list)
    packages: PackageSpec = field(default_factory=PackageSpec)
    services: dict[str, list[str]] = field(
        default_factory=lambda: {"enable": [], "disable": []}
    )
    config: ConfigSpec = field(default_factory=ConfigSpec)
    validation: ValidationSpec = field(default_factory=ValidationSpec)
    extra: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list, repr=False)

    # -- serialization ----------------------------------------------------

    def to_dict(self) -> dict:
        data = {
            "lcm": self.lcm,
            "name": self.name,
            "description": self.description,
            "source": dict(self.source),
            "target": dict(self.target),
            "users": [user.to_dict() for user in self.users],
            "packages": self.packages.to_dict(),
            "services": {key: list(value) for key, value in self.services.items()},
            "config": self.config.to_dict(),
            "validation": self.validation.to_dict(),
        }
        data.update(self.extra)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Profile":
        if not isinstance(data, dict):
            raise LcmError("profile must be a YAML mapping")

        warnings: list[str] = []
        version = data.get("lcm")
        if version is None:
            warnings.append("profile has no `lcm:` version; assuming 1")
            version = 1
        if int(version) != PROFILE_VERSION:
            raise LcmError(
                f"unsupported profile version {version}; this build understands {PROFILE_VERSION}"
            )

        known = {
            "lcm",
            "name",
            "description",
            "source",
            "target",
            "users",
            "packages",
            "services",
            "config",
            "validation",
        }
        extra = {key: value for key, value in data.items() if key not in known}
        for key in extra:
            warnings.append(f"unknown profile key ignored by this build: {key}")

        users = []
        for item in data.get("users") or []:
            if isinstance(item, str):
                users.append(UserSpec(name=item))
                continue
            if not isinstance(item, dict) or not item.get("name"):
                raise LcmError(f"invalid user entry: {item!r}")
            users.append(
                UserSpec(
                    name=str(item["name"]),
                    uid=int(item["uid"]) if item.get("uid") is not None else None,
                    gid=int(item["gid"]) if item.get("gid") is not None else None,
                    groups=[str(g) for g in item.get("groups") or []],
                    shell=str(item.get("shell") or "/bin/bash"),
                    home=item.get("home"),
                )
            )

        package_data = data.get("packages") or {}
        raw_entries = []
        for item in package_data.get("raw") or []:
            if isinstance(item, str):
                raw_entries.append({"name": item, "family": None})
            elif isinstance(item, dict) and item.get("name"):
                raw_entries.append(
                    {"name": str(item["name"]), "family": item.get("family")}
                )
            else:
                warnings.append(f"ignored invalid raw package entry: {item!r}")

        config_data = data.get("config") or {}
        validation_data = data.get("validation") or {}

        profile = cls(
            lcm=int(version),
            name=str(data.get("name") or "workstation"),
            description=str(data.get("description") or ""),
            source=dict(data.get("source") or {}),
            target=dict(data.get("target") or {}),
            users=users,
            packages=PackageSpec(
                native=[str(item) for item in package_data.get("native") or []],
                flatpak=[str(item) for item in package_data.get("flatpak") or []],
                raw=raw_entries,
                exclude=[str(item) for item in package_data.get("exclude") or []],
            ),
            services={
                "enable": [
                    str(item)
                    for item in (data.get("services") or {}).get("enable") or []
                ],
                "disable": [
                    str(item)
                    for item in (data.get("services") or {}).get("disable") or []
                ],
            },
            config=ConfigSpec(
                etc=[str(item) for item in config_data.get("etc") or []],
                home=[str(item) for item in config_data.get("home") or []],
                never=[str(item) for item in config_data.get("never") or []],
            ),
            validation=ValidationSpec(
                require_gpu=bool(validation_data.get("require_gpu", True)),
                require_audio=bool(validation_data.get("require_audio", True)),
                max_failed_units=int(validation_data.get("max_failed_units", 0)),
            ),
            extra=extra,
            warnings=warnings,
        )
        profile.validate()
        return profile

    def validate(self) -> None:
        if not self.name:
            raise LcmError("profile has an empty name")
        if not self.users:
            self.warnings.append("profile defines no users")
        if not (self.packages.native or self.packages.flatpak or self.packages.raw):
            self.warnings.append("profile defines no packages")

    # -- io ---------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "Profile":
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise LcmError(f"cannot read profile: {path}") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise LcmError(f"invalid YAML in {path}: {exc}") from exc
        profile = cls.from_dict(data or {})
        return profile

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.write_text(self.to_yaml(), encoding="utf-8")
        return path

    def to_yaml(self) -> str:
        header = (
            "# LCM profile.  Data only: no hooks, no scripts, no shell.\n"
            "# Packages use canonical ids from `lcm mapping`.\n"
        )
        body = yaml.safe_dump(
            self.to_dict(),
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )
        return header + body

    # -- construction -----------------------------------------------------

    @classmethod
    def from_system(
        cls,
        system: SystemInfo,
        database,
        capture,
        flatpaks: list[str],
        name: str | None = None,
    ) -> "Profile":
        users = [
            UserSpec(
                name=user.name,
                uid=user.uid,
                gid=user.gid,
                groups=[group for group in user.groups if group not in {"root"}],
                shell=user.shell,
                home=user.home,
            )
            for user in system.users
        ]

        native: list[str] = []
        raw: list[dict] = []
        seen_canonical: set[str] = set()
        dropped = 0
        for package in capture.names:
            # A canonical mapping always wins: it is the strongest evidence
            # that this package is something the user chose to have.
            canonical = database.canonical_for(system.distro.family, package)
            if canonical:
                if canonical not in seen_canonical:
                    seen_canonical.add(canonical)
                    native.append(canonical)
                continue
            if is_system_package(package):
                dropped += 1
                continue
            raw.append({"name": package, "family": system.distro.family})

        etc_paths, _review = load_etc_allowlist()

        profile = cls(
            name=name or f"{system.distro.id}-workstation",
            description=f"Captured from {system.distro.pretty} on {system.hardware.kernel}",
            source={
                "distro": system.distro.id,
                "release": system.distro.version,
                "family": system.distro.family,
            },
            users=users,
            packages=PackageSpec(
                native=sorted(native),
                flatpak=sorted(set(flatpaks)),
                raw=sorted(raw, key=lambda item: item["name"]),
            ),
            services={
                "enable": enabled_services(),
                "disable": [],
            },
            config=ConfigSpec(
                etc=etc_paths,
                home=list(DEFAULT_HOME),
                never=list(DEFAULT_NEVER),
            ),
        )
        if capture.fidelity != "high":
            profile.warnings.append(
                f"package capture fidelity was low: {'; '.join(capture.notes)}"
            )
        return profile


def is_system_package(name: str) -> bool:
    if name in SYSTEM_EXACT:
        return True
    if name.startswith(SYSTEM_PREFIXES):
        return True
    return name.endswith(SYSTEM_SUFFIXES)


def load_etc_allowlist() -> tuple[list[str], list[str]]:
    path = Path(__file__).resolve().parent / "data" / "etc-allowlist.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return [], []
    safe = [str(item) for item in data.get("safe") or []]
    review = [str(item) for item in data.get("review") or []]
    return safe, review


def enabled_services() -> list[str]:
    ok, out, _ = run_ok(["systemctl", "list-unit-files", "--state=enabled", "--no-legend"])
    if not ok:
        return []
    enabled = []
    for line in out.splitlines():
        name = line.split()[0] if line.split() else ""
        if not name:
            continue
        for candidate in SERVICE_CANDIDATES:
            if name.startswith(candidate):
                enabled.append(name)
                break
    return sorted(set(enabled))


def empty_profile(distro: Distro | None = None) -> Profile:
    source = {}
    if distro is not None:
        source = {
            "distro": distro.id,
            "release": distro.version,
            "family": distro.family,
        }
    return Profile(
        source=source,
        users=[UserSpec(name="user", uid=1000)],
        config=ConfigSpec(
            etc=load_etc_allowlist()[0],
            home=list(DEFAULT_HOME),
            never=list(DEFAULT_NEVER),
        ),
    )
