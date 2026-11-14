"""Transactional distro replacement.

The invariant: the running system is never modified.  The target is built as
a peer btrfs subvolume, registered as its own firmware boot entry, validated
on first boot, and only then committed.  Rollback is a boot order change.

`replace` runs from the live system, not from a rescue ISO.  That is possible
precisely because nothing under the running root is written to.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path

from lcm import __version__, pkgs
from lcm.assess import analyze, needed_space_bytes, render_plan
from lcm.bundle import create as create_bundle
from lcm.bundle import suggested_name
from lcm.detect import Boot, SystemInfo, detect_system, family_of
from lcm.mapping import Database
from lcm.profile import Profile
from lcm.util import (
    LcmError,
    Style,
    atomic_write,
    confirm,
    have,
    human_bytes,
    is_mountpoint,
    require_root,
    run,
    run_ok,
    timestamp,
    utc_now,
)

STATE_ORDER = [
    "planned",
    "prepared",
    "bootstrapped",
    "configured",
    "armed",
    "validated",
    "committed",
    "rolled_back",
    "failed",
]

JOURNAL_ROOT = Path("/var/lib/lcm/journal")
BUNDLE_DIR = Path("/var/lib/lcm/bundles")
POOL_MOUNT = Path("/var/lib/lcm/mnt/pool")
TARGET_ROOT = Path("/mnt/lcm-target")

DEFAULT_SUITES = {
    "debian": "stable",
    "pikaos": "sid",
    "ubuntu": "noble",
    "linuxmint": "noble",
    "pop": "noble",
    "kali": "kali-rolling",
    "arch": "",
    "fedora": "",
    "suse": "",
}

DEFAULT_MIRRORS = {
    "debian": "http://deb.debian.org/debian",
}

DEBIAN_BASE = [
    "systemd-sysv",
    "initramfs-tools",
    "dbus",
    "ca-certificates",
    "network-manager",
    "sudo",
    "locales",
    "console-setup",
    "keyboard-configuration",
    "efibootmgr",
    "systemd-boot-efi",
    "openssh-client",
    "iproute2",
    "kmod",
    "curl",
]

FEDORA_BASE = [
    "@core",
    "kernel",
    "systemd",
    "systemd-udev",
    "NetworkManager",
    "sudo",
    "openssh-clients",
    "dnf",
    "fedora-release",
    "fedora-repos",
    "efibootmgr",
    "systemd-boot-efi",
    "iproute",
]

ARCH_BASE = [
    "base",
    "systemd",
    "linux",
    "linux-firmware",
    "networkmanager",
    "sudo",
    "efibootmgr",
    "iproute2",
]

ARCH_BOOTSTRAP_URL = "https://geo.mirror.pkgbuild.com/iso/latest/archlinux-bootstrap-x86_64.tar.zst"

SUSE_BASE = [
    "patterns-base-minimal_base",
    "kernel-default",
    "systemd",
    "NetworkManager",
    "sudo",
    "efibootmgr",
    "iproute2",
]


# --------------------------------------------------------------------------
# journal
# --------------------------------------------------------------------------

@dataclass
class Journal:
    id: str
    data: dict
    root: Path = JOURNAL_ROOT
    persist: bool = True

    @property
    def directory(self) -> Path:
        return self.root / self.id

    @property
    def path(self) -> Path:
        return self.directory / "journal.json"

    @property
    def state(self) -> str:
        return str(self.data.get("state", "planned"))

    def set_state(self, state: str, **extra) -> None:
        if state not in STATE_ORDER:
            raise LcmError(f"invalid journal state: {state}")
        self.data["state"] = state
        self.data["updated"] = utc_now()
        self.data.update(extra)
        self.save()

    def record(self, event: str, **extra) -> None:
        events = self.data.setdefault("events", [])
        events.append({"at": utc_now(), "event": event, **extra})
        self.save()

    def save(self) -> None:
        if not self.persist:
            return
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        atomic_write(
            self.path,
            json.dumps(self.data, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )
        esp = self.data.get("esp_mount")
        if esp:
            try:
                atomic_write(
                    Path(esp) / "lcm" / f"journal-{self.id}.json",
                    json.dumps(self.data, indent=2, sort_keys=True) + "\n",
                    mode=0o644,
                )
            except OSError:
                pass

    @classmethod
    def create(cls, system: SystemInfo, target: str, *, persist: bool = True) -> "Journal":
        now = time.strftime("%Y%m%d-%H%M%S")
        journal_id = f"{now}-{target}"
        data = {
            "id": journal_id,
            "lcm": __version__,
            "state": "planned",
            "created": utc_now(),
            "updated": utc_now(),
            "source": system.distro.to_dict(),
            "target": target,
            "target_family": family_of(target),
            "old_subvol": system.storage.root_subvol,
            "pool_device": system.storage.pool_device,
            "pool_uuid": system.storage.pool_uuid,
            "esp_mount": system.storage.esp_mount,
            "esp_device": system.storage.esp_device,
            "luks": system.storage.luks,
            "luks_uuid": system.storage.luks_uuid,
            "events": [],
        }
        journal = cls(id=journal_id, data=data, persist=persist)
        journal.save()
        return journal

    @classmethod
    def load(cls, journal_id: str, root: Path = JOURNAL_ROOT) -> "Journal":
        path = root / journal_id / "journal.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise LcmError(f"journal not found: {journal_id}") from exc
        except json.JSONDecodeError as exc:
            raise LcmError(f"corrupt journal: {path}") from exc
        return cls(id=journal_id, data=data, root=root)

    @classmethod
    def all(cls, root: Path = JOURNAL_ROOT) -> list["Journal"]:
        if not root.is_dir():
            return []
        journals = []
        for candidate in sorted(root.iterdir(), reverse=True):
            if (candidate / "journal.json").exists():
                try:
                    journals.append(cls.load(candidate.name, root))
                except LcmError:
                    continue
        return journals

    @classmethod
    def latest(cls, root: Path = JOURNAL_ROOT) -> "Journal | None":
        for journal in cls.all(root):
            if journal.state not in {"committed", "rolled_back", "failed"}:
                return journal
        journals = cls.all(root)
        return journals[0] if journals else None


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

@dataclass
class FakeResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class Runner:
    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.commands: list[list[str]] = []

    def run(self, cmd, *, check=True, capture=True, env=None):
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        self.commands.append(argv)
        if self.dry_run:
            print("    $ " + shlex.join(argv))
            return FakeResult()
        return run(argv, check=check, capture=capture, env=env)

    def ok(self, cmd):
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        self.commands.append(argv)
        if self.dry_run:
            print("    $ " + shlex.join(argv))
            return True, "", ""
        return run_ok(argv)


@dataclass
class InstallContext:
    system: SystemInfo
    profile: Profile
    target: str
    target_family: str
    journal: Journal
    runner: Runner
    dry_run: bool
    assume_yes: bool
    mirror: str | None = None
    suite: str | None = None
    repo: str | None = None
    repo_key: str | None = None
    extra_packages: list[str] = field(default_factory=list)
    meta_packages: list[str] = field(default_factory=list)
    capture: dict = field(default_factory=dict)
    pool_mount: Path = POOL_MOUNT
    target_root: Path = TARGET_ROOT
    old_subvol: str = "@"
    new_subvol: str = ""
    new_boot_subvol: str = ""
    mounted: list[Path] = field(default_factory=list)
    new_entry: str | None = None
    old_entry: str | None = None
    boot_next: bool = False


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------

def _required_tools(family: str) -> list[str]:
    missing: list[str] = []
    for tool in ("btrfs", "mount", "chroot", "efibootmgr", "tar"):
        if not have(tool):
            missing.append(tool)

    if family == "debian":
        if not have("mmdebstrap") and not have("debootstrap"):
            missing.append("mmdebstrap (or debootstrap)")
    elif family == "fedora":
        if not have("dnf"):
            missing.append("dnf")
    elif family == "arch":
        # pacstrap is preferred, but a Fedora host will not have it.  The
        # official Arch bootstrap tarball only needs curl, tar and zstd.
        if not have("pacstrap"):
            for tool in ("curl", "zstd"):
                if not have(tool):
                    missing.append(tool)
    elif family == "suse":
        if not have("zypper"):
            missing.append("zypper")
    return missing


def preflight(ctx: InstallContext) -> None:
    system = ctx.system
    storage = system.storage
    problems: list[str] = []

    if not storage.is_btrfs:
        problems.append("root is not btrfs")
    if not system.boot.uefi:
        problems.append("system is not booted in UEFI mode")
    if not storage.esp_device or not storage.esp_mount:
        problems.append("no EFI System Partition found")
    if storage.multi_device:
        problems.append("multi-device btrfs is not supported in v1")
    if not storage.root_subvol:
        problems.append("root subvolume could not be determined")
    if not storage.home_separate and not storage.home_subvol:
        problems.append(
            "no separate /home. v1 refuses to continue because user data would "
            "live inside the root subvolume that commit deletes"
        )
    if storage.home_separate and not storage.home_uuid:
        problems.append("cannot determine the /home filesystem UUID")
    if storage.esp_free_bytes and storage.esp_free_bytes < 150 * 1024 * 1024:
        problems.append("ESP has under 150 MiB free")
    needed = needed_space_bytes(ctx.profile)
    if storage.free_bytes < needed:
        problems.append(
            f"not enough free space: {human_bytes(storage.free_bytes)} free,"
            f" {human_bytes(needed)} needed"
        )
    if not storage.pool_uuid:
        problems.append("cannot determine the btrfs filesystem UUID")
    missing = _required_tools(ctx.target_family)
    if missing and not ctx.dry_run:
        problems.append("missing tools: " + ", ".join(missing))
    elif missing:
        print(
            "note: missing host tools (a real run would fail): "
            + ", ".join(missing)
        )

    if problems:
        raise LcmError(
            "preflight failed:\n  - " + "\n  - ".join(problems)
        )


# --------------------------------------------------------------------------
# prepare
# --------------------------------------------------------------------------

def _mount_pool(ctx: InstallContext) -> None:
    if not ctx.runner.dry_run:
        ctx.pool_mount.mkdir(parents=True, exist_ok=True)
    if not is_mountpoint(ctx.pool_mount):
        ctx.runner.run(
            ["mount", "-o", "subvolid=5", ctx.system.storage.pool_device, str(ctx.pool_mount)]
        )
        ctx.mounted.append(ctx.pool_mount)


def prepare(ctx: InstallContext) -> None:
    system = ctx.system
    pool = system.storage.pool_device
    if not pool:
        raise LcmError("cannot determine btrfs pool device")

    _mount_pool(ctx)
    backup = f"@lcm-backup-{timestamp()}"
    old_path = ctx.pool_mount / ctx.old_subvol
    if not ctx.runner.dry_run and not old_path.exists():
        raise LcmError(f"root subvolume not found: {old_path}")

    ctx.runner.run(["btrfs", "subvolume", "snapshot", "-r", str(old_path), str(ctx.pool_mount / backup)])
    ctx.journal.record("snapshot", path=backup)
    existing = ctx.pool_mount / ctx.new_subvol
    if not ctx.runner.dry_run and existing.exists():
        raise LcmError(
            f"target subvolume already exists ({ctx.new_subvol}); "
            "run `lcm recover` to clean up an unfinished attempt"
        )
    ctx.runner.run(["btrfs", "subvolume", "create", str(ctx.pool_mount / ctx.new_subvol)])
    ctx.runner.run(
        ["btrfs", "subvolume", "create", str(ctx.pool_mount / ctx.new_boot_subvol)]
    )
    if not ctx.runner.dry_run:
        ctx.target_root.mkdir(parents=True, exist_ok=True)
        (ctx.target_root / "boot").mkdir(parents=True, exist_ok=True)
    ctx.runner.run(
        ["mount", "-o", f"subvol={ctx.new_subvol}", pool, str(ctx.target_root)]
    )
    ctx.mounted.append(ctx.target_root)
    # /boot has its own subvolume: the kernel and initramfs must land there,
    # not in the root subvolume, so fstab and reality agree after reboot.
    ctx.runner.run(
        [
            "mount",
            "-o",
            f"subvol={ctx.new_boot_subvol}",
            pool,
            str(ctx.target_root / "boot"),
        ]
    )
    ctx.mounted.append(ctx.target_root / "boot")
    ctx.journal.set_state("prepared", backup_subvol=backup)


# --------------------------------------------------------------------------
# bootstrap
# --------------------------------------------------------------------------

def _default_mirror(target: str) -> str | None:
    return DEFAULT_MIRRORS.get(target)


def _debian_kernel_package() -> str:
    machine = os.uname().machine
    if machine in {"x86_64", "amd64"}:
        return "linux-image-amd64"
    if machine in {"aarch64", "arm64"}:
        return "linux-image-arm64"
    if machine.startswith("armv7"):
        return "linux-image-armmp"
    return "linux-image-" + machine


def _debian_include(ctx: InstallContext) -> list[str]:
    packages = list(DEBIAN_BASE)
    packages.append(_debian_kernel_package())
    if ctx.system.storage.luks:
        packages.append("cryptsetup-initramfs")
    packages.extend(ctx.extra_packages)
    return packages


def _bootstrap_arch(ctx: InstallContext) -> None:
    """Bootstrap Arch from any Linux host.

    If `pacstrap` exists we use it.  Otherwise we extract the official
    bootstrap tarball and drive pacman inside the chroot, which is exactly
    what pacstrap does and works fine from Fedora.
    """
    root = ctx.target_root
    packages = [*ARCH_BASE, *ctx.extra_packages]
    if ctx.system.storage.luks:
        packages.append("cryptsetup")

    if have("pacstrap"):
        ctx.runner.run(["pacstrap", "-c", str(root), *packages], capture=False)
        return

    cache = Path("/var/lib/lcm/cache")
    if not ctx.runner.dry_run:
        cache.mkdir(parents=True, exist_ok=True)
    archive = cache / "archlinux-bootstrap-x86_64.tar.zst"
    url = ctx.mirror or ARCH_BOOTSTRAP_URL
    if not ctx.runner.dry_run and not archive.exists():
        ctx.runner.run(
            ["curl", "-fL", "--retry", "3", url, "-o", str(archive)],
            capture=False,
        )

    ctx.runner.run(
        [
            "tar",
            "-xpf",
            str(archive),
            "-C",
            str(root),
            "--strip-components=1",
            "--zstd",
        ],
        capture=False,
    )

    if not ctx.runner.dry_run:
        (root / "etc").mkdir(parents=True, exist_ok=True)
        try:
            (root / "etc/resolv.conf").write_text(
                Path("/etc/resolv.conf").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        except OSError:
            pass
        mirrorlist = root / "etc/pacman.d/mirrorlist"
        existing = ""
        if mirrorlist.exists():
            existing = mirrorlist.read_text(encoding="utf-8", errors="replace")
        mirrorlist.write_text(
            "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n" + existing,
            encoding="utf-8",
        )

    binds: list[Path] = []
    for directory in ("dev", "proc", "sys"):
        target = root / directory
        if not ctx.runner.dry_run:
            target.mkdir(parents=True, exist_ok=True)
        if not is_mountpoint(target):
            ctx.runner.run(["mount", "--rbind", f"/{directory}", str(target)])
            binds.append(target)

    try:
        ctx.runner.run(
            ["chroot", str(root), "pacman-key", "--init"], capture=False
        )
        ctx.runner.run(
            ["chroot", str(root), "pacman-key", "--populate", "archlinux"],
            capture=False,
        )
        ctx.runner.run(
            ["chroot", str(root), "pacman", "-Syu", "--noconfirm", *packages],
            capture=False,
        )
    finally:
        for target in reversed(binds):
            if not ctx.runner.dry_run and is_mountpoint(target):
                run_ok(["umount", "-R", str(target)])


def _seed_fedora_repos(root: Path, release: str, *, gpgcheck: bool) -> None:
    """Write minimal Fedora repo files into the target.

    A Fedora host already has these, but a Debian or Arch host running dnf
    does not, so `dnf --installroot` would have nothing to install from.
    """
    check = "1" if gpgcheck else "0"
    base = f"""name=Fedora $releasever - $basearch
metalink=https://mirrors.fedoraproject.org/metalink?repo={{repo}}&arch=$basearch
enabled=1
gpgcheck={check}
countme=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch
"""
    directory = root / "etc/yum.repos.d"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "fedora.repo").write_text(
        "[fedora]\n" + base.format(repo="fedora-$releasever"), encoding="utf-8"
    )
    (directory / "fedora-updates.repo").write_text(
        "[fedora-updates]\n"
        + base.format(repo="updates-released-f$releasever"),
        encoding="utf-8",
    )


def bootstrap(ctx: InstallContext) -> None:
    target = ctx.target
    family = ctx.target_family
    root = str(ctx.target_root)
    suite = ctx.suite or DEFAULT_SUITES.get(target, "")
    mirror = ctx.mirror or _default_mirror(target)

    if family == "debian":
        if not mirror:
            raise LcmError(
                f"no default mirror for {target}; pass --mirror "
                "(for example the distribution's own repository URL)"
            )
        if have("mmdebstrap"):
            argv = [
                "mmdebstrap",
                "--variant=important",
                "--components=main,contrib,non-free,non-free-firmware",
                "--include=" + ",".join(_debian_include(ctx)),
                suite or "stable",
                root,
                mirror,
            ]
        else:
            argv = [
                "debootstrap",
                "--components=main,contrib,non-free,non-free-firmware",
                "--include=" + ",".join(_debian_include(ctx)),
                suite or "stable",
                root,
                mirror,
            ]
        ctx.runner.run(argv, capture=False)

    elif family == "fedora":
        release = ctx.suite or ctx.profile.target.get("release") or "44"
        cross_host = ctx.system.distro.family != "fedora"
        base_packages = list(FEDORA_BASE)
        if ctx.system.storage.luks:
            base_packages.append("cryptsetup")
        if cross_host and not ctx.runner.dry_run:
            _seed_fedora_repos(ctx.target_root, str(release), gpgcheck=False)
        argv = [
            "dnf",
            "--installroot",
            root,
            "--releasever",
            str(release),
            "--setopt=install_weak_deps=False",
        ]
        if cross_host:
            # The target has no keyring until fedora-gpg-keys is installed,
            # so the bootstrap transaction cannot verify signatures.  We turn
            # verification back on immediately afterwards.
            argv.append("--nogpgcheck")
        argv += ["-y", "install", *base_packages, *ctx.extra_packages]
        ctx.runner.run(argv, capture=False)
        if cross_host and not ctx.runner.dry_run:
            _seed_fedora_repos(ctx.target_root, str(release), gpgcheck=True)

    elif family == "arch":
        _bootstrap_arch(ctx)

    elif family == "suse":
        argv = ["zypper", "--root", root, "--non-interactive", "install", *SUSE_BASE, *ctx.extra_packages]
        ctx.runner.run(argv, capture=False)

    else:
        raise LcmError(f"no bootstrap backend for family: {family}")

    ctx.journal.set_state("bootstrapped", suite=suite, mirror=mirror)


# --------------------------------------------------------------------------
# configure
# --------------------------------------------------------------------------

def _fstab(ctx: InstallContext) -> str:
    storage = ctx.system.storage
    lines = [
        "# Generated by lcm.  Do not share this file between installations.",
        f"UUID={storage.pool_uuid} / btrfs subvol={ctx.new_subvol},compress=zstd,noatime 0 0",
        f"UUID={storage.pool_uuid} /boot btrfs subvol={ctx.new_boot_subvol},compress=zstd,noatime 0 0",
    ]
    if storage.home_separate and storage.home_uuid:
        if storage.home_subvol:
            lines.append(
                f"UUID={storage.home_uuid} /home btrfs subvol={storage.home_subvol},"
                "compress=zstd,noatime 0 0"
            )
        else:
            fstype = storage.home_fstype or "auto"
            lines.append(f"UUID={storage.home_uuid} /home {fstype} defaults 0 2")
    if storage.esp_uuid:
        lines.append(
            f"UUID={storage.esp_uuid} /boot/efi vfat umask=0077,shortname=winnt 0 2"
        )
    return "\n".join(lines) + "\n"


def _mount_binds(ctx: InstallContext) -> None:
    root = ctx.target_root
    for directory in ("dev", "proc", "sys", "run"):
        target = root / directory
        if not ctx.runner.dry_run:
            target.mkdir(parents=True, exist_ok=True)
        if not is_mountpoint(target):
            ctx.runner.run(["mount", "--rbind", f"/{directory}", str(target)])
            ctx.mounted.append(target)

    esp = ctx.system.storage.esp_device
    if esp:
        esp_target = root / "boot/efi"
        if not ctx.runner.dry_run:
            esp_target.mkdir(parents=True, exist_ok=True)
        if not is_mountpoint(esp_target):
            ctx.runner.run(["mount", esp, str(esp_target)])
            ctx.mounted.append(esp_target)

    storage = ctx.system.storage
    if storage.home_separate and storage.home_uuid:
        home_target = root / "home"
        if not ctx.runner.dry_run:
            home_target.mkdir(parents=True, exist_ok=True)
        if not is_mountpoint(home_target):
            options = ["-o", f"subvol={storage.home_subvol}"] if storage.home_subvol else []
            ctx.runner.run(
                ["mount", *options, f"UUID={storage.home_uuid}", str(home_target)]
            )
            ctx.mounted.append(home_target)


def _unmount(ctx: InstallContext) -> None:
    for mount in reversed(ctx.mounted):
        if ctx.runner.dry_run or not is_mountpoint(mount):
            continue
        run_ok(["umount", "-R", str(mount)])
    ctx.mounted.clear()


def _chroot(ctx: InstallContext, argv: list[str], *, env=None, capture=True):
    return ctx.runner.run(["chroot", str(ctx.target_root), *argv], env=env, capture=capture)


def _read_hostname() -> str:
    try:
        value = Path("/etc/hostname").read_text(encoding="utf-8").strip()
        if value:
            return value.splitlines()[0]
    except OSError:
        pass
    return os.uname().nodename or "localhost"


def _usable_resolv_conf() -> str:
    """Return nameservers that work inside a chroot.

    A systemd-resolved host points /etc/resolv.conf at 127.0.0.53, which is
    unreachable from inside `chroot` because resolved is not running there.
    Filter loopback addresses and fall back to public resolvers.
    """
    servers: list[str] = []
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8")
    except OSError:
        text = ""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            server = fields[1]
            if not (
                server.startswith("127.")
                or server in {"::1", "0.0.0.0"}
            ):
                servers.append(server)
    if not servers:
        servers = ["1.1.1.1", "9.9.9.9"]
    seen: list[str] = []
    for server in servers:
        if server not in seen:
            seen.append(server)
    return "\n".join(f"nameserver {server}" for server in seen) + "\n"


def _write_base_files(ctx: InstallContext) -> None:
    if ctx.runner.dry_run:
        print("    (dry-run) write /etc/fstab, /etc/hostname, /etc/localtime, /etc/resolv.conf")
        return
    root = ctx.target_root
    atomic_write(root / "etc/fstab", _fstab(ctx), mode=0o644)

    atomic_write(root / "etc/hostname", _read_hostname() + "\n", mode=0o644)

    zoneinfo = root / "etc/localtime"
    try:
        target = os.readlink("/etc/localtime")
    except OSError:
        target = ""
    if zoneinfo.exists() or zoneinfo.is_symlink():
        if not ctx.runner.dry_run:
            zoneinfo.unlink()
    if not ctx.runner.dry_run:
        zoneinfo.parent.mkdir(parents=True, exist_ok=True)
        try:
            zoneinfo.symlink_to(target or "/usr/share/zoneinfo/UTC")
        except OSError:
            pass

    resolv = root / "etc/resolv.conf"
    if not ctx.runner.dry_run:
        resolv.parent.mkdir(parents=True, exist_ok=True)
        try:
            if resolv.exists() or resolv.is_symlink():
                resolv.unlink()
            resolv.write_text(_usable_resolv_conf(), encoding="utf-8")
        except OSError:
            pass


def _write_selinux_relabel(ctx: InstallContext) -> None:
    """Mark a Fedora target for a first-boot SELinux relabel.

    Roots assembled with dnf --installroot commonly have unlabeled files.
    Booting enforcing with those labels can break login and services, so the
    target's own autorelabel service must run once before validation.
    """
    if ctx.target_family != "fedora":
        return
    marker = ctx.target_root / ".autorelabel"
    if ctx.runner.dry_run:
        print("    (dry-run) mark the target for an SELinux relabel (/.autorelabel)")
        return
    atomic_write(marker, "", mode=0o600)
    ctx.journal.record("selinux", autorelabel=True)
    print(
        "    SELinux: wrote /.autorelabel; the first boot relabels and may reboot once"
    )


def _add_repo(ctx: InstallContext) -> None:
    """Add a target overlay repository (Debian family) before installing."""
    if not ctx.repo:
        return
    if ctx.target_family != "debian":
        raise LcmError("--repo is only supported for Debian-family targets")
    if ctx.runner.dry_run:
        print(f"    (dry-run) add repository: {ctx.repo}")
        return
    atomic_write(
        ctx.target_root / "etc/apt/sources.list.d/lcm-target.list",
        ctx.repo.strip() + "\n",
        mode=0o644,
    )
    if ctx.repo_key:
        key = ctx.repo_key.strip()
        if key.endswith(".deb"):
            destination = "/tmp/lcm-keyring.deb"
            ctx.runner.run(
                ["chroot", str(ctx.target_root), "curl", "-fsSL", key, "-o", destination],
                capture=False,
            )
            ctx.runner.run(
                ["chroot", str(ctx.target_root), "dpkg", "-i", destination], capture=False
            )
        else:
            destination = "/etc/apt/trusted.gpg.d/lcm-target.asc"
            ctx.runner.run(
                ["chroot", str(ctx.target_root), "curl", "-fsSL", key, "-o", destination],
                capture=False,
            )
    ctx.runner.run(
        ["chroot", str(ctx.target_root), "apt-get", "update"], capture=False
    )


GROUP_ALIASES = {
    # source group -> alternatives to try on the target, in order
    "wheel": ("sudo", "wheel"),
    "sudo": ("wheel", "sudo"),
    "adm": ("adm", "wheel"),
    "plugdev": ("plugdev", "wheel"),
}


def _shadow_hash(user: str) -> str | None:
    try:
        for line in Path("/etc/shadow").read_text(encoding="utf-8").splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[0] == user:
                value = fields[1]
                if value and not value.startswith(("!", "*")):
                    return value
    except OSError:
        pass
    return None


def _create_users(ctx: InstallContext) -> None:
    for user in ctx.profile.users:
        existing_ok, existing_out, _ = ctx.runner.ok(
            ["chroot", str(ctx.target_root), "getent", "passwd", user.name]
        )
        if existing_ok and existing_out.strip():
            continue
        groups: list[str] = []
        for group in user.groups:
            candidates = GROUP_ALIASES.get(group, (group,))
            for candidate in candidates:
                ok, _, _ = ctx.runner.ok(
                    ["chroot", str(ctx.target_root), "getent", "group", candidate]
                )
                if ok:
                    if candidate not in groups:
                        groups.append(candidate)
                    break
        argv = ["useradd", "-m", "-U", "-s", user.shell or "/bin/bash"]
        if user.uid is not None:
            argv += ["-u", str(user.uid)]
        if groups:
            argv += ["-G", ",".join(groups)]
        argv.append(user.name)
        ctx.runner.run(["chroot", str(ctx.target_root), *argv], capture=False)

        # Carry the password hash across so the same login keeps working.
        # The hash never leaves the machine and is written with argv (no shell).
        password_hash = _shadow_hash(user.name)
        if password_hash:
            ctx.runner.run(
                [
                    "chroot",
                    str(ctx.target_root),
                    "usermod",
                    "-p",
                    password_hash,
                    user.name,
                ],
                capture=False,
            )
        else:
            # Never leave an account with an empty password.  Locking is the
            # safe fallback when /etc/shadow cannot be read.
            ctx.runner.run(
                ["chroot", str(ctx.target_root), "passwd", "-l", user.name],
                capture=False,
            )


def _chroot_install(
    ctx: InstallContext, names: list[str], env: dict[str, str]
) -> list[str]:
    """Install inside the chroot, tolerating package names the target lacks."""
    if not names:
        return []
    batch = ["chroot", str(ctx.target_root), *pkgs.install_command(ctx.target_family, names)]
    try:
        ctx.runner.run(batch, env=env, capture=False)
        return []
    except LcmError:
        if ctx.runner.dry_run:
            return []
        failed: list[str] = []
        for name in names:
            single = [
                "chroot",
                str(ctx.target_root),
                *pkgs.install_command(ctx.target_family, [name]),
            ]
            try:
                ctx.runner.run(single, env=env, capture=False)
            except LcmError:
                failed.append(name)
        return failed


def _chroot_flatpak(ctx: InstallContext, app_ids: list[str]) -> list[str]:
    if not app_ids:
        return []
    batch = [
        "chroot",
        str(ctx.target_root),
        *pkgs.flatpak_install_command(app_ids),
    ]
    try:
        ctx.runner.run(batch, capture=False)
        return []
    except LcmError:
        if ctx.runner.dry_run:
            return []
        failed: list[str] = []
        for app_id in app_ids:
            single = [
                "chroot",
                str(ctx.target_root),
                *pkgs.flatpak_install_command([app_id]),
            ]
            try:
                ctx.runner.run(single, capture=False)
            except LcmError:
                failed.append(app_id)
        return failed


def _install_packages(
    ctx: InstallContext,
) -> tuple[list[str], list[str], list[str], list[str]]:
    database = Database()
    profile = ctx.profile
    native: list[str] = []
    flatpak: list[str] = []
    unknown: list[str] = []
    excluded = {str(item) for item in profile.packages.exclude}

    for canonical in profile.packages.native:
        if canonical in excluded:
            continue
        resolution = database.resolve(canonical, ctx.target_family, ctx.target)
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
        resolution = database.resolve_raw(
            name,
            str(item.get("family") or profile.source.get("family") or ""),
            ctx.target_family,
            source_distro=profile.source.get("distro"),
            target_distro=ctx.target,
        )
        if resolution.native:
            native.append(resolution.native)
        elif resolution.flatpak:
            flatpak.append(resolution.flatpak)
        else:
            unknown.append(name)

    flatpak.extend(profile.packages.flatpak)
    native.extend(ctx.meta_packages)
    native = sorted(set(native))
    flatpak = sorted(set(flatpak))

    if flatpak and "flatpak" not in native:
        native.append("flatpak")

    update = pkgs.update_command(ctx.target_family)
    env = dict(os.environ)
    if ctx.target_family == "debian":
        env["DEBIAN_FRONTEND"] = "noninteractive"
    if update:
        ctx.runner.run(["chroot", str(ctx.target_root), *update], env=env, capture=False)
    failed = _chroot_install(ctx, native, env)
    if flatpak:
        ctx.runner.run(
            [
                "chroot",
                str(ctx.target_root),
                "flatpak",
                "remote-add",
                "--if-not-exists",
                "flathub",
                "https://flathub.org/repo/flathub.flatpakrepo",
            ],
            capture=False,
        )
        failed.extend(_chroot_flatpak(ctx, flatpak))
    return native, flatpak, unknown, failed


def _rebuild_initramfs(ctx: InstallContext) -> None:
    if ctx.target_family == "debian":
        ctx.runner.run(["chroot", str(ctx.target_root), "update-initramfs", "-u", "-k", "all"], capture=False)
    elif ctx.target_family == "fedora":
        ctx.runner.run(["chroot", str(ctx.target_root), "dracut", "-f", "--regenerate-all"], capture=False)
    elif ctx.target_family == "arch":
        ctx.runner.run(["chroot", str(ctx.target_root), "mkinitcpio", "-P"], capture=False)
    elif ctx.target_family == "suse":
        ctx.runner.run(["chroot", str(ctx.target_root), "dracut", "-f"], capture=False)


def _initrd_names(kernel_name: str) -> list[str]:
    # `vmlinuz` plus a suffix: "" (generic), "-6.2.0" (Fedora), or "-linux"
    # (Arch).  Derive the initramfs name from the exact kernel name so a stale
    # initramfs for another version can never be paired with it.
    suffix = kernel_name[len("vmlinuz") :]
    names: list[str] = []
    if suffix:
        names.extend(
            [
                f"initrd.img{suffix}",
                f"initramfs{suffix}.img",
                f"initrd{suffix}",
            ]
        )
    names.extend(["initramfs.img", "initrd.img", "initrd"])
    return names


def _pick_kernel(root: Path) -> tuple[Path, Path]:
    """Pick the newest real kernel and the initramfs for that exact version.

    Selecting the kernel and initramfs independently by mtime can pair two
    different releases.  Fedora's rescue kernel is also newer by mtime after
    installation, so it must never be chosen as the boot kernel.
    """
    boot = root / "boot"
    kernels = [
        path
        for path in boot.glob("vmlinuz*")
        if path.is_file()
        and "rescue" not in path.name.lower()
        and not path.name.endswith((".old", ".new", ".bak"))
    ]
    if not kernels:
        raise LcmError("no kernel found in target /boot")
    kernels.sort(
        key=lambda path: (path.stat().st_mtime, path.name), reverse=True
    )
    for kernel in kernels:
        for name in _initrd_names(kernel.name):
            initrd = boot / name
            if initrd.is_file():
                return kernel, initrd
    raise LcmError(
        "no initramfs matching the newest kernel found in target /boot: "
        + ", ".join(path.name for path in kernels)
    )


def _kernel_cmdline(ctx: InstallContext) -> str:
    storage = ctx.system.storage
    flags = f"subvol={ctx.new_subvol}"
    if storage.luks and storage.luks_uuid:
        if ctx.target_family in {"debian", "arch"}:
            # initramfs-tools and mkinitcpio both understand cryptdevice=.
            return (
                f"cryptdevice=UUID={storage.luks_uuid}:cryptroot "
                f"root=/dev/mapper/cryptroot rootflags={flags} rw quiet"
            )
        return (
            f"rd.luks.uuid=luks-{storage.luks_uuid} "
            f"root=UUID={storage.pool_uuid} rootflags={flags} rw quiet"
        )
    return f"root=UUID={storage.pool_uuid} rootflags={flags} rw quiet"


def _prepare_boot_hooks(ctx: InstallContext) -> None:
    """Make the target initramfs able to unlock an encrypted root."""
    storage = ctx.system.storage
    if not storage.luks:
        return
    if ctx.target_family == "arch":
        if ctx.runner.dry_run:
            print("    (dry-run) add `encrypt` to mkinitcpio HOOKS")
            return
        path = ctx.target_root / "etc/mkinitcpio.conf"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            raise LcmError("cannot read /etc/mkinitcpio.conf in the target")
        if "encrypt" not in text.split("HOOKS=", 1)[-1].split("\n", 1)[0]:
            updated = re.sub(
                r"(HOOKS=\([^)]*?)(filesystems)",
                r"\1encrypt \2",
                text,
                count=1,
            )
            if updated == text:
                updated = text.replace("HOOKS=(base", "HOOKS=(base encrypt", 1)
            atomic_write(path, updated, mode=0o644)
    elif ctx.target_family == "debian":
        # cryptsetup-initramfs was installed during bootstrap; nothing else to do.
        return


def _ukify_path(ctx: InstallContext) -> str | None:
    if ctx.runner.dry_run:
        return "ukify"
    root = str(ctx.target_root)
    ok, out, _ = ctx.runner.ok(
        ["chroot", root, "sh", "-c", "command -v ukify 2>/dev/null || true"]
    )
    if ok and out.strip():
        return out.strip().splitlines()[0]
    ok, _, _ = ctx.runner.ok(
        ["chroot", root, "test", "-x", "/usr/lib/systemd/ukify"]
    )
    return "/usr/lib/systemd/ukify" if ok else None


def _ensure_ukify(ctx: InstallContext) -> None:
    if ctx.runner.dry_run or _ukify_path(ctx):
        return
    root = str(ctx.target_root)
    attempts: list[list[str]] = []
    if ctx.target_family == "debian":
        attempts = [["apt-get", "install", "-y", "systemd-ukify"]]
    elif ctx.target_family == "fedora":
        attempts = [["dnf", "install", "-y", "systemd-ukify"]]
    elif ctx.target_family == "arch":
        attempts = [["pacman", "-S", "--needed", "--noconfirm", "systemd"]]
    for argv in attempts:
        try:
            ctx.runner.run(["chroot", root, *argv], capture=False)
        except LcmError:
            continue
    if not _ukify_path(ctx):
        raise LcmError(
            "ukify is not available in the target. Debian stable does not ship it; "
            "use a trixie/sid target (PikaOS is sid) or install systemd-ukify from "
            "backports first."
        )


def _build_uki(ctx: InstallContext) -> Path:
    uki_rel = f"EFI/Linux/lcm-{ctx.target}.efi"
    uki_path = ctx.target_root / "boot/efi" / uki_rel
    if ctx.runner.dry_run:
        print(f"    (dry-run) build unified kernel image {uki_rel}")
        return uki_path
    kernel, initrd = _pick_kernel(ctx.target_root)
    uki_path.parent.mkdir(parents=True, exist_ok=True)

    ukify = _ukify_path(ctx)
    if ukify is None:
        raise LcmError("ukify disappeared after installation; cannot build the UKI")

    ctx.runner.run(
        [
            "chroot",
            str(ctx.target_root),
            ukify,
            "build",
            "--linux",
            f"/boot/{kernel.name}",
            "--initrd",
            f"/boot/{initrd.name}",
            "--cmdline",
            _kernel_cmdline(ctx),
            "--output",
            f"/boot/efi/{uki_rel}",
        ],
        capture=False,
    )
    return uki_path


def configure(ctx: InstallContext) -> None:
    _mount_binds(ctx)
    _write_base_files(ctx)
    _add_repo(ctx)
    _create_users(ctx)

    native, flatpak, unknown, failed = _install_packages(ctx)
    ctx.journal.record(
        "packages",
        native=len(native),
        flatpak=len(flatpak),
        unknown=unknown,
        failed=failed,
    )
    if failed:
        print(
            "warning: these packages were not available on the target and were "
            "skipped: " + ", ".join(failed)
        )

    _write_selinux_relabel(ctx)
    _prepare_boot_hooks(ctx)
    _ensure_ukify(ctx)
    _rebuild_initramfs(ctx)
    _build_uki(ctx)
    ctx.journal.set_state(
        "configured",
        packages=native,
        flatpak=flatpak,
        unknown=unknown,
        failed=failed,
    )


# --------------------------------------------------------------------------
# arm
# --------------------------------------------------------------------------

VALIDATION_SCRIPT = """#!/bin/sh
set -u
SUBVOL="{subvol}"
MAX_FAILED={max_failed}
out=/var/lib/lcm
mkdir -p "$out"
ok=1

failed=$(systemctl --failed --no-legend 2>/dev/null | wc -l | tr -d ' ')
[ "$failed" -le "$MAX_FAILED" ] || ok=0

root_ok=0
findmnt -no OPTIONS / 2>/dev/null | grep -q "subvol=/*$SUBVOL" && root_ok=1
[ "$root_ok" = 1 ] || ok=0

net_ok=0
ip route show default 2>/dev/null | grep -q . && net_ok=1

gpu_ok=0
[ -e /dev/dri/card0 ] && gpu_ok=1

audio_ok=1
if command -v wpctl >/dev/null 2>&1; then
    wpctl status 2>/dev/null | grep -qi sink || audio_ok=0
fi

dm_ok=0
systemctl is-active --quiet display-manager 2>/dev/null && dm_ok=1
[ "$dm_ok" = 1 ] || ok=0

printf 'ok=%s\\nfailed_units=%s\\nroot_subvol=%s\\nnetwork=%s\\ngpu=%s\\naudio=%s\\ndisplay_manager=%s\\n' \\
    "$ok" "$failed" "$root_ok" "$net_ok" "$gpu_ok" "$audio_ok" "$dm_ok" > "$out/validation.env"
cp "$out/validation.env" /boot/efi/lcm-validation.env 2>/dev/null || true
rm -f "$out/pending"
"""

VALIDATION_UNIT = """[Unit]
Description=LCM first boot validation
After=graphical.target network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/lcm/pending

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lcm-firstboot-validate
RemainAfterExit=yes

[Install]
WantedBy=graphical.target
"""


def _write_validation(ctx: InstallContext) -> None:
    if ctx.runner.dry_run:
        print("    (dry-run) install lcm-firstboot-validate.service")
        return
    root = ctx.target_root
    max_failed = ctx.profile.validation.max_failed_units
    atomic_write(
        root / "usr/local/sbin/lcm-firstboot-validate",
        VALIDATION_SCRIPT.format(subvol=ctx.new_subvol, max_failed=max_failed),
        mode=0o755,
    )
    atomic_write(
        root / "etc/systemd/system/lcm-firstboot-validate.service",
        VALIDATION_UNIT,
        mode=0o644,
    )
    atomic_write(root / "var/lib/lcm/pending", utc_now() + "\n", mode=0o644)
    ctx.runner.run(
        [
            "chroot",
            str(ctx.target_root),
            "systemctl",
            "enable",
            "lcm-firstboot-validate.service",
        ],
        capture=False,
    )


def _boot_order() -> list[str]:
    ok, out, _ = run_ok(["efibootmgr"])
    if not ok:
        return []
    for line in out.splitlines():
        if line.startswith("BootOrder:"):
            return [
                chunk.strip()
                for chunk in line.split(":", 1)[1].split(",")
                if chunk.strip()
            ]
    return []


def _set_boot_order(order: list[str]) -> None:
    if order:
        run(["efibootmgr", "-o", ",".join(order)])


def _add_boot_entry(ctx: InstallContext) -> str:
    if ctx.runner.dry_run:
        return "0000"
    storage = ctx.system.storage
    if not storage.esp_disk or storage.esp_partition is None:
        raise LcmError("cannot determine ESP disk/partition for efibootmgr")
    loader = f"\\EFI\\Linux\\lcm-{ctx.target}.efi"
    proc = ctx.runner.run(
        [
            "efibootmgr",
            "-c",
            "-d",
            storage.esp_disk,
            "-p",
            str(storage.esp_partition),
            "-L",
            f"LCM {ctx.target}",
            "-l",
            loader,
        ]
    )
    match = re.search(r"Boot([0-9A-Fa-f]{4})\*?\s+LCM", proc.stdout or "")
    if not match:
        raise LcmError("could not parse the new firmware boot entry from efibootmgr")
    number = match.group(1).upper()

    order = _boot_order()
    order = [entry for entry in order if entry != number]
    order.append(number)
    ctx.runner.run(["efibootmgr", "-o", ",".join(order)])
    return number


def _old_boot_entry(
    boot: Boot, new_entry: str | None, source_name: str = ""
) -> str | None:
    """Prefer the entry the firmware says it actually booted.

    Label matching can select a sibling entry with a similar name.  BootCurrent
    identifies the entry that launched the running system, which is exactly the
    one commit should eventually remove.  When the firmware does not report
    BootCurrent, fall back to the running distribution's name, not to whichever
    entry happens to be first in BootOrder.
    """
    current = boot.boot_current
    if (
        current
        and current != new_entry
        and any(entry.number == current for entry in boot.entries)
    ):
        return current

    needles: list[str] = []
    for word in [source_name, *source_name.split()]:
        needle = word.strip().lower()
        if needle and needle not in needles:
            needles.append(needle)
    for entry in boot.entries:
        if entry.number == new_entry:
            continue
        if any(needle in entry.label.lower() for needle in needles):
            return entry.number
    return None


def _set_boot_next(ctx: InstallContext, number: str) -> None:
    """Try the new entry once, falling back to the saved BootOrder on failure."""
    if ctx.runner.dry_run:
        print(f"    $ efibootmgr -n {number}")
        ctx.boot_next = True
        return
    ok, _, err = ctx.runner.ok(["efibootmgr", "-n", number])
    if ok:
        ctx.boot_next = True
        ctx.journal.record("boot_next", entry=number)
    else:
        print(
            "warning: could not set BootNext; pick the LCM entry in the firmware "
            f"menu instead ({err.strip()})"
        )


def arm(ctx: InstallContext) -> None:
    _write_validation(ctx)
    number = _add_boot_entry(ctx)
    ctx.new_entry = number
    old_entry = _old_boot_entry(
        ctx.system.boot, number, ctx.system.distro.name
    )
    ctx.old_entry = old_entry
    _set_boot_next(ctx, number)
    ctx.journal.set_state(
        "armed",
        new_subvol=ctx.new_subvol,
        new_boot_subvol=ctx.new_boot_subvol,
        new_boot_entry=number,
        old_boot_entry=old_entry,
        kernel_cmdline=_kernel_cmdline(ctx),
    )


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------

def _export_bundle(ctx: InstallContext) -> Path | None:
    if ctx.dry_run:
        print("    (would write a pre-replace state bundle to /var/lib/lcm/bundles)")
        return None
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(BUNDLE_DIR, 0o700)
    except OSError:
        pass
    database = Database()
    resolutions = []
    for canonical in ctx.profile.packages.native:
        resolutions.append(
            database.resolve(canonical, ctx.target_family, ctx.target).to_dict()
        )
    for item in ctx.profile.packages.raw:
        name = str(item.get("name", ""))
        if name:
            resolutions.append(
                database.resolve_raw(
                    name,
                    str(item.get("family") or ctx.profile.source.get("family") or ""),
                    ctx.target_family,
                    source_distro=ctx.profile.source.get("distro"),
                    target_distro=ctx.target,
                ).to_dict()
            )
    packages_data = {
        "source_family": ctx.system.distro.family,
        "target_family": ctx.target_family,
        "capture": ctx.capture
        or {
            "manager": "lcm",
            "fidelity": "high",
            "notes": ["profile supplied explicitly; no system capture performed"],
        },
        "resolutions": resolutions,
        "stats": {
            "total": len(resolutions),
            "mapped": sum(1 for item in resolutions if item.get("native")),
        },
    }
    out = BUNDLE_DIR / suggested_name(ctx.profile)
    return create_bundle(out, ctx.profile, packages_data, ctx.system)


def replace(
    system: SystemInfo,
    profile: Profile,
    target: str,
    *,
    assume_yes: bool = False,
    dry_run: bool = False,
    mirror: str | None = None,
    suite: str | None = None,
    repo: str | None = None,
    repo_key: str | None = None,
    extra_packages: list[str] | None = None,
    meta_packages: list[str] | None = None,
    capture: dict | None = None,
) -> Journal:
    family = family_of(target)
    if not dry_run:
        require_root("lcm replace")

    runner = Runner(dry_run=dry_run)
    journal = Journal.create(system, target, persist=not dry_run)
    old_subvol = system.storage.root_subvol or "@"
    ctx = InstallContext(
        system=system,
        profile=profile,
        target=target,
        target_family=family,
        journal=journal,
        runner=runner,
        dry_run=dry_run,
        assume_yes=assume_yes,
        mirror=mirror,
        suite=suite,
        repo=repo,
        repo_key=repo_key,
        extra_packages=extra_packages or [],
        meta_packages=meta_packages or [],
        capture=capture or {},
        old_subvol=old_subvol,
        new_subvol=f"@{target}",
        new_boot_subvol=f"@{target}-boot",
    )

    assessment = analyze(system, target, Database(), profile)
    print(render_plan(assessment, Style(not dry_run)))
    print()
    if assessment.errors:
        raise LcmError(
            "assessment has blocking errors; fix them before replacing:\n  - "
            + "\n  - ".join(item.message for item in assessment.errors)
        )

    if not dry_run and not assume_yes:
        if not confirm(
            f"Replace {system.distro.pretty} with {target} using subvolume {ctx.new_subvol}?",
            assume_yes=False,
        ):
            raise LcmError("aborted")

    try:
        preflight(ctx)
        bundle_path = _export_bundle(ctx)
        if bundle_path:
            ctx.journal.record("bundle", path=str(bundle_path))
        prepare(ctx)
        bootstrap(ctx)
        configure(ctx)
        arm(ctx)
        ctx.journal.record("armed", new_entry=ctx.new_entry, old_entry=ctx.old_entry)
    except Exception as exc:
        journal.set_state("failed", error=str(exc))
        raise
    finally:
        _unmount(ctx)

    print()
    print(f"Target built in subvolume {ctx.new_subvol}.")
    print(f"Firmware entry: {ctx.new_entry or '(dry run)'}  (old entry: {ctx.old_entry or 'unknown'})")
    if ctx.boot_next:
        print("A one-shot BootNext points at the new entry; the old system stays")
        print("first in BootOrder, so a failed boot falls back to it automatically.")
    else:
        print("The old system is still the default boot entry.")
    print()
    print("Next:")
    print("  1. reboot; the new system is tried once automatically")
    print('     (or pick "LCM <target>" in the firmware menu with F12)')
    print("  2. confirm networking, GPU and audio work; a Fedora target relabels")
    print("     SELinux on first boot and may reboot once by itself")
    print("  3. run `sudo lcm commit` to delete the old subvolume")
    print("  4. or run `sudo lcm rollback` to make the old system default again")
    return journal


# --------------------------------------------------------------------------
# commit / rollback / recover
# --------------------------------------------------------------------------

def _read_validation() -> dict[str, str]:
    for path in (
        Path("/var/lib/lcm/validation.env"),
        Path("/boot/efi/lcm-validation.env"),
    ):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        values = {}
        for line in text.splitlines():
            key, _, value = line.partition("=")
            if key:
                values[key.strip()] = value.strip()
        return values
    return {}


def commit(*, assume_yes: bool = False, keep_old: bool = False, force: bool = False) -> None:
    require_root("lcm commit")
    system = detect_system()
    candidates = [
        item for item in Journal.all() if item.state in {"armed", "validated"}
    ]
    journal = candidates[0] if candidates else None
    if journal is None:
        raise LcmError("no armed journal found; nothing to commit")

    new_subvol = str(journal.data.get("new_subvol") or "")
    if not new_subvol:
        raise LcmError("journal has no target subvolume")
    if system.storage.root_subvol != new_subvol:
        raise LcmError(
            f"this command must run from the new system (root subvol={new_subvol});"
            f" current root subvol={system.storage.root_subvol}"
        )

    validation = _read_validation()
    if validation.get("ok") != "1" and not force:
        raise LcmError(
            "first-boot validation did not pass: "
            + json.dumps(validation)
            + "\nre-run with --force only if you have checked the system yourself"
        )

    if not assume_yes:
        if not confirm(
            f"Delete the old subvolume {journal.data.get('old_subvol')} and its boot entry?",
            assume_yes=False,
        ):
            raise LcmError("aborted")

    pool = system.storage.pool_device
    if not pool:
        raise LcmError("cannot determine pool device")
    POOL_MOUNT.mkdir(parents=True, exist_ok=True)
    mounted = False
    if not is_mountpoint(POOL_MOUNT):
        run(["mount", "-o", "subvolid=5", pool, str(POOL_MOUNT)])
        mounted = True
    try:
        if not keep_old:
            old = POOL_MOUNT / str(journal.data.get("old_subvol") or "@")
            if old.exists():
                run(["btrfs", "subvolume", "delete", str(old)])
        old_entry = journal.data.get("old_boot_entry")
        if old_entry:
            run_ok(["efibootmgr", "-b", str(old_entry), "-B"])
    finally:
        if mounted:
            run_ok(["umount", str(POOL_MOUNT)])

    new_entry = journal.data.get("new_boot_entry")
    order = _boot_order()
    if new_entry:
        order = [new_entry] + [entry for entry in order if entry != new_entry]
        _set_boot_order(order)

    journal.set_state("committed", commit_time=utc_now(), kept_old=keep_old)
    print("Committed. The old root subvolume is gone." if not keep_old else "Committed; old subvolume kept.")


def rollback(*, entry: str | None = None) -> None:
    require_root("lcm rollback")
    journal = Journal.latest()
    old_entry = entry or (journal.data.get("old_boot_entry") if journal else None)
    if not old_entry:
        raise LcmError(
            "no old boot entry recorded; pass --entry <BootNNNN> explicitly"
        )
    order = _boot_order()
    order = [old_entry] + [item for item in order if item != old_entry]
    _set_boot_order(order)
    # A pending one-shot BootNext would otherwise override this order on the
    # next boot and try the new system again.
    run_ok(["efibootmgr", "-N"])
    if journal:
        journal.set_state("rolled_back", rolled_back_at=utc_now())
    print(
        f"Boot order now starts with {old_entry} and any one-shot BootNext is cleared."
    )
    print("Reboot to return to the old system.")


def recover(*, cleanup: str | None = None, assume_yes: bool = False) -> str:
    journals = Journal.all()
    if not journals:
        return "No journals found."
    if cleanup is None:
        lines = ["Journals:"]
        for journal in journals:
            lines.append(
                f"  {journal.id}  state={journal.state}  target={journal.data.get('new_subvol', '?')}"
            )
        lines.append("")
        lines.append("Use `lcm recover --cleanup <id>` to remove an unfinished target.")
        return "\n".join(lines)

    journal = Journal.load(cleanup)
    if journal.state in {"armed", "validated", "committed"}:
        raise LcmError(
            f"journal {cleanup} is in state {journal.state}; refusing automatic cleanup"
        )
    require_root("lcm recover --cleanup")
    if not assume_yes:
        if not confirm(
            f"Delete target subvolume {journal.data.get('new_subvol')}?",
            assume_yes=False,
        ):
            raise LcmError("aborted")

    pool = journal.data.get("pool_device")
    subvol = journal.data.get("new_subvol")
    if not pool or not subvol:
        raise LcmError("journal is missing pool or subvolume information")
    POOL_MOUNT.mkdir(parents=True, exist_ok=True)
    mounted = False
    if not is_mountpoint(POOL_MOUNT):
        run(["mount", "-o", "subvolid=5", pool, str(POOL_MOUNT)])
        mounted = True
    try:
        for name in (subvol, str(journal.data.get("new_boot_subvol") or "")):
            if not name:
                continue
            path = POOL_MOUNT / name
            if path.exists():
                run(["btrfs", "subvolume", "delete", str(path)])
    finally:
        if mounted:
            run_ok(["umount", str(POOL_MOUNT)])
    journal.set_state("failed", recovered_at=utc_now())
    return f"Removed {subvol}. The old system is untouched."
