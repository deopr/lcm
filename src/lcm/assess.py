"""Read-only risk assessment and migration planning.

`lcm check` and `lcm plan` share this engine.  Neither writes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lcm.detect import SystemInfo, family_of
from lcm.mapping import Database, MappingStats, Resolution
from lcm.profile import Profile
from lcm.util import Style, human_bytes, indent, parse_size

BASE_INSTALL_BYTES = parse_size("12GiB")
PER_PACKAGE_BYTES = parse_size("24MiB")
FLATPAK_BYTES = parse_size("2GiB")
MIN_ESP_BYTES = parse_size("150MiB")


@dataclass
class Finding:
    level: str  # ok | info | warn | error
    code: str
    message: str
    hint: str = ""


@dataclass
class PackageAnalysis:
    stats: MappingStats
    flatpak: list[str]
    capture: dict
    resolutions: list[Resolution] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "stats": self.stats.to_dict(),
            "flatpak": self.flatpak,
            "capture": self.capture,
        }


@dataclass
class Assessment:
    system: SystemInfo
    target_id: str
    target_family: str
    profile: Profile
    findings: list[Finding]
    packages: PackageAnalysis
    needed_bytes: int
    verdict: str  # green | yellow | red

    @property
    def errors(self) -> list[Finding]:
        return [item for item in self.findings if item.level == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [item for item in self.findings if item.level == "warn"]

    def to_dict(self) -> dict:
        return {
            "source": self.system.distro.to_dict(),
            "target": {"id": self.target_id, "family": self.target_family},
            "verdict": self.verdict,
            "needed_bytes": self.needed_bytes,
            "free_bytes": self.system.storage.free_bytes,
            "packages": self.packages.to_dict(),
            "findings": [item.__dict__ for item in self.findings],
        }


def _level_rank(level: str) -> int:
    return {"ok": 0, "info": 1, "warn": 2, "error": 3}.get(level, 3)


def needed_space_bytes(profile: Profile) -> int:
    count = (
        len(profile.packages.native)
        + len(profile.packages.raw)
        + len(profile.packages.flatpak)
    )
    total = BASE_INSTALL_BYTES + PER_PACKAGE_BYTES * count
    if profile.packages.flatpak:
        total += FLATPAK_BYTES
    return total


def _package_analysis(
    system: SystemInfo,
    profile: Profile,
    database: Database,
    target_id: str,
    target_family: str,
    capture: dict,
) -> PackageAnalysis:
    stats = MappingStats()
    resolutions: list[Resolution] = []

    for canonical in profile.packages.native:
        resolution = database.resolve(canonical, target_family, target_id)
        stats.add(resolution)
        resolutions.append(resolution)

    for item in profile.packages.raw:
        name = str(item.get("name", ""))
        if not name:
            continue
        source_family = str(item.get("family") or system.distro.family)
        resolution = database.resolve_raw(
            name,
            source_family,
            target_family,
            source_distro=system.distro.id,
            target_distro=target_id,
        )
        stats.add(resolution)
        resolutions.append(resolution)

    return PackageAnalysis(
        stats=stats,
        flatpak=list(profile.packages.flatpak),
        capture=capture,
        resolutions=resolutions,
    )


def analyze(
    system: SystemInfo,
    target_id: str,
    database: Database,
    profile: Profile,
    capture: dict | None = None,
) -> Assessment:
    target_family = family_of(target_id)
    findings: list[Finding] = []
    storage = system.storage

    # -- storage ---------------------------------------------------------
    if not storage.is_btrfs:
        findings.append(
            Finding(
                "error",
                "storage.fstype",
                f"root filesystem is {storage.root_fstype or 'unknown'}, not btrfs",
                "v1 builds the new system as a btrfs subvolume. ext4/LVM support is not implemented.",
            )
        )
    else:
        findings.append(
            Finding(
                "ok",
                "storage.btrfs",
                f"btrfs root on {storage.root_source}"
                + (f" (subvol={storage.root_subvol})" if storage.root_subvol else ""),
            )
        )
    if storage.multi_device:
        findings.append(
            Finding(
                "error",
                "storage.multi_device",
                "btrfs pool spans multiple devices",
                "multi-device pools are not supported in v1.",
            )
        )
    if storage.luks:
        findings.append(
            Finding(
                "info",
                "storage.luks",
                "LUKS container detected; it will be reused, never reformatted",
                f"mapper: {storage.luks_device or 'unknown'}",
            )
        )
    if not storage.root_subvol:
        findings.append(
            Finding(
                "warn",
                "storage.subvol_unknown",
                "cannot determine the root subvolume name",
                "the installer may refuse to guess; mount / with an explicit subvol= option.",
            )
        )

    # -- boot ------------------------------------------------------------
    if not system.boot.uefi:
        findings.append(
            Finding(
                "error",
                "boot.bios",
                "system booted in BIOS/CSM mode",
                "v1 registers the new system as a firmware boot entry and requires UEFI.",
            )
        )
    else:
        findings.append(Finding("ok", "boot.uefi", "UEFI firmware detected"))
    if not storage.esp_device or not storage.esp_mount:
        findings.append(
            Finding(
                "error",
                "boot.esp",
                "no EFI System Partition found",
                "an ESP mounted at /boot/efi or /efi is required.",
            )
        )
    else:
        findings.append(
            Finding(
                "ok",
                "boot.esp",
                f"ESP {storage.esp_device} at {storage.esp_mount}"
                f" ({human_bytes(storage.esp_free_bytes)} free)",
            )
        )
        if storage.esp_free_bytes < MIN_ESP_BYTES:
            findings.append(
                Finding(
                    "error",
                    "boot.esp_space",
                    f"ESP has less than {human_bytes(MIN_ESP_BYTES)} free",
                    "a unified kernel image needs room; free space or enlarge the ESP.",
                )
            )
    if system.boot.secure_boot:
        findings.append(
            Finding(
                "warn",
                "boot.secure_boot",
                "Secure Boot is enabled",
                "the generated UKI is unsigned. Enroll a MOK or disable Secure Boot for the first boot.",
            )
        )
    if system.boot.uefi:
        findings.append(
            Finding(
                "info",
                "boot.independent",
                "the target gets its own firmware boot entry; the existing bootloader is not modified",
            )
        )

    # -- space -----------------------------------------------------------
    needed = needed_space_bytes(profile)
    if storage.free_bytes < needed:
        findings.append(
            Finding(
                "error",
                "space.free",
                f"not enough free space: {human_bytes(storage.free_bytes)} available,"
                f" about {human_bytes(needed)} needed",
                "free space or build the target on a larger disk.",
            )
        )
    else:
        findings.append(
            Finding(
                "ok",
                "space.free",
                f"{human_bytes(storage.free_bytes)} free, about {human_bytes(needed)} needed",
            )
        )

    # -- hardware --------------------------------------------------------
    if "nvidia" in system.hardware.gpu_vendors:
        findings.append(
            Finding(
                "warn",
                "hardware.nvidia",
                "NVIDIA GPU detected; the driver is out-of-tree",
                "proprietary driver packages are not migrated. Reinstall the target's NVIDIA stack after first boot.",
            )
        )
    elif system.hardware.gpu_vendors:
        findings.append(
            Finding(
                "ok",
                "hardware.gpu",
                f"GPU: {', '.join(system.hardware.gpus)} (in-tree driver)",
            )
        )
    if system.hardware.out_of_tree_modules:
        findings.append(
            Finding(
                "warn",
                "hardware.modules",
                "out-of-tree kernel modules in use: "
                + ", ".join(system.hardware.out_of_tree_modules),
                "these will not survive the hop; plan a target-native replacement.",
            )
        )
    if system.hardware.virtualization:
        findings.append(
            Finding(
                "info",
                "hardware.vm",
                f"running inside {system.hardware.virtualization}",
                "ideal for testing the replace pipeline before touching bare metal.",
            )
        )

    # -- packages --------------------------------------------------------
    packages = _package_analysis(
        system, profile, database, target_id, target_family, capture or {}
    )
    stats = packages.stats
    raw_count = sum(1 for item in profile.packages.raw if item.get("name"))
    if stats.total:
        # Mapping coverage is a quality signal, never a hard blocker: an
        # incomplete mapping means fewer apps get reinstalled automatically,
        # not that the hop is unsafe.  Only structural problems (btrfs, UEFI,
        # ESP, space) are allowed to turn the verdict red.
        level = "ok" if stats.percent >= 80 else "warn"
        detail = (
            f"{stats.mapped}/{stats.total} packages mapped ({stats.percent:.0f}%)"
            f" · {stats.flatpak} via Flatpak · {len(set(stats.unknown))} unmatched"
        )
        findings.append(Finding(level, "packages.mapped", detail))
    if stats.unknown:
        sample = ", ".join(sorted(set(stats.unknown))[:10])
        more = "" if len(set(stats.unknown)) <= 10 else ", ..."
        findings.append(
            Finding(
                "warn",
                "packages.unknown",
                f"no target mapping for: {sample}{more}",
                "these stay in the profile as raw entries; `lcm restore` reports "
                "them on the target so you can install them by hand.",
            )
        )
    if raw_count and stats.total and stats.percent < 80:
        findings.append(
            Finding(
                "info",
                "packages.capture",
                f"{raw_count} captured package name(s) have no canonical mapping yet",
                "the mapping database grows over time; add an entry to "
                "`lcm mapping` data or accept the manual review on the target.",
            )
        )
    if stats.flatpak:
        findings.append(
            Finding(
                "info",
                "packages.flatpak",
                f"{stats.flatpak} package(s) will be installed via Flatpak",
            )
        )
    if (capture or {}).get("fidelity") == "low":
        findings.append(
            Finding(
                "warn",
                "packages.fidelity",
                "package capture fidelity is low",
                "; ".join((capture or {}).get("notes") or ["the source manager could not list user-installed packages"]),
            )
        )
    if target_family == "debian" and "firefox" in stats.by_canonical:
        findings.append(
            Finding(
                "warn",
                "packages.downgrade",
                "firefox maps to Firefox ESR on Debian-family targets (older release channel)",
                "profiles, extensions and DRM behaviour can differ; consider the Flatpak instead.",
            )
        )
    findings.append(
        Finding(
            "info",
            "packages.versions",
            "package version comparison is not performed offline",
            "run `lcm check` again from the target after install, or inspect the target repositories manually.",
        )
    )

    # -- target ----------------------------------------------------------
    if target_family == "unknown":
        findings.append(
            Finding(
                "error",
                "target.unknown",
                f"unknown target distribution: {target_id}",
                "supported families: fedora, debian, arch, suse.",
            )
        )
    if target_id == system.distro.id:
        findings.append(
            Finding(
                "info",
                "target.same",
                "target is the current distribution; this would be a no-op",
            )
        )

    findings.sort(key=lambda item: -_level_rank(item.level))
    if any(item.level == "error" for item in findings):
        verdict = "red"
    elif any(item.level == "warn" for item in findings):
        verdict = "yellow"
    else:
        verdict = "green"

    return Assessment(
        system=system,
        target_id=target_id,
        target_family=target_family,
        profile=profile,
        findings=findings,
        packages=packages,
        needed_bytes=needed,
        verdict=verdict,
    )


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

VERDICT_TEXT = {
    "green": ("GREEN", "go"),
    "yellow": ("YELLOW", "review the warnings, then run `lcm plan`"),
    "red": ("RED", "blocked; fix the errors first"),
}

LEVEL_MARK = {"ok": "ok  ", "info": "info", "warn": "warn", "error": "FAIL"}


def render(assessment: Assessment, style: Style | None = None) -> str:
    style = style or Style(False)
    system = assessment.system
    lines: list[str] = []

    lines.append(style.bold("LCM migration assessment"))
    lines.append(f"Source:   {system.distro.pretty}  ({system.distro.family})")
    lines.append(
        f"Target:   {assessment.target_id}  ({assessment.target_family})"
    )
    lines.append(f"Kernel:   {system.hardware.kernel}")
    lines.append("")
    lines.append(indent(system.summary()))
    lines.append("")

    lines.append(style.bold("Findings"))
    for finding in assessment.findings:
        mark = LEVEL_MARK.get(finding.level, finding.level)
        if finding.level == "error":
            mark = style.red(mark)
        elif finding.level == "warn":
            mark = style.yellow(mark)
        elif finding.level == "ok":
            mark = style.green(mark)
        else:
            mark = style.dim(mark)
        lines.append(f"  [{mark}] {finding.message}")
        if finding.hint:
            lines.append(style.dim(f"         {finding.hint}"))

    stats = assessment.packages.stats
    if stats.total:
        lines.append("")
        lines.append(style.bold("Packages"))
        lines.append(
            f"  {stats.total} total · {stats.native} native · "
            f"{stats.flatpak} flatpak · {len(set(stats.unknown))} unknown"
        )
        if stats.unknown:
            lines.append(
                "  unknown: " + ", ".join(sorted(set(stats.unknown))[:12])
            )

    label, advice = VERDICT_TEXT[assessment.verdict]
    color = {
        "green": style.green,
        "yellow": style.yellow,
        "red": style.red,
    }[assessment.verdict]
    lines.append("")
    lines.append(f"Verdict: {color(label)} - {advice}")
    return "\n".join(lines)


def plan_steps(assessment: Assessment) -> list[tuple[str, str, list[str]]]:
    system = assessment.system
    target = assessment.target_id
    subvol = f"@{target}"
    pool = system.storage.pool_device or "<pool>"
    old = system.storage.root_subvol or "@"
    tag = "<timestamp>"
    return [
        (
            "preflight",
            "verify space, ESP headroom, partition table and journal",
            [
                "sfdisk --dump <disk> > /var/lib/lcm/journal/partition-table.sfdump",
                "efibootmgr -v > /var/lib/lcm/journal/efibootmgr.txt",
            ],
        ),
        (
            "prepare",
            f"snapshot {old} and create {subvol}",
            [
                f"mount -o subvolid=5 {pool} /var/lib/lcm/mnt/pool",
                f"btrfs subvolume snapshot -r /var/lib/lcm/mnt/pool/{old} /var/lib/lcm/mnt/pool/@lcm-backup-{tag}",
                f"btrfs subvolume create /var/lib/lcm/mnt/pool/{subvol}",
                f"mount -o subvol={subvol} {pool} /mnt/lcm-target",
            ],
        ),
        (
            "bootstrap",
            f"install {target} into {subvol} using the family backend",
            ["mmdebstrap ... /mnt/lcm-target <mirror>   # or dnf --installroot / pacstrap"],
        ),
        (
            "configure",
            "fstab, users, packages, initramfs, unified kernel image",
            [
                "write fstab by UUID and subvolume",
                "create users with the same UID/GID and map groups by name",
                "install the mapped package set inside the chroot",
                "ukify build ... --output /boot/efi/EFI/Linux/lcm-<target>.efi",
            ],
        ),
        (
            "arm",
            "register a separate firmware boot entry; keep the old system default",
            ["efibootmgr -c -L 'LCM <target>' -l '\\EFI\\Linux\\lcm-<target>.efi'"],
        ),
        (
            "validate",
            "boot the target once, run the first-boot checks",
            ["select the LCM entry in the firmware boot menu (F12)"],
        ),
        (
            "commit",
            "delete the old root subvolume and its firmware entry",
            ["btrfs subvolume delete /mnt/pool/@", "efibootmgr -b <old> -B"],
        ),
        (
            "rollback",
            "return to the old system at any point before commit",
            ["efibootmgr -o <old-entry>,<lcm-entry>"],
        ),
    ]


def render_plan(assessment: Assessment, style: Style | None = None) -> str:
    style = style or Style(False)
    system = assessment.system
    lines = [
        style.bold(
            f"Plan: {system.distro.pretty} -> {assessment.target_id}"
        ),
        f"Free space: {human_bytes(system.storage.free_bytes)}"
        f"   Estimated need: {human_bytes(assessment.needed_bytes)}",
        "",
    ]
    for index, (phase, description, commands) in enumerate(
        plan_steps(assessment), start=1
    ):
        lines.append(f"{index}. {style.bold(phase):<12} {description}")
        for command in commands:
            lines.append(style.dim(f"     $ {command}"))
    lines.append("")
    lines.append(
        style.dim(
            "The old root is never modified before `commit`.  "
            "`replace` writes a rollback journal and a state bundle first."
        )
    )
    return "\n".join(lines)
