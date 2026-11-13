"""Read-only inspection of the running system.

Everything in this module is safe to run unprivileged (some details are
simply unavailable without root).  Nothing here modifies the machine.
"""

from __future__ import annotations

import glob
import grp
import json
import os
import pwd
import re
from dataclasses import dataclass, field
from pathlib import Path

from lcm.util import LcmError, human_bytes, run_ok

# --------------------------------------------------------------------------
# distributions
# --------------------------------------------------------------------------

FAMILY_IDS: dict[str, str] = {
    # fedora family
    "fedora": "fedora",
    "rhel": "fedora",
    "centos": "fedora",
    "rocky": "fedora",
    "almalinux": "fedora",
    "nobara": "fedora",
    "bazzite": "fedora",
    "aurora": "fedora",
    "bluefin": "fedora",
    # debian family
    "debian": "debian",
    "ubuntu": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "pikaos": "debian",
    "kali": "debian",
    "zorin": "debian",
    "elementary": "debian",
    "neon": "debian",
    "raspbian": "debian",
    "devuan": "debian",
    "mx": "debian",
    # arch family
    "arch": "arch",
    "manjaro": "arch",
    "endeavouros": "arch",
    "cachyos": "arch",
    "garuda": "arch",
    "artix": "arch",
    "arcolinux": "arch",
    # suse family
    "opensuse": "suse",
    "opensuse-leap": "suse",
    "opensuse-tumbleweed": "suse",
    "opensuse-microos": "suse",
    "sles": "suse",
    "sled": "suse",
}

FAMILY_NAMES = {
    "fedora": "Fedora/RHEL",
    "debian": "Debian/Ubuntu",
    "arch": "Arch",
    "suse": "openSUSE",
    "unknown": "unknown",
}


def family_of(*distro_ids: str) -> str:
    for value in distro_ids:
        key = (value or "").strip().lower()
        if key in FAMILY_IDS:
            return FAMILY_IDS[key]
    return "unknown"


def parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        data[key.strip()] = value
    return data


@dataclass(frozen=True)
class Distro:
    id: str
    name: str
    version: str
    id_like: tuple[str, ...]
    family: str

    @property
    def pretty(self) -> str:
        if self.version:
            return f"{self.name} {self.version}"
        return self.name

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "id_like": list(self.id_like),
            "family": self.family,
        }


def detect_distro() -> Distro:
    text = ""
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(candidate).read_text(encoding="utf-8")
            break
        except OSError:
            continue
    if not text:
        raise LcmError("cannot read /etc/os-release")

    data = parse_os_release(text)
    distro_id = data.get("ID", "unknown").lower()
    id_like = tuple(
        part.strip().lower()
        for part in data.get("ID_LIKE", "").split()
        if part.strip()
    )
    family = family_of(distro_id, *id_like)
    name = data.get("NAME") or data.get("PRETTY_NAME") or distro_id
    version = data.get("VERSION_ID") or ""
    return Distro(
        id=distro_id,
        name=name,
        version=version,
        id_like=id_like,
        family=family,
    )


# --------------------------------------------------------------------------
# block devices
# --------------------------------------------------------------------------

EFI_PARTTYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


def _lsblk() -> list[dict]:
    ok, out, _ = run_ok(
        [
            "lsblk",
            "-J",
            "-o",
            "NAME,PATH,TYPE,FSTYPE,UUID,SIZE,MOUNTPOINT,PARTTYPE,PKNAME",
        ]
    )
    if not ok or not out.strip():
        return []
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return []

    flat: list[dict] = []

    def walk(items: list[dict]) -> None:
        for item in items:
            node = dict(item)
            flat.append(node)
            walk(item.get("children") or [])

    walk(payload.get("blockdevices") or [])
    return flat


def _findmnt(target: str = "/") -> dict:
    ok, out, _ = run_ok(
        ["findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "--target", target]
    )
    if not ok or not out.strip():
        return {}
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return {}
    entries = payload.get("filesystems") or []
    return entries[0] if entries else {}


def _option_value(options: str, key: str) -> str | None:
    for chunk in (options or "").split(","):
        name, _, value = chunk.partition("=")
        if name == key:
            return value
    return None


def _statvfs_free(path: str) -> int:
    try:
        stats = os.statvfs(path)
        return stats.f_bavail * stats.f_frsize
    except OSError:
        return 0


def _btrfs_free(path: str) -> int | None:
    ok, out, _ = run_ok(["btrfs", "filesystem", "usage", "-b", path])
    if not ok:
        return None
    match = re.search(r"Free \(estimated\):\s+(\d+)", out)
    if match:
        return int(match.group(1))
    return None


def _btrfs_subvolumes(path: str) -> list[str]:
    ok, out, _ = run_ok(["btrfs", "subvolume", "list", path])
    if not ok:
        return []
    names = []
    for line in out.splitlines():
        match = re.search(r"\spath\s+(.+)$", line)
        if match:
            names.append(match.group(1).strip())
    return names


def _partition_number(name: str) -> int | None:
    match = re.search(r"p?(\d+)$", name or "")
    if match:
        return int(match.group(1))
    return None


@dataclass
class Storage:
    root_source: str
    root_fstype: str
    root_options: str
    root_subvol: str | None
    pool_device: str | None
    pool_uuid: str | None
    luks: bool
    luks_device: str | None
    luks_uuid: str | None
    esp_device: str | None
    esp_mount: str | None
    esp_uuid: str | None
    esp_disk: str | None
    esp_partition: int | None
    esp_free_bytes: int
    free_bytes: int
    total_bytes: int
    btrfs_free_bytes: int | None
    subvolumes: list[str] = field(default_factory=list)
    home_separate: bool = False
    home_source: str | None = None
    home_subvol: str | None = None
    home_uuid: str | None = None
    home_fstype: str | None = None
    boot_separate: bool = False
    boot_source: str | None = None
    multi_device: bool = False

    @property
    def is_btrfs(self) -> bool:
        return self.root_fstype == "btrfs"

    @property
    def esp_ok(self) -> bool:
        return bool(self.esp_device and self.esp_mount)

    def to_dict(self) -> dict:
        data = dict(self.__dict__)
        return data


def detect_storage() -> Storage:
    root = _findmnt("/")
    root_source = root.get("source", "")
    root_fstype = root.get("fstype", "")
    root_options = root.get("options", "")
    root_subvol = _option_value(root_options, "subvol")
    if root_subvol:
        root_subvol = root_subvol.lstrip("/")

    nodes = _lsblk()

    def node_for(source: str) -> dict | None:
        plain = source.split("[", 1)[0]
        for node in nodes:
            if node.get("path") == plain:
                return node
        return None

    root_node = node_for(root_source)
    if root_node is None:
        for node in nodes:
            if node.get("mountpoint") == "/":
                root_node = node
                break

    luks = False
    luks_device = None
    luks_uuid = None
    if root_node is not None:
        if root_node.get("type") == "crypt":
            luks = True
            luks_device = root_node.get("path")
            luks_uuid = root_node.get("uuid")
        parent_name = root_node.get("pkname")
        if parent_name:
            for node in nodes:
                if node.get("name") == parent_name and node.get("type") == "crypt":
                    luks = True
                    luks_device = node.get("path")
                    luks_uuid = node.get("uuid")

    pool_uuid = root_node.get("uuid") if root_node else None
    if root_fstype == "btrfs" and not pool_uuid:
        ok, out, _ = run_ok(["btrfs", "filesystem", "show", "/"])
        if ok:
            match = re.search(r"uuid:\s*([0-9a-fA-F-]+)", out)
            if match:
                pool_uuid = match.group(1)

    multi_device = False
    if root_fstype == "btrfs":
        ok, out, _ = run_ok(["btrfs", "filesystem", "show", "/"])
        if ok and len(re.findall(r"^\s*/dev/", out, re.MULTILINE)) > 1:
            multi_device = True

    esp_node = None
    for node in nodes:
        parttype = (node.get("parttype") or "").lower()
        if parttype == EFI_PARTTYPE:
            esp_node = node
            if node.get("mountpoint") in {"/boot/efi", "/efi"}:
                break
    if esp_node is None:
        for node in nodes:
            if node.get("fstype") == "vfat" and node.get("mountpoint") in {
                "/boot/efi",
                "/efi",
            }:
                esp_node = node
                break

    esp_device = esp_node.get("path") if esp_node else None
    esp_mount = esp_node.get("mountpoint") if esp_node else None
    esp_uuid = esp_node.get("uuid") if esp_node else None
    esp_disk = esp_node.get("pkname") if esp_node else None
    if esp_disk and not str(esp_disk).startswith("/"):
        esp_disk = f"/dev/{esp_disk}"
    esp_partition = _partition_number(esp_node.get("name", "")) if esp_node else None
    if esp_disk is None and esp_node is not None:
        esp_disk = re.sub(r"p?\d+$", "", esp_node.get("name", "")) or None
        if esp_disk and not esp_disk.startswith("/"):
            esp_disk = f"/dev/{esp_disk}"

    home = _findmnt("/home")
    home_separate = home.get("target") == "/home"
    home_node = node_for(home.get("source", "")) if home_separate else None
    boot = _findmnt("/boot")
    boot_separate = boot.get("target") == "/boot"

    total = 0
    try:
        stats = os.statvfs("/")
        total = stats.f_blocks * stats.f_frsize
    except OSError:
        pass

    return Storage(
        root_source=root_source,
        root_fstype=root_fstype,
        root_options=root_options,
        root_subvol=root_subvol,
        pool_device=(
            root_source.split("[", 1)[0] if root_fstype == "btrfs" else None
        ),
        pool_uuid=pool_uuid,
        luks=luks,
        luks_device=luks_device,
        luks_uuid=luks_uuid,
        esp_device=esp_device,
        esp_mount=esp_mount,
        esp_uuid=esp_uuid,
        esp_disk=esp_disk,
        esp_partition=esp_partition,
        esp_free_bytes=_statvfs_free(esp_mount) if esp_mount else 0,
        free_bytes=_statvfs_free("/"),
        total_bytes=total,
        btrfs_free_bytes=_btrfs_free("/") if root_fstype == "btrfs" else None,
        subvolumes=_btrfs_subvolumes("/") if root_fstype == "btrfs" else [],
        home_separate=home_separate,
        home_source=home.get("source") if home_separate else None,
        home_subvol=(
            (_option_value(home.get("options", ""), "subvol") or "").lstrip("/") or None
        )
        if home_separate
        else None,
        home_uuid=home_node.get("uuid") if home_node else None,
        home_fstype=home.get("fstype") if home_separate else None,
        boot_separate=boot_separate,
        boot_source=boot.get("source") if boot_separate else None,
        multi_device=multi_device,
    )


# --------------------------------------------------------------------------
# boot
# --------------------------------------------------------------------------

@dataclass
class BootEntry:
    number: str
    label: str
    active: bool
    loader: str
    order: int = 999


@dataclass
class Boot:
    uefi: bool
    secure_boot: bool | None
    loader: str
    entries: list[BootEntry]
    esp_mount: str | None
    uki_files: list[str] = field(default_factory=list)

    def entry_for(self, needle: str) -> BootEntry | None:
        needle = needle.lower()
        for entry in self.entries:
            if needle in entry.label.lower():
                return entry
        return None

    def to_dict(self) -> dict:
        return {
            "uefi": self.uefi,
            "secure_boot": self.secure_boot,
            "loader": self.loader,
            "entries": [entry.__dict__ for entry in self.entries],
        }


_SECURE_BOOT_VAR = (
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
)


def _secure_boot() -> bool | None:
    try:
        data = Path(_SECURE_BOOT_VAR).read_bytes()
    except OSError:
        data = b""
    if len(data) >= 5:
        return data[4] == 1
    ok, out, _ = run_ok(["mokutil", "--sb-state"])
    if ok:
        if "SecureBoot enabled" in out:
            return True
        if "SecureBoot disabled" in out:
            return False
    return None


def _boot_entries() -> tuple[list[BootEntry], list[str]]:
    ok, out, _ = run_ok(["efibootmgr", "-v"])
    if not ok:
        return [], []

    order_numbers: list[str] = []
    entries: list[BootEntry] = []
    for line in out.splitlines():
        if line.startswith("BootOrder:"):
            order_numbers = [
                chunk.strip() for chunk in line.split(":", 1)[1].split(",") if chunk
            ]
            continue
        match = re.match(r"^Boot([0-9A-Fa-f]{4})(\*?)\s+(.*)$", line)
        if not match:
            continue
        number, active, rest = match.groups()
        label, _, loader = rest.partition("\t")
        entries.append(
            BootEntry(
                number=number.upper(),
                label=label.strip(),
                active=bool(active),
                loader=loader.strip(),
                order=order_numbers.index(number.upper())
                if number.upper() in order_numbers
                else 999,
            )
        )
    entries.sort(key=lambda entry: entry.order)
    return entries, order_numbers


def detect_boot(storage: Storage) -> Boot:
    uefi = os.path.isdir("/sys/firmware/efi")
    secure = _secure_boot() if uefi else None
    entries, _order = _boot_entries() if uefi else ([], [])

    loader = "unknown"
    uki_files: list[str] = []
    if storage.esp_mount:
        esp = Path(storage.esp_mount)
        if (esp / "EFI/Linux").is_dir():
            uki_files = sorted(
                str(path.relative_to(esp)) for path in (esp / "EFI/Linux").glob("*.efi")
            )
        if (esp / "EFI/fedora/grubx64.efi").exists():
            loader = "grub"
        elif (esp / "EFI/systemd/systemd-bootx64.efi").exists():
            loader = "systemd-boot"
        elif uki_files:
            loader = "uki"
        elif (esp / "EFI/debian/grubx64.efi").exists():
            loader = "grub"

    return Boot(
        uefi=uefi,
        secure_boot=secure,
        loader=loader,
        entries=entries,
        esp_mount=storage.esp_mount,
        uki_files=uki_files,
    )


# --------------------------------------------------------------------------
# hardware
# --------------------------------------------------------------------------

OUT_OF_TREE = {
    "nvidia",
    "nvidia_drm",
    "nvidia_modeset",
    "nvidia_uvm",
    "wl",
    "broadcom_wl",
    "v4l2loopback",
    "zfs",
    "spl",
    "virtualbox",
    "vboxdrv",
    "vboxnetadp",
    "vboxnetflt",
    "vmw_vmci",
    "vmw_vsock_vmci_transport",
    "rtl8821ce",
    "rtl88x2bu",
    "8188eu",
    "r8125",
    "it87",
    "nct6775",
}

GPU_VENDORS = [
    ("advanced micro devices", "amd"),
    ("ati", "amd"),
    ("nvidia", "nvidia"),
    ("intel", "intel"),
    ("vmware", "vmware"),
    ("red hat", "virtio"),
    ("apple", "apple"),
    ("aspeed", "aspeed"),
]


@dataclass
class Hardware:
    cpu: str
    memory_bytes: int
    gpus: list[str]
    gpu_vendors: list[str]
    wifi: list[str]
    out_of_tree_modules: list[str]
    virtualization: str | None
    kernel: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _cpu_name() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return os.uname().machine


def _memory_bytes() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _gpu_vendors_from_sysfs() -> list[str]:
    vendors: list[str] = []
    mapping = {"0x1002": "amd", "0x10de": "nvidia", "0x8086": "intel", "0x15ad": "vmware"}
    for path in glob.glob("/sys/class/drm/card*/device/vendor"):
        try:
            vendor = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if vendor in mapping and mapping[vendor] not in vendors:
            vendors.append(mapping[vendor])
    return vendors


def _wifi_adapters() -> list[str]:
    adapters = []
    for path in glob.glob("/sys/class/net/*"):
        if not os.path.isdir(os.path.join(path, "wireless")):
            continue
        name = os.path.basename(path)
        driver = ""
        link = os.path.join(path, "device", "driver")
        if os.path.islink(link):
            driver = os.path.basename(os.readlink(link))
        adapters.append(f"{name} ({driver})" if driver else name)
    return adapters


def _loaded_modules() -> set[str]:
    modules = set()
    try:
        for line in Path("/proc/modules").read_text(encoding="utf-8").splitlines():
            if line:
                modules.add(line.split()[0])
    except OSError:
        pass
    return modules


def detect_hardware() -> Hardware:
    gpus: list[str] = []
    vendors: list[str] = []
    ok, out, _ = run_ok(["lspci", "-nn"])
    if ok:
        for line in out.splitlines():
            lower = line.lower()
            if "vga compatible controller" in lower or "3d controller" in lower or "display controller" in lower:
                gpus.append(line.split(":", 2)[-1].strip())
                for needle, vendor in GPU_VENDORS:
                    if needle in lower and vendor not in vendors:
                        vendors.append(vendor)
    if not gpus:
        vendors = _gpu_vendors_from_sysfs()
        gpus = [f"{vendor} GPU" for vendor in vendors]

    virt_ok, virt_out, _ = run_ok(["systemd-detect-virt"])
    virtualization = None
    if virt_ok:
        value = virt_out.strip()
        if value and value != "none":
            virtualization = value

    return Hardware(
        cpu=_cpu_name(),
        memory_bytes=_memory_bytes(),
        gpus=gpus,
        gpu_vendors=vendors,
        wifi=_wifi_adapters(),
        out_of_tree_modules=sorted(_loaded_modules() & OUT_OF_TREE),
        virtualization=virtualization,
        kernel=os.uname().release,
    )


# --------------------------------------------------------------------------
# users
# --------------------------------------------------------------------------

@dataclass
class User:
    name: str
    uid: int
    gid: int
    groups: list[str]
    shell: str
    home: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def detect_users() -> list[User]:
    users = []
    for entry in pwd.getpwall():
        if entry.pw_uid < 1000 or entry.pw_uid == 65534:
            continue
        if entry.pw_shell.endswith(("nologin", "false")):
            continue
        try:
            gids = os.getgrouplist(entry.pw_name, entry.pw_gid)
        except OSError:
            gids = [entry.pw_gid]
        groups = []
        for gid in gids:
            try:
                groups.append(grp.getgrgid(gid).gr_name)
            except KeyError:
                pass
        users.append(
            User(
                name=entry.pw_name,
                uid=entry.pw_uid,
                gid=entry.pw_gid,
                groups=sorted(set(groups)),
                shell=entry.pw_shell,
                home=entry.pw_dir,
            )
        )
    return users


# --------------------------------------------------------------------------
# aggregate
# --------------------------------------------------------------------------

@dataclass
class SystemInfo:
    distro: Distro
    storage: Storage
    boot: Boot
    hardware: Hardware
    users: list[User]

    def summary(self) -> str:
        lines = [
            f"Distro:  {self.distro.pretty}  ({self.distro.family})",
            f"Kernel:  {self.hardware.kernel}",
            f"Storage: {self.storage.root_fstype} on {self.storage.root_source}"
            + (f"  subvol={self.storage.root_subvol}" if self.storage.root_subvol else ""),
            f"Free:    {human_bytes(self.storage.free_bytes)}",
            f"Boot:    {'UEFI' if self.boot.uefi else 'BIOS'}"
            + (f"  secure-boot={self.boot.secure_boot}" if self.boot.uefi else ""),
            f"CPU:     {self.hardware.cpu}",
            f"GPU:     {', '.join(self.hardware.gpus) or 'unknown'}",
        ]
        if self.storage.esp_device:
            lines.append(
                f"ESP:     {self.storage.esp_device} at {self.storage.esp_mount}"
                f"  ({human_bytes(self.storage.esp_free_bytes)} free)"
            )
        return "\n".join(lines)


def detect_system() -> SystemInfo:
    storage = detect_storage()
    return SystemInfo(
        distro=detect_distro(),
        storage=storage,
        boot=detect_boot(storage),
        hardware=detect_hardware(),
        users=detect_users(),
    )
