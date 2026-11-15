# LCM — Linux Continuity Manager

Carry a Linux setup between distributions.

LCM treats a distro migration as a transaction:

1. describe the desired target as **data** (`.lcm.yaml`),
2. snapshot the source machine (`.lcmb`),
3. build the new distro in a **separate btrfs subvolume**,
4. boot it through its **own firmware entry**,
5. `commit` only after the new system validates; until then the old system
   remains untouched and one boot-order change restores it.

`/home` is never recreated. The ESP is never reformatted. Nothing is deleted
before `commit`.

> **Status: early alpha.** The `export` → `restore` path is implemented and
> has been exercised on real Arch and Debian VMs. `replace` is implemented but
> has **not yet been boot-tested on real UEFI + btrfs hardware**. It should not
> be used as the only migration path. Keep the source system bootable and
> retain an independent backup until that test passes.

## Support matrix

| Target | Install into a subvolume (`replace`) | Apply a bundle (`restore`) |
| --- | --- | --- |
| Fedora / RHEL family | experimental* | yes |
| Debian / Ubuntu / PikaOS | experimental* | yes |
| Arch / Manjaro / CachyOS | experimental* | yes |
| openSUSE | experimental | yes |

\* Implemented, but not yet boot-tested on real UEFI + btrfs hardware. Treat
it as a development feature.

- **systemd only.** dinit, runit, OpenRC and similar init systems are out of
  scope.
- `replace` requires a btrfs root, UEFI, an ESP at `/boot/efi` or `/efi`, and a
  separate `/home` (its own subvolume or filesystem). It refuses rather than
  risk user data.
- `restore` is filesystem-agnostic: it installs packages and writes only inside
  `/home` and an explicit `/etc` allowlist.

## Install

From a source checkout on Debian, Fedora, or Arch:

```sh
sudo ./install.sh
lcm --version
```

`install.sh` installs the distro's PyYAML package if needed and places a
launcher in `/usr/local/bin/lcm`.

For development without installing:

```sh
PYTHONPATH=src python3 -m lcm --help
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## The two artifacts

### `.lcm.yaml` — the profile

A human-editable, distro-neutral description of desired state. It contains
packages as canonical ids (`firefox`, not `firefox-esr`), users, services, and
the configuration paths to carry. **It contains no executable code** — no
hooks, no scripts, no shell snippets.

```yaml
lcm: 1
name: workstation
packages:
  native: [firefox, git, neovim, flatpak]
  flatpak: [com.valvesoftware.Steam]
services:
  enable: [sshd, fstrim.timer]
config:
  etc: [NetworkManager/system-connections]
  home: [.config, .ssh, .bashrc]
```

See `examples/workstation.lcm.yaml` for a full example.

### `.lcmb` — the bundle

A gzipped tar containing the profile, resolved package metadata, hardware
notes, a `manifest.json`, a SHA-256 checksum file, and payload tars for the
allowlisted `/home` and `/etc` paths. `restore` also accepts a bundle renamed
to `.lcm`; it detects the format by content.

Safety properties:

- bundles are written with mode `0600` (they can contain SSH keys),
- the outer bundle contains no links; extraction refuses absolute member
  paths, `..` member paths, device nodes, and FIFOs,
- payload symlinks are preserved when they stay inside the restored tree;
  absolute links and relative links that escape it are skipped with a note,
- every file is checksummed and verified before use,
- unreadable source files are skipped rather than aborting the export,
- `--full-home` can include browser profiles, SSH/GPG keys, and other
  credentials; treat the bundle like a password vault.

## Migration coverage

`replace` and `restore` cover different migration paths:

- **`replace` on the same machine** builds a new distro next to the old one and
  **reuses `/home` completely**. User files remain because `/home` is never
  copied or recreated. The old root remains bootable until `commit`.
- **`export` → `restore` on another machine or after a wipe** carries only the
  content listed in the profile. The default covers dotfiles and application
  configuration; `--full-home` adds user files.

| What | `replace` (same machine) | `export` → `restore` (default) | `export --full-home` → `restore` |
| --- | --- | --- | --- |
| Dotfiles, shell rc files, `.config`, fonts/icons/themes | kept | included | included |
| Documents, Pictures, Videos, Music, Projects | kept | not included | included |
| Other app data such as `.thunderbird`, `.var/app`, `.wine` | kept | not included | included |
| Caches, Trash, `Downloads`, `Games`, Steam/lutris libraries | kept | excluded | excluded |
| `.ssh` keys | kept | included | included |
| `.gnupg` keyring | kept | not included | included |
| `/etc` allowlist (for example NetworkManager connections) | not copied to the new distro; snapshotted in the pre-replace bundle | included, with per-file backups | included, with per-file backups |
| Package selection | mapped and installed | mapped and installed | mapped and installed |
| Exact package versions, third-party repos, AUR state | not preserved | not preserved | not preserved |
| `/var/lib`, databases, Docker images, VMs | untouched on the old root | not included | not included |
| Users and passwords | users recreated with the same UID and password hash | mapped onto the existing human account when possible; a missing account may be created without the old password | same |

`--full-home` becomes an allowlist of `.` and skips common junk directories:
`.cache`, `.local/share/Trash`, `.local/share/Steam`, `.local/share/lutris`,
`Downloads`, `Games`, `.lcm-backup`, and cache directories inside known
browser and editor trees. A project directory named `cache` or `Cache` is
**not** dropped. Add specific paths with repeatable `--include-home`; an
explicit include overrides a default exclusion (for example,
`--include-home Downloads/taxes.pdf`):

```sh
lcm export -o ~/lcm-backup.lcmb --include-home Documents --include-home Projects
lcm export --full-home -o /mnt/storage/lcm-full.lcmb
```

`-o`/`--output` accepts a `.lcmb` file or an existing directory. The older
positional form (`lcm export ~/lcm-backup.lcmb`) remains supported. When the
destination is omitted, LCM writes `<profile>-<timestamp>.lcmb` in the current
directory.

Staging space for the payload tars defaults to the output filesystem, not
`/tmp`, so a full-home export uses the selected disk or NAS. If the output is
on a NAS, keep the scratch space local:

```sh
lcm export --full-home -o /mnt/nas/backups/lcm-full.lcmb --staging-dir /mnt/storage
```

The staged payload and the compressed bundle both exist at the same time, so
budget roughly twice the selected home data and check `df -h` first. Existing
bundles are not overwritten without `--force`.

A large export is not one silent block. LCM reports each phase separately:
capture, checksum verification and compression. Every line shows the bytes
completed, elapsed time and an estimated time left, and the final output lists
the exact duration of each phase:

```text
  capture home:alice: 51% | 42.7 GiB / 83.1 GiB | 48,231 / 100,454 files | elapsed 18m 04s | ~17m 12s left
  verify checksums: 26% | 22.9 GiB / 88.8 GiB | 12 / 20 files | elapsed 4m 12s | ~12m 32s left
  compress bundle: 37% | 33.1 GiB / 88.8 GiB | 9 / 20 files | 12.3 GiB written | elapsed 18m 20s | ~30m 33s left

Phase timings:
  capture home:alice  18m 42s
  capture etc          0.1s
  verify checksums     2m 12s
  compress bundle     21m 08s
  total               42m 03s
```

The checksum and compression passes read the entire staged payload, so they can
look idle in a process list even while bytes are moving. Watch the byte counter
and the ETA rather than the CPU percentage. Progress goes to stderr, so
`--json` output on stdout stays valid.

A bundle is a continuity snapshot, not a disk image. It does not clone
`/var/lib`, package versions, third-party repositories, container images, or
non-allowlisted `/etc` state. Treat it as a setup-and-files snapshot, not a
full disk image.

## Commands

### Read-only first

```sh
lcm check --target debian                  # verdict: green / yellow / red
lcm plan  --target debian                  # the exact steps that would run
lcm check --target arch --profile workstation.lcm.yaml
lcm mapping firefox --to debian            # package resolution
lcm mapping firefox-esr --from debian --to arch
```

`check` and `plan` never write anything. `check` exits 0 even for a red
verdict; read the verdict line.

### Capture a machine

```sh
lcm export -o ~/lcm-backup.lcmb               # packages + dotfiles/config allowlist
lcm export --full-home -o /mnt/storage/lcm-full.lcmb  # also carry personal files
lcm export -o /mnt/storage/lcm.lcmb --include-home Projects --include-home Documents
lcm export --no-payload -o /tmp/meta.lcmb     # metadata only
lcm export -o /mnt/storage/for-arch.lcmb --target arch  # preview mapping for a target
lcm backup -o /mnt/nas/lcm.lcmb               # alias for export
```

`--full-home` captures personal files as well. Choose a destination with
enough room, and use `--staging-dir` when the destination is a NAS:

```sh
lcm export --full-home -o /mnt/nas/backups/lcm-full.lcmb --staging-dir /mnt/storage
```

A full-home export stages the payload next to the output by default, so it no
longer depends on `/tmp` size. Both the staged payload and the final bundle
exist during the export; allow roughly twice the selected data.

Run `lcm` with no arguments for a short command overview, or
`lcm export --help` / `lcm restore --help` for examples.

### Apply a bundle to the current machine

This is the safer path and the recommended one for a fresh VM:

```sh
lcm restore ~/lcm-backup.lcmb                    # dry run
sudo lcm restore ~/lcm-backup.lcmb --apply --yes # apply changes
sudo lcm restore ~/lcm-backup.lcmb --apply --step packages
sudo lcm restore workstation.lcm.yaml --apply    # profile only, no file payload
sudo lcm import  ~/lcm-backup.lcmb --apply --yes # same as restore
sudo lcm import  ~/lcm-backup.lcmb --apply --yes --try-raw
```

Before restoring, the bundle is unpacked to a workspace. LCM chooses a
directory with enough free space and prefers `$TMPDIR`, `/var/tmp`, or the
bundle's own filesystem over `/tmp`, because `/tmp` is RAM-backed on many
systems. The dry run unpacks the payload too, so it needs the same workspace.
Override the choice when the default candidates are too small:

```sh
lcm restore /mnt/storage/lcm-full.lcmb --work-dir /mnt/storage/lcm-work
TMPDIR=/mnt/storage/lcm-work lcm restore /mnt/storage/lcm-full.lcmb
```

`--try-raw` is an opt-in best effort for packages that had no canonical
mapping: it tries the source package name unchanged on the target. This helps
when both distros use the same name; names the target does not carry are
reported as failures. It is off by default because it is not a verified
cross-family mapping.

- packages are attempted as a batch, then one by one; missing names are
  reported instead of aborting the restore,
- Flatpak apps are installed after `flatpak` itself, with Flathub added,
- if the profile's user does not exist and the machine has exactly one human
  account, dotfiles are restored into that account,
- overwritten files are backed up under `/var/lib/lcm/backup/<timestamp>` or
  `~/.lcm-backup/<timestamp>`.

### Replace a distro (btrfs + UEFI, experimental)

> This path has not yet been boot-tested on real UEFI + btrfs hardware. Test
> it in a VM or on a snapshot first, and keep the old system bootable.

```sh
sudo lcm replace --target debian --suite trixie   # dry run happens first
sudo lcm replace --target arch --profile workstation.lcm.yaml

# derivative example: add a third-party repository and meta package
sudo lcm replace --target pikaos --suite sid \
     --repo 'deb http://repo.pika-os.com/ pikaos main' \
     --repo-key https://repo.pika-os.com/pikaos.gpg \
     --meta pikaos-desktop
```

What happens:

1. preflight checks btrfs, UEFI, ESP headroom, free space and `/home`,
2. a pre-replace `.lcmb` is exported to `/var/lib/lcm/bundles` (mode 0600),
3. the old root is snapshotted read-only as `@lcm-backup-<timestamp>`,
4. `@<target>` and `@<target>-boot` are created and mounted,
5. the target is bootstrapped:
   - Debian: `mmdebstrap` (or `debootstrap`),
   - Fedora: `dnf --installroot` (repo files are seeded when the host is not
     Fedora),
   - Arch: `pacstrap`, or the official Arch bootstrap tarball when `pacstrap`
     is unavailable (works from Fedora/Debian),
6. fstab, users (same UID and password hash), packages, initramfs and a
   **unified kernel image** are created,
7. a separate firmware entry `LCM <target>` is registered; the old entry stays
   first in BootOrder, and a one-shot `BootNext` makes the firmware try the new
   entry exactly once, falling back to the old system if it fails,
8. Fedora targets get `/.autorelabel` so SELinux relabels the new root on first
   boot (this may reboot once).

Then:

```sh
# reboot; BootNext tries "LCM <target>" once, or pick it with F12
sudo lcm validate                 # runs the same checks as first boot
sudo lcm commit                   # deletes old root, boot entry, and snapshot
sudo lcm commit --keep-old        # keep the old root subvolume
sudo lcm commit --keep-backup     # keep the @lcm-backup-* snapshot too
sudo lcm rollback                 # make the old entry default again
sudo lcm recover                  # inspect / clean up unfinished attempts
sudo lcm journal list
```

Journal states: `planned → prepared → bootstrapped → configured → armed →
validated → committed`, plus `rolled_back` and `failed`. The journal is copied
to the ESP so it survives a broken root.

## Testing on a fresh Debian VM

The acceptance path for `export` → `restore` is a Debian VM with no prior
configuration. `lcm check` assesses the **replace** path and reports RED on an
ext4 VM because `replace` requires btrfs; that result is expected. Use the
`restore` dry run below to validate this path.

```sh
# inside the VM, as a user with sudo
sudo apt-get update
sudo apt-get install -y git python3 python3-yaml

git clone https://github.com/deopr/lcm.git && cd lcm
sudo ./install.sh

# transfer the bundle into the VM (scp, shared folder, or similar)
sudo lcm restore /path/to/lcm-backup.lcmb           # dry run, inspect output
sudo lcm restore /path/to/lcm-backup.lcmb --apply --yes --no-flatpak

# or apply a plain profile instead of a bundle
sudo lcm restore /path/to/workstation.lcm.yaml --apply --yes --no-flatpak

# success checks
dpkg -l | grep -E 'firefox|git|neovim'
ls -la ~/.config ~/.ssh
```

If the bundle was produced on Fedora, most raw Fedora-only names are reported
as *unmapped*; that result is expected. The canonical package set (the
`native:` list) is installed, and Flatpak apps are installed as well. A higher
hit rate is possible by exporting with `--target debian` and inspecting the
`lcm restore` dry run before applying.

### Testing on a fresh Arch VM

```sh
# inside the VM, as a normal user with sudo (not as root)
sudo pacman -Syu --needed git python python-yaml

git clone https://github.com/deopr/lcm.git && cd lcm
sudo ./install.sh

sudo lcm restore /path/to/lcm-backup.lcmb              # dry run
sudo lcm restore /path/to/lcm-backup.lcmb --apply --yes --try-raw
```

Run `lcm` through `sudo` from the account that should receive the dotfiles. A
single human account is mapped automatically; running as root with no normal
account causes LCM to create the bundle's user instead. `--try-raw` is useful
for a Fedora-to-Arch test because it attempts source names that have no
canonical mapping and reports the ones Arch does not carry.

`--strict` makes CI fail on any missing package name; a cross-distro bundle
normally contains a few names the target calls differently. The `restore` path
has been exercised on clean Debian 13 and Debian 12 containers. Debian 13
installed the full example set; Debian 12 installed all but three newer tools
(`eza`, `fastfetch`, `starship`) and reported them without aborting. Bundle
restores on both releases exercised user-home mapping and dotfiles, including
kept relative symlinks and skipped absolute symlinks (and Python 3.11's older
tarfile API on Debian 12). Restores keep relative symlinks that stay inside
the home directory, including links that use `..`, and skip absolute links or
links that escape the tree.

## Safety invariants

- `check`, `plan`, `mapping`, `journal list` never write.
- `replace` never modifies the running root; it snapshots it read-only first.
- The old firmware entry remains first in `BootOrder` until `commit`; the new
  entry is tried once through `BootNext`.
- `commit` deletes only after validation (`--force` exists, but says why) and
  removes the pre-replace `@lcm-backup-*` snapshot unless `--keep-backup` is
  passed; `--keep-old` retains the old root subvolume.
- `/home` is reused and only written additively, with per-file backups.
- Partition table and `efibootmgr` output are recorded in the journal.
- No profile or bundle can execute code.

## Known limitations

- **Debian 12 (bookworm)** does not ship `systemd-ukify`. A UKI cannot be
  built there; use a Debian 13 / `trixie` / `sid` target (PikaOS is `sid`) or
  install `systemd-ukify` from backports first. `lcm` fails with an explicit
  message instead of a half-built system. The `restore` path does not need a
  UKI and works on Debian 12.
- Secure Boot is not signed. Disable it for the first boot or enroll a MOK;
  `check` warns when it is enabled.
- `replace` supports single-device btrfs pools only.
- Multi-GPU/NVIDIA proprietary stacks are not migrated; the target's own
  driver packages must be installed after first boot.
- Package **versions** are not compared offline; `check` reports mapping
  coverage, not repository freshness.
- openSUSE support is untested beyond detection.
- `restore` does not merge `/etc` files, it backs up and overwrites. Review the
  dry run.
- `restore` unpacks the full payload before verification and before the dry
  run, so the workspace needs room for the uncompressed bundle. Use
  `--work-dir` when `/tmp` is small or RAM-backed.

## Package mappings

Canonical ids live in `src/lcm/data/mappings.yaml`. Add an entry when a package
is reported as unmatched:

```yaml
packages:
  example-app: {fedora: example-app, debian: example-app, arch: example-app, flatpak: org.example.ExampleApp}
```

The mapping is deliberately conservative: HTTPS-first, with no silent name
guessing across families. Unmatched names are preserved as raw entries in the
bundle so nothing is lost.

## Contributing

The public repository is <https://github.com/deopr/lcm>. Bug reports and
package-mapping additions are welcome:

- open an issue at <https://github.com/deopr/lcm/issues> with the source
  distro, the target distro, and the exact command;
- include the dry-run output, the package names reported as unmapped, and
  whether the failure came from `export`, `restore`, or `replace`;
- for mapping fixes, add the canonical id to `src/lcm/data/mappings.yaml` and
  run `PYTHONPATH=src python3 -m unittest discover -s tests`.

`replace` is experimental, so reports from real UEFI + btrfs hardware are
especially useful.

## License

MIT.
