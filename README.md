# LCM — Linux Continuity Manager

Transactional distro replacement with a rollback button.

LCM treats a distro hop as a transaction:

1. describe the machine you want as **data** (`.lcm.yaml`),
2. snapshot the machine you have (`.lcmb`),
3. build the new distro in a **separate btrfs subvolume**,
4. boot it through its **own firmware entry**,
5. `commit` only after the new system validates; until then the old system is
   untouched and one boot-order change brings it back.

`/home` is never recreated. The ESP is never reformatted. Nothing is deleted
before `commit`.

## Support matrix

| Target | Install into a subvolume (`replace`) | Apply a bundle (`restore`) |
| --- | --- | --- |
| Fedora / RHEL family | yes | yes |
| Debian / Ubuntu / PikaOS | yes | yes |
| Arch / Manjaro / CachyOS | yes | yes |
| openSUSE | experimental | yes |

- **systemd only.** dinit, runit, OpenRC and friends are out of scope.
- `replace` requires: btrfs root, UEFI, an ESP at `/boot/efi` or `/efi`, and a
  separate `/home` (its own subvolume or filesystem). It refuses rather than
  risk user data.
- `restore` works on ext4, LVM, anything — it only installs packages and writes
  inside `/home` and an explicit `/etc` allowlist.

## Install

From a source checkout, on Debian, Fedora or Arch:

```sh
sudo ./install.sh
lcm --version
```

`install.sh` installs the distro's PyYAML package if needed and puts a launcher
in `/usr/local/bin/lcm`.

For development without installing:

```sh
PYTHONPATH=src python3 -m lcm --help
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## The two artifacts

### `.lcm.yaml` — the profile

A human-editable, distro-neutral description of desired state. It contains
packages as canonical ids (`firefox`, not `firefox-esr`), users, services and
the config paths worth carrying. **It contains no executable code** — no hooks,
no scripts, no shell snippets.

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

- bundles are written mode `0600` (they can contain SSH keys),
- extraction refuses absolute paths, `..`, device nodes, FIFOs and top-level
  links; absolute symlinks inside a payload are skipped with a note,
- every file is checksummed and verified before use,
- unreadable source files are skipped rather than aborting the export.

## Commands

### Read-only first

```sh
lcm check --target pikaos                  # verdict: green / yellow / red
lcm plan  --target pikaos                  # the exact steps that would run
lcm check --target arch --profile my.lcm.yaml
lcm mapping firefox --to debian            # package resolution
lcm mapping firefox-esr --from debian --to arch
```

`check` and `plan` never write anything. `check` exits 0 even for a red
verdict; read the verdict line.

### Capture this machine

```sh
lcm export ~/lcm-backup.lcmb               # full bundle (packages + dotfiles)
lcm export ~/meta.lcmb --no-payload        # metadata only
lcm export ~/for-arch.lcmb --target arch   # preview mapping for a target
```

### Apply a bundle to the machine you are on

This is the safe half, and the one to use on a fresh VM:

```sh
lcm restore ~/lcm-backup.lcmb                    # dry run
sudo lcm restore ~/lcm-backup.lcmb --apply --yes # do it
sudo lcm restore ~/lcm-backup.lcmb --apply --step packages
sudo lcm restore my.lcm.yaml --apply             # profile only, no file payload
```

- packages are attempted as a batch, then one by one; missing names are
  reported instead of aborting the restore,
- Flatpak apps are installed after `flatpak` itself, with Flathub added,
- if the profile's user does not exist and the machine has exactly one human
  account, dotfiles are restored into that account,
- overwritten files are backed up under `/var/lib/lcm/backup/<timestamp>` or
  `~/.lcm-backup/<timestamp>`.

### Replace a distro (btrfs + UEFI)

```sh
sudo lcm replace --target debian                  # dry run happens first
sudo lcm replace --target arch --profile my.lcm.yaml
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
   the default.

Then:

```sh
# reboot, pick "LCM <target>" in the firmware menu (usually F12)
sudo lcm validate                 # runs the same checks as first boot
sudo lcm commit                   # deletes the old subvolume + old boot entry
sudo lcm commit --keep-old        # or keep it around
sudo lcm rollback                 # make the old entry default again
sudo lcm recover                  # inspect / clean up unfinished attempts
sudo lcm journal list
```

Journal states: `planned → prepared → bootstrapped → configured → armed →
validated → committed`, plus `rolled_back` and `failed`. The journal is copied
to the ESP so it survives a broken root.

## Testing on a fresh Debian VM

This is the acceptance path: install the bundle on a Debian VM that has nothing
on it. `lcm check` assesses the **replace** path and will report RED on an ext4
VM because replace needs btrfs; that is expected. Use the `restore` dry run
below as the check for this path.

```sh
# inside the VM, as the user with sudo
sudo apt-get update
sudo apt-get install -y git python3 python3-yaml    # or: sudo ./install.sh

git clone <this-repo> lcm && cd lcm
sudo ./install.sh

# copy the bundle into the VM (scp, shared folder, whatever)
sudo lcm restore /path/to/lcm-backup.lcmb           # dry run, inspect output
sudo lcm restore /path/to/lcm-backup.lcmb --apply --yes --no-flatpak

# or install a plain profile instead of a bundle
sudo lcm restore /path/to/workstation.lcm.yaml --apply --yes --no-flatpak

# success checks
dpkg -l | grep -E 'firefox|git|neovim'
ls -la ~/.config ~/.ssh
```

If the bundle was produced on Fedora, most raw Fedora-only names will be
reported as *unmapped*; that is expected. The canonical package set (the
`native:` list) is installed, and Flatpak apps are installed too. To get a
higher hit rate, export with `--target debian` and inspect `lcm restore`'s dry
run before applying.

Use `--strict` only when you want CI to fail on any missing package name; a
cross-distro bundle normally contains a few names the target calls differently.
This path was exercised on clean Debian 13 and Debian 12 containers. Debian 13
installed the full example set; Debian 12 installed all but three newer tools
(`eza`, `fastfetch`, `starship`) and reported them without aborting. A bundle
restore on Debian 13 also exercised user-home mapping and dotfiles, including
kept relative symlinks and skipped absolute symlinks.

## Safety invariants

- `check`, `plan`, `mapping`, `journal list` never write.
- `replace` never modifies the running root; it snapshots it read-only first.
- The old firmware entry remains first until `commit`.
- `commit` deletes only after validation (`--force` exists, but says why).
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

## Package mappings

Canonical ids live in `src/lcm/data/mappings.yaml`. Add an entry when a package
you use is reported as unmatched:

```yaml
packages:
  myapp: {fedora: myapp, debian: myapp, arch: myapp, flatpak: org.example.MyApp}
```

The mapping is intentionally honest: HTTPS-first, no silent name guessing
across families. Unmatched names are preserved as raw entries in the bundle so
nothing is lost.

## License

MIT.
