# `replace` hardware test record

Copy this file into an issue or a pull request after a real UEFI + btrfs run.
Record facts, not conclusions: the exact commands and their output are more
useful than a one-line "it worked".

## Environment

```sh
date -u
uname -a
cat /etc/os-release
lsblk -o NAME,SIZE,FSTYPE,PARTTYPENAME,MOUNTPOINTS
findmnt -no SOURCE,FSTYPE,OPTIONS /
sudo efibootmgr -v
```

Record:

- source distro and release:
- target distro and release:
- firmware and Secure Boot state:
- btrfs layout (`@`, `@home`, separate `/home`, single device or RAID):
- ESP size and free space:
- GPU and whether proprietary drivers are involved:

## Before `replace`

```sh
sudo lcm check --target <target>
sudo lcm replace --target <target> --profile <profile>
```

Record the dry-run plan and the full preflight result. Note any warnings that
were accepted.

## During `replace`

Record the journal id printed at the end, then:

```sh
sudo lcm journal show <id> --json
```

Attach the complete JSON. It contains the command sequence, snapshot name,
subvolume names, firmware entries, and every state transition.

## First boot

Record:

- whether firmware selected `LCM <target>` through `BootNext` without manual
  intervention,
- whether the fallback to the old system was needed,
- the exact boot error, if any,
- the output of `efibootmgr -v` after the first boot,
- `systemctl --failed` and `journalctl -b -p err`,
- `sudo lcm validate` and `/var/lib/lcm/validation.env`,
- whether the ESP journal copy exists under `/boot/efi/lcm/`.

## Commit and follow-up

```sh
sudo lcm commit --prune
sudo efibootmgr -v
sudo btrfs subvolume list /
```

State whether the old root, old firmware entry, and snapshot are gone, and
whether the new entry is first in `BootOrder`. If `--prune` was not used,
record the retained snapshot name instead.

## Result

- verdict: pass / pass with caveats / fail
- first reboot result:
- rollback tested: yes / no
- data preserved in `/home`: yes / no
- packages missing or broken:
- notes for the next tester:
