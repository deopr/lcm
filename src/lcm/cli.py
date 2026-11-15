"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
import time
from pathlib import Path

from lcm import __version__, assess, bundle, detect, install, mapping, pkgs, profile as profile_mod, restore, validate
from lcm.util import LcmError, Style, human_bytes, human_duration


class _Parser(argparse.ArgumentParser):
    """Keep command examples readable instead of re-wrapping them."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(*args, **kwargs)


def _style(args: argparse.Namespace) -> Style:
    return Style(sys.stdout.isatty() and not getattr(args, "no_color", False))


def _info(args: argparse.Namespace, message: str) -> None:
    """Human status goes to stderr when stdout must stay valid JSON."""
    stream = sys.stderr if getattr(args, "json", False) else sys.stdout
    print(message, file=stream, flush=True)


class _ExportProgress:
    """Live phase progress, including elapsed and estimated time left.

    Capture, checksum and compression are separate phases.  Each one reports
    bytes completed and total bytes, so a long single-file read or the silent
    verification/compression passes still show movement and an ETA.
    """

    def __init__(self) -> None:
        self.tty = sys.stderr.isatty()
        self.last = 0.0
        self.key: str | None = None
        self.active = False
        self.phases: list[tuple[str, float]] = []

    @staticmethod
    def _name(event: bundle.ProgressEvent) -> str:
        if event.phase == "capture":
            return f"capture {event.label}"
        if event.phase == "checksums":
            return "verify checksums"
        if event.phase == "compress":
            return "compress bundle"
        return event.label or event.phase

    def __call__(self, event: bundle.ProgressEvent) -> None:
        key = f"{event.phase}:{event.label}"
        if key != self.key:
            self._end_line()
            self.key = key
            self.last = 0.0
        if event.finished:
            self._render(event, finished=True)
            self._end_line()
            self.phases.append((self._name(event), event.elapsed))
            self.key = None
            return
        now = time.monotonic()
        if now - self.last < (1.0 if self.tty else 20.0):
            return
        self.last = now
        self._render(event)

    def _render(
        self, event: bundle.ProgressEvent, *, finished: bool = False
    ) -> None:
        name = self._name(event)
        if finished:
            text = (
                f"  {name}: done in {human_duration(event.elapsed)} "
                f"({human_bytes(event.done)}"
            )
            if event.files:
                text += f", {event.files:,} files"
            text += ")"
            if event.phase == "compress" and event.output is not None:
                text += f", {human_bytes(event.output)} written"
        else:
            parts = []
            if event.total is not None and event.total > 0:
                percent = min(100, int(event.done * 100 / event.total))
                parts.append(f"{percent}%")
                parts.append(
                    f"{human_bytes(event.done)} / {human_bytes(event.total)}"
                )
            else:
                parts.append(human_bytes(event.done))
            if event.total_files:
                parts.append(
                    f"{event.files:,} / {event.total_files:,} files"
                )
            elif event.files:
                parts.append(f"{event.files:,} files")
            if event.phase == "compress" and event.output:
                parts.append(f"{human_bytes(event.output)} written")
            parts.append(f"elapsed {human_duration(event.elapsed)}")
            if (
                event.total is not None
                and event.done > 0
                and event.done < event.total
                and event.elapsed >= 0.5
            ):
                rate = event.done / event.elapsed
                remaining = (event.total - event.done) / rate
                parts.append(f"~{human_duration(remaining)} left")
            elif event.total is not None and event.done >= event.total:
                parts.append("finishing")
            else:
                parts.append("estimating time left")
            text = f"  {name}: " + " | ".join(parts)

        self.active = True
        if self.tty:
            print(f"\r{text}\033[K", end="", file=sys.stderr, flush=True)
        else:
            print(text, file=sys.stderr, flush=True)

    def _end_line(self) -> None:
        if self.active and self.tty:
            print(file=sys.stderr)
        self.active = False

    def finish(self) -> None:
        self._end_line()

    def render_summary(self) -> str:
        if not self.phases:
            return ""
        width = max(len(name) for name, _ in self.phases)
        lines = ["Phase timings:"]
        for name, seconds in self.phases:
            lines.append(f"  {name:<{width}}  {human_duration(seconds)}")
        total = sum(seconds for _, seconds in self.phases)
        lines.append(f"  {'total':<{width}}  {human_duration(total)}")
        return "\n".join(lines)

    def timings(self) -> list[dict]:
        return [
            {"phase": name, "seconds": round(seconds, 3)}
            for name, seconds in self.phases
        ]


def _emit_json(data) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output"
    )


def _profile_for(args, system, database):
    """Load a profile, or capture the current system into one."""
    if getattr(args, "profile", None):
        return profile_mod.Profile.load(args.profile), {}
    capture = pkgs.capture(system.distro.family)
    flatpaks = pkgs.capture_flatpak()
    profile = profile_mod.Profile.from_system(system, database, capture, flatpaks)
    return profile, capture.to_dict()


def _packages_payload(assessment) -> dict:
    return {
        "source_family": assessment.system.distro.family,
        "target_family": assessment.target_family,
        "capture": assessment.packages.capture,
        "resolutions": [item.to_dict() for item in assessment.packages.resolutions],
        "stats": assessment.packages.stats.to_dict(),
        "flatpak": assessment.packages.flatpak,
    }


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_check(args: argparse.Namespace) -> int:
    system = detect.detect_system()
    database = mapping.Database()
    profile, capture = _profile_for(args, system, database)
    for warning in profile.warnings:
        print(f"note: {warning}", file=sys.stderr)
    assessment = assess.analyze(system, args.target, database, profile, capture)
    if getattr(args, "json", False):
        _emit_json(assessment.to_dict())
    else:
        print(assess.render(assessment, _style(args)))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    system = detect.detect_system()
    database = mapping.Database()
    profile, capture = _profile_for(args, system, database)
    assessment = assess.analyze(system, args.target, database, profile, capture)
    if getattr(args, "json", False):
        payload = assessment.to_dict()
        payload["steps"] = [
            {"phase": phase, "description": description, "commands": commands}
            for phase, description, commands in assess.plan_steps(assessment)
        ]
        _emit_json(payload)
    else:
        print(assess.render(assessment, _style(args)))
        print()
        print(assess.render_plan(assessment, _style(args)))
    return 0


def _pattern_covers(pattern: str, path: str) -> bool:
    """True when an exclusion pattern is the path itself or one of its parents."""
    pattern_parts = Path(pattern).parts
    path_parts = Path(path).parts
    return bool(pattern_parts) and path_parts[: len(pattern_parts)] == pattern_parts


def _apply_home_options(profile, args: argparse.Namespace) -> None:
    """Expand the profile's home allowlist for a complete user-data move."""
    full_home = getattr(args, "full_home", False)
    if full_home:
        profile.config.home = ["."]
        profile.config.never = sorted(
            {str(item) for item in profile_mod.DEFAULT_NEVER}
            | {str(item) for item in profile.config.never}
        )
    extras = list(getattr(args, "include_home", None) or [])
    if not extras:
        return
    cleaned: list[str] = []
    for item in extras:
        candidate = Path(item).expanduser()
        if candidate.is_absolute() or ".." in candidate.parts:
            raise LcmError(
                "--include-home paths must be relative to the user's home "
                f"(got {item!r})"
            )
        cleaned.append(str(candidate))
    if not full_home:
        profile.config.home = sorted({*profile.config.home, *cleaned})
    # An explicit --include-home wins over a default exclusion, so
    # `--include-home Downloads` can bring back a normally skipped path.
    profile.config.never = [
        str(pattern)
        for pattern in profile.config.never
        if not any(_pattern_covers(str(pattern), item) for item in cleaned)
    ]


def _export_destination(args: argparse.Namespace, profile) -> Path:
    """Resolve where the bundle should be written.

    PATH and --output are equivalent; a file, an existing directory or a
    trailing slash are all accepted.  With no destination, use the current
    directory and a timestamped name.
    """
    positional = getattr(args, "path", None)
    option = getattr(args, "output", None)
    if positional and option:
        raise LcmError(
            "choose the export destination once: give PATH or --output, not both"
        )
    chosen = option or positional
    if not chosen:
        return Path.cwd() / bundle.suggested_name(profile)

    out = Path(chosen).expanduser()
    if out.is_dir() or str(chosen).endswith(("/", os.sep)):
        out = out / bundle.suggested_name(profile)
    if out.suffix.lower() != ".lcmb":
        out = out.with_name(out.name + ".lcmb")
    return Path(os.path.abspath(out))


def cmd_export(args: argparse.Namespace) -> int:
    system = detect.detect_system()
    database = mapping.Database()
    profile, capture = _profile_for(args, system, database)
    if args.name:
        profile.name = args.name
    _apply_home_options(profile, args)
    target = args.target or system.distro.id

    out = _export_destination(args, profile)
    if out.exists() and not getattr(args, "force", False):
        raise LcmError(
            f"refusing to overwrite an existing bundle: {out}\n"
            "choose another name, or pass --force to replace it"
        )
    if not out.parent.is_dir():
        raise LcmError(
            f"output directory does not exist: {out.parent}\n"
            "create or mount it first (for example: mkdir -p /mnt/storage)"
        )
    if not os.access(out.parent, os.W_OK):
        raise LcmError(f"output directory is not writable: {out.parent}")

    staging = None
    if getattr(args, "staging_dir", None):
        staging = Path(
            os.path.abspath(Path(args.staging_dir).expanduser())
        )
        if not staging.is_dir():
            raise LcmError(
                f"staging directory does not exist: {staging}\n"
                "create or mount it first"
            )
        if not os.access(staging, os.W_OK):
            raise LcmError(f"staging directory is not writable: {staging}")

    free = shutil.disk_usage(out.parent).free
    _info(args, f"Destination: {out}")
    _info(args, f"  free space: {human_bytes(free)}")
    if staging is not None:
        staging_free = shutil.disk_usage(staging).free
        _info(
            args,
            f"Staging: {staging} ({human_bytes(staging_free)} free)",
        )
    else:
        _info(args, "Staging: next to the output (same filesystem)")
    if args.full_home:
        _info(
            args,
            "Mode: full home. Staging and the bundle are large; "
            "check the free space above.",
        )

    assessment = assess.analyze(system, target, database, profile, capture)
    progress = _ExportProgress()
    try:
        written = bundle.create(
            out,
            profile,
            _packages_payload(assessment),
            system,
            include_payload=not args.no_payload,
            staging_dir=staging,
            progress=progress,
        )
    finally:
        if progress is not None:
            progress.finish()

    size = written.stat().st_size
    payload = {
        "bundle": str(written),
        "size": size,
        "profile": str(profile.name),
        "packages": assessment.packages.stats.to_dict(),
        "staging": str(staging) if staging else str(written.parent),
        "timings": progress.timings() if progress else [],
    }
    if getattr(args, "json", False):
        _emit_json(payload)
        return 0

    print(f"Wrote {written} ({human_bytes(size)})")
    print(
        f"  {assessment.packages.stats.total} packages · "
        f"{assessment.packages.stats.percent:.0f}% mapped for {target}"
    )
    if progress:
        summary = progress.render_summary()
        if summary:
            print()
            print(summary)
    if args.full_home:
        print(
            "  This bundle may contain credentials; it is mode 0600. "
            "Encrypt the disk or NAS it lives on."
        )
    if profile.warnings:
        print("  warnings: " + "; ".join(profile.warnings))
    print()
    print("Preview it on the target machine with:")
    print(f"  lcm restore {shlex.quote(str(written))}")
    print("Apply it with:")
    print(
        f"  sudo lcm restore {shlex.quote(str(written))} --apply --yes"
    )
    return 0


def _looks_like_bundle(path: Path) -> bool:
    """Detect a bundle by content, so a bundle renamed to .lcm still works."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(512)
    except OSError:
        return False
    return head.startswith(b"\x1f\x8b") or head[257:262] == b"ustar"


def cmd_restore(args: argparse.Namespace) -> int:
    path = Path(args.bundle)
    suffix = path.suffix.lower()
    is_profile = suffix in {".yaml", ".yml"} or (
        suffix == ".lcm" and not _looks_like_bundle(path)
    )
    if is_profile:
        loaded_profile = profile_mod.Profile.load(path)
        report = restore.run_profile(
            loaded_profile,
            apply=args.apply,
            steps=args.step,
            assume_yes=args.yes,
            include_flatpak=not args.no_flatpak,
            try_raw=args.try_raw,
        )
        if getattr(args, "json", False):
            payload = dict(report.__dict__)
            payload["backup_root"] = (
                str(report.backup_root) if report.backup_root else None
            )
            _emit_json(payload)
        else:
            print(restore.render(report, _style(args)))
        return 1 if args.strict and report.failed else 0

    loaded = bundle.load(path, work_dir=getattr(args, "work_dir", None))
    try:
        report = restore.run(
            loaded,
            apply=args.apply,
            steps=args.step,
            assume_yes=args.yes,
            include_flatpak=not args.no_flatpak,
            try_raw=args.try_raw,
        )
        if getattr(args, "json", False):
            payload = dict(report.__dict__)
            payload["backup_root"] = str(report.backup_root) if report.backup_root else None
            _emit_json(payload)
        else:
            print(restore.render(report, _style(args)))
    finally:
        loaded.cleanup()
    return 1 if args.strict and report.failed else 0


def cmd_replace(args: argparse.Namespace) -> int:
    system = detect.detect_system()
    database = mapping.Database()
    profile, capture = _profile_for(args, system, database)
    journal = install.replace(
        system,
        profile,
        args.target,
        assume_yes=args.yes,
        dry_run=args.dry_run,
        mirror=args.mirror,
        suite=args.suite,
        repo=args.repo,
        repo_key=args.repo_key,
        extra_packages=args.package or [],
        meta_packages=args.meta or [],
        capture=capture,
    )
    print(f"Journal: {journal.id}")
    return 0


def cmd_commit(args: argparse.Namespace) -> int:
    install.commit(
        assume_yes=args.yes,
        keep_old=args.keep_old,
        prune_backup=args.prune,
        force=args.force,
    )
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    install.rollback(entry=args.entry)
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    message = install.recover(cleanup=args.cleanup, assume_yes=args.yes)
    if getattr(args, "json", False):
        _emit_json({"message": message})
    else:
        print(message)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    system = detect.detect_system()
    journal = install.Journal.latest()
    expected = None
    if journal is not None and journal.data.get("new_subvol"):
        expected = str(journal.data["new_subvol"])
    report = validate.collect(
        expected_subvol=expected,
        max_failed_units=args.max_failed,
    )
    if not args.no_write:
        validate.write(report, system.storage.esp_mount)
    if getattr(args, "json", False):
        _emit_json(report)
    else:
        print(validate.render(report, _style(args)))
    return 0 if report["ok"] else 1


def cmd_journal(args: argparse.Namespace) -> int:
    if args.action == "show":
        if not args.id:
            raise LcmError("journal show requires an id")
        journal = install.Journal.load(args.id)
        _emit_json(journal.data)
        return 0
    journals = install.Journal.all()
    if getattr(args, "json", False):
        _emit_json([journal.data for journal in journals])
        return 0
    if not journals:
        print("No journals.")
        return 0
    print(f"{'id':<28} {'state':<12} target")
    for journal in journals:
        print(
            f"{journal.id:<28} {journal.state:<12} "
            f"{journal.data.get('new_subvol', '?')}"
        )
    return 0


def cmd_mapping(args: argparse.Namespace) -> int:
    database = mapping.Database()
    target_family = detect.family_of(args.to) if args.to else detect.detect_distro().family
    target_id = args.to if args.to else detect.detect_distro().id
    canonical = args.name
    if args.source:
        found = database.canonical_for(detect.family_of(args.source), args.name)
        if not found:
            raise LcmError(
                f"{args.name!r} is not in the mapping database for {args.source}"
            )
        canonical = found
    resolution = database.resolve(canonical, target_family, target_id)
    entry = database.get(canonical)
    if getattr(args, "json", False):
        _emit_json({"entry": entry, "resolution": resolution.to_dict()})
        return 0
    print(f"{canonical} -> {target_family} ({target_id})")
    print(f"  native:     {resolution.native or '-'}")
    print(f"  flatpak:    {resolution.flatpak or '-'}")
    print(f"  confidence: {resolution.confidence}")
    if resolution.note:
        print(f"  note:       {resolution.note}")
    if not entry:
        print("  (not in database)")
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="lcm",
        description=(
            "Linux Continuity Manager: move this machine to another distro,\n"
            "or carry its setup to a fresh install with a portable .lcmb bundle."
        ),
        epilog=(
            "Common workflows:\n"
            "  lcm export -o ~/lcm-backup.lcmb\n"
            "  lcm export --full-home -o /mnt/storage/lcm-full.lcmb\n"
            "  lcm export --full-home -o /mnt/nas/lcm-full.lcmb "
            "--staging-dir /mnt/storage\n"
            "  lcm restore /mnt/storage/lcm-full.lcmb\n"
            "  sudo lcm restore /mnt/storage/lcm-full.lcmb --apply --yes\n"
            "  lcm check --target arch\n"
            "  lcm plan --target arch\n"
            "\n"
            "Run 'lcm <command> --help' for options and more examples."
        ),
    )
    parser.add_argument("--version", action="version", version=f"lcm {__version__}")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--json", action="store_true", help="machine-readable output")

    sub = parser.add_subparsers(
        dest="command", title="commands", metavar="<command>"
    )

    check = sub.add_parser(
        "check",
        help="check whether this machine can be replaced (read-only)",
        description="Assess this machine against a target distro. Nothing is changed.",
        epilog=(
            "Examples:\n"
            "  lcm check --target arch\n"
            "  lcm check --target debian --profile workstation.lcm.yaml"
        ),
    )
    check.add_argument(
        "--target", required=True, help="target distro id, e.g. arch, debian, fedora"
    )
    check.add_argument(
        "--profile", help="use this .lcm.yaml instead of capturing the current system"
    )
    _add_json(check)
    check.set_defaults(func=cmd_check)

    plan = sub.add_parser(
        "plan",
        help="show what replace would do (read-only)",
        description="Show the exact steps replace would run. Nothing is changed.",
        epilog=(
            "Examples:\n"
            "  lcm plan --target arch\n"
            "  lcm plan --target debian --profile workstation.lcm.yaml"
        ),
    )
    plan.add_argument(
        "--target", required=True, help="target distro id, e.g. arch, debian, fedora"
    )
    plan.add_argument(
        "--profile", help="use this .lcm.yaml instead of capturing the current system"
    )
    _add_json(plan)
    plan.set_defaults(func=cmd_plan)

    export = sub.add_parser(
        "export",
        aliases=["backup"],
        help="save this machine as a portable .lcmb file",
        description=(
            "Capture packages, dotfiles and optionally personal files into one\n"
            "portable .lcmb file. This is a continuity backup, not a disk image."
        ),
        epilog=(
            "Examples:\n"
            "  lcm export -o ~/lcm-backup.lcmb\n"
            "  lcm export --full-home -o /mnt/storage/lcm-full.lcmb\n"
            "  lcm export --full-home -o /mnt/nas/lcm-full.lcmb "
            "--staging-dir /mnt/storage\n"
            "  lcm export --include-home Documents --include-home Projects "
            "-o /mnt/storage/lcm.lcmb\n"
            "  lcm export --no-payload -o /tmp/packages.lcmb\n"
            "\n"
            "Staging defaults to the output's filesystem. Use --staging-dir when\n"
            "the output is on a NAS and you want scratch space on a local disk.\n"
            "A full-home export needs room for the staged payload plus the\n"
            "compressed .lcmb."
        ),
    )
    export.add_argument(
        "path",
        nargs="?",
        help="destination file or directory (same as --output)",
    )
    export.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="where to write the .lcmb; a file or an existing directory",
    )
    export.add_argument("--name", help="profile name (default: hostname)")
    export.add_argument(
        "--target", help="target distro id for the package-mapping preview"
    )
    export.add_argument("--profile", help="start from an existing .lcm.yaml")
    export.add_argument(
        "--no-payload",
        action="store_true",
        help="metadata only; skip home and /etc file payloads",
    )
    export.add_argument(
        "--full-home",
        action="store_true",
        help=(
            "include the whole home except caches, Trash, Downloads and games "
            "(can be very large)"
        ),
    )
    export.add_argument(
        "--include-home",
        action="append",
        default=[],
        metavar="PATH",
        help="add a home-relative path (repeatable; overrides an exclusion)",
    )
    export.add_argument(
        "--staging-dir",
        metavar="DIR",
        help="scratch space for payload tars (default: next to the output)",
    )
    export.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing bundle",
    )
    _add_json(export)
    export.set_defaults(func=cmd_export)

    restore_cmd = sub.add_parser(
        "restore",
        aliases=["import"],
        help="preview or apply a .lcmb bundle on this machine",
        description=(
            "Apply packages and configuration from a bundle or profile.\n"
            "The default is a dry run; --apply actually writes changes."
        ),
        epilog=(
            "Examples:\n"
            "  lcm restore /mnt/storage/lcm-full.lcmb\n"
            "  sudo lcm restore /mnt/storage/lcm-full.lcmb --apply --yes\n"
            "  sudo lcm restore bundle.lcmb --apply --step packages\n"
            "  sudo lcm restore bundle.lcmb --apply --try-raw --no-flatpak\n"
            "  lcm restore big.lcmb --work-dir /mnt/storage/lcm-work"
        ),
    )
    restore_cmd.add_argument(
        "bundle", help=".lcmb/.lcm bundle or .lcm/.lcm.yaml profile"
    )
    restore_cmd.add_argument(
        "--apply",
        action="store_true",
        help="write changes (without this, restore only previews)",
    )
    restore_cmd.add_argument(
        "--step",
        metavar="STEPS",
        help="comma-separated steps: packages,config,services",
    )
    restore_cmd.add_argument(
        "--no-flatpak", action="store_true", help="skip Flatpak applications"
    )
    restore_cmd.add_argument(
        "--try-raw",
        action="store_true",
        help="also try unmapped source package names unchanged (best effort)",
    )
    restore_cmd.add_argument(
        "--work-dir",
        metavar="DIR",
        help=(
            "unpack the bundle here instead of /tmp; needs enough free space "
            "for the uncompressed payload"
        ),
    )
    restore_cmd.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any package could not be installed",
    )
    restore_cmd.add_argument(
        "--yes", action="store_true", help="do not ask for confirmation"
    )
    _add_json(restore_cmd)
    restore_cmd.set_defaults(func=cmd_restore)

    replace_cmd = sub.add_parser(
        "replace",
        help="build another distro beside this one (advanced)",
        description=(
            "Build a new distro in a btrfs subvolume without touching the\n"
            "running system. The old system stays bootable until commit."
        ),
        epilog=(
            "Examples:\n"
            "  lcm check --target debian\n"
            "  sudo lcm replace --target debian --dry-run\n"
            "  sudo lcm replace --target debian --yes"
        ),
    )
    replace_cmd.add_argument(
        "--target", required=True, help="target distro id, e.g. arch, debian, fedora"
    )
    replace_cmd.add_argument(
        "--profile", help="use this .lcm.yaml instead of capturing the current system"
    )
    replace_cmd.add_argument(
        "--mirror", help="base mirror, or Arch bootstrap tarball URL"
    )
    replace_cmd.add_argument("--suite", help="target suite/release")
    replace_cmd.add_argument("--repo", help="extra Debian-family repository line")
    replace_cmd.add_argument(
        "--repo-key", help="keyring URL for --repo (.deb or .asc)"
    )
    replace_cmd.add_argument(
        "--package", action="append", help="extra package to install (repeatable)"
    )
    replace_cmd.add_argument(
        "--meta", action="append", help="target meta package(s) (repeatable)"
    )
    replace_cmd.add_argument(
        "--yes", action="store_true", help="do not ask for confirmation"
    )
    replace_cmd.add_argument(
        "--dry-run", action="store_true", help="show the plan and commands only"
    )
    replace_cmd.set_defaults(func=cmd_replace)

    commit = sub.add_parser(
        "commit",
        help="delete the old system after the new one validates",
        description=(
            "Remove the old subvolume and firmware entry. The pre-replace\n"
            "@lcm-backup-* snapshot is kept unless --prune is passed.\n"
            "Run this from the new system after first-boot validation has passed."
        ),
    )
    commit.add_argument(
        "--yes", action="store_true", help="do not ask for confirmation"
    )
    commit.add_argument(
        "--keep-old", action="store_true", help="keep the old subvolume"
    )
    commit.add_argument(
        "--prune",
        action="store_true",
        help="also delete the pre-replace @lcm-backup-* snapshot (kept by default)",
    )
    commit.add_argument(
        "--force", action="store_true", help="ignore failed validation"
    )
    commit.set_defaults(func=cmd_commit)

    rollback = sub.add_parser(
        "rollback",
        help="boot the old system again",
        description="Make the old firmware entry first and clear any one-shot BootNext.",
    )
    rollback.add_argument("--entry", help="explicit BootNNNN entry")
    rollback.set_defaults(func=cmd_rollback)

    recover = sub.add_parser(
        "recover",
        help="inspect or clean up unfinished replacements",
        description="List replacement journals or remove an unfinished target.",
    )
    recover.add_argument("--cleanup", metavar="ID")
    recover.add_argument(
        "--yes", action="store_true", help="do not ask for confirmation"
    )
    _add_json(recover)
    recover.set_defaults(func=cmd_recover)

    validate_cmd = sub.add_parser(
        "validate",
        help="re-run first-boot checks on this system",
        description="Check services, root subvolume, network, GPU and audio.",
    )
    validate_cmd.add_argument("--max-failed", type=int, default=0)
    validate_cmd.add_argument(
        "--no-write", action="store_true", help="do not write validation results"
    )
    _add_json(validate_cmd)
    validate_cmd.set_defaults(func=cmd_validate)

    journal = sub.add_parser(
        "journal",
        help="inspect replacement history",
        description="List replacement journals or show one in detail.",
    )
    journal.add_argument(
        "action", nargs="?", choices=["list", "show"], default="list"
    )
    journal.add_argument("id", nargs="?")
    _add_json(journal)
    journal.set_defaults(func=cmd_journal)

    mapping_cmd = sub.add_parser(
        "mapping",
        help="look up how a package maps between distros",
        description=(
            "Resolve a canonical package id to a distro package, or reverse-map\n"
            "a distro package name."
        ),
        epilog=(
            "Examples:\n"
            "  lcm mapping firefox --to debian\n"
            "  lcm mapping firefox-esr --from debian --to arch"
        ),
    )
    mapping_cmd.add_argument("name", help="canonical id or distro package name")
    mapping_cmd.add_argument("--to", help="target distro id")
    mapping_cmd.add_argument(
        "--from", dest="source", help="source distro id for reverse lookup"
    )
    _add_json(mapping_cmd)
    mapping_cmd.set_defaults(func=cmd_mapping)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except LcmError as exc:
        print(f"lcm: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("lcm: interrupted", file=sys.stderr)
        return 130
