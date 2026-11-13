"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lcm import __version__, assess, bundle, detect, install, mapping, pkgs, profile as profile_mod, restore, validate
from lcm.util import LcmError, Style


def _style(args: argparse.Namespace) -> Style:
    return Style(sys.stdout.isatty() and not getattr(args, "no_color", False))


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


def _apply_home_options(profile, args: argparse.Namespace) -> None:
    """Expand the profile's home allowlist for a complete user-data move."""
    if getattr(args, "full_home", False):
        profile.config.home = ["."]
        profile.config.never = sorted(
            {*profile_mod.DEFAULT_NEVER, *profile.config.never}
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
    profile.config.home = sorted({*profile.config.home, *cleaned})


def cmd_export(args: argparse.Namespace) -> int:
    system = detect.detect_system()
    database = mapping.Database()
    profile, capture = _profile_for(args, system, database)
    if args.name:
        profile.name = args.name
    _apply_home_options(profile, args)
    target = args.target or system.distro.id
    assessment = assess.analyze(system, target, database, profile, capture)

    out = Path(args.path)
    if out.is_dir() or args.path.endswith("/"):
        out = out / bundle.suggested_name(profile)
    written = bundle.create(
        out,
        profile,
        _packages_payload(assessment),
        system,
        include_payload=not args.no_payload,
    )
    payload = {
        "bundle": str(written),
        "size": written.stat().st_size,
        "profile": str(profile.name),
        "packages": assessment.packages.stats.to_dict(),
    }
    if getattr(args, "json", False):
        _emit_json(payload)
    else:
        print(f"Wrote {written}")
        print(
            f"  {assessment.packages.stats.total} packages · "
            f"{assessment.packages.stats.percent:.0f}% mapped for {target}"
        )
        if profile.warnings:
            print("  warnings: " + "; ".join(profile.warnings))
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

    loaded = bundle.load(path)
    try:
        report = restore.run(
            loaded,
            apply=args.apply,
            steps=args.step,
            assume_yes=args.yes,
            include_flatpak=not args.no_flatpak,
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
    install.commit(assume_yes=args.yes, keep_old=args.keep_old, force=args.force)
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
    parser = argparse.ArgumentParser(
        prog="lcm",
        description="Linux Continuity Manager: transactional distro replacement, "
        "with a rollback button.",
    )
    parser.add_argument("--version", action="version", version=f"lcm {__version__}")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--json", action="store_true", help="machine-readable output")

    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="read-only risk assessment for a target")
    check.add_argument("--target", required=True, help="target distro id, e.g. pikaos, arch, fedora")
    check.add_argument("--profile", help="use a .lcm.yaml profile instead of capturing")
    _add_json(check)
    check.set_defaults(func=cmd_check)

    plan = sub.add_parser("plan", help="show the exact migration plan")
    plan.add_argument("--target", required=True)
    plan.add_argument("--profile")
    _add_json(plan)
    plan.set_defaults(func=cmd_plan)

    export = sub.add_parser("export", help="capture this system into a .lcmb bundle")
    export.add_argument("path", help="output file or directory")
    export.add_argument("--name", help="profile name")
    export.add_argument("--target", help="target distro id for the mapping preview")
    export.add_argument("--profile", help="start from an existing profile")
    export.add_argument("--no-payload", action="store_true", help="metadata only")
    export.add_argument(
        "--full-home",
        action="store_true",
        help="include the whole home, excluding caches, Trash, Downloads and games",
    )
    export.add_argument(
        "--include-home",
        action="append",
        default=[],
        metavar="PATH",
        help="extra home-relative path to include (repeatable)",
    )
    _add_json(export)
    export.set_defaults(func=cmd_export)

    restore_cmd = sub.add_parser(
        "restore",
        aliases=["import"],
        help="apply a .lcmb/.lcm bundle or .lcm.yaml profile",
    )
    restore_cmd.add_argument(
        "bundle", help=".lcmb/.lcm bundle or .lcm/.lcm.yaml profile"
    )
    restore_cmd.add_argument("--apply", action="store_true", help="actually write changes")
    restore_cmd.add_argument("--step", help="packages,config,services")
    restore_cmd.add_argument(
        "--no-flatpak", action="store_true", help="skip Flatpak applications"
    )
    restore_cmd.add_argument(
        "--strict", action="store_true", help="exit 1 if any package failed"
    )
    restore_cmd.add_argument("--yes", action="store_true")
    _add_json(restore_cmd)
    restore_cmd.set_defaults(func=cmd_restore)

    replace_cmd = sub.add_parser("replace", help="build the target as a new btrfs subvolume")
    replace_cmd.add_argument("--target", required=True)
    replace_cmd.add_argument("--profile")
    replace_cmd.add_argument("--mirror", help="base mirror, or Arch bootstrap tarball URL")
    replace_cmd.add_argument("--suite", help="target suite/release")
    replace_cmd.add_argument("--repo", help="extra Debian-family repository line")
    replace_cmd.add_argument("--repo-key", help="keyring URL for --repo (.deb or .asc)")
    replace_cmd.add_argument("--package", action="append", help="extra package to install")
    replace_cmd.add_argument("--meta", action="append", help="target meta package(s)")
    replace_cmd.add_argument("--yes", action="store_true")
    replace_cmd.add_argument("--dry-run", action="store_true")
    replace_cmd.set_defaults(func=cmd_replace)

    commit = sub.add_parser("commit", help="delete the old system after validation")
    commit.add_argument("--yes", action="store_true")
    commit.add_argument("--keep-old", action="store_true", help="keep the old subvolume")
    commit.add_argument("--force", action="store_true", help="ignore failed validation")
    commit.set_defaults(func=cmd_commit)

    rollback = sub.add_parser("rollback", help="make the old system the default boot entry")
    rollback.add_argument("--entry", help="explicit BootNNNN entry")
    rollback.set_defaults(func=cmd_rollback)

    recover = sub.add_parser("recover", help="inspect or clean up unfinished attempts")
    recover.add_argument("--cleanup", metavar="ID")
    recover.add_argument("--yes", action="store_true")
    _add_json(recover)
    recover.set_defaults(func=cmd_recover)

    validate_cmd = sub.add_parser("validate", help="run first-boot checks on this system")
    validate_cmd.add_argument("--max-failed", type=int, default=0)
    validate_cmd.add_argument("--no-write", action="store_true")
    _add_json(validate_cmd)
    validate_cmd.set_defaults(func=cmd_validate)

    journal = sub.add_parser("journal", help="list or show replacement journals")
    journal.add_argument("action", nargs="?", choices=["list", "show"], default="list")
    journal.add_argument("id", nargs="?")
    _add_json(journal)
    journal.set_defaults(func=cmd_journal)

    mapping_cmd = sub.add_parser("mapping", help="resolve a canonical package id")
    mapping_cmd.add_argument("name")
    mapping_cmd.add_argument("--to", help="target distro id")
    mapping_cmd.add_argument("--from", dest="source", help="source distro id for reverse lookup")
    _add_json(mapping_cmd)
    mapping_cmd.set_defaults(func=cmd_mapping)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except LcmError as exc:
        print(f"lcm: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("lcm: interrupted", file=sys.stderr)
        return 130
