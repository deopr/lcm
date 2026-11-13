"""Unit tests for LCM core.  No root, network or real disks required."""

from __future__ import annotations

import argparse
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from lcm import bundle, pkgs
from lcm.cli import _apply_home_options, _looks_like_bundle, build_parser
from lcm.profile import DEFAULT_NEVER
from lcm.restore import _extract, _never
from lcm.assess import analyze, needed_space_bytes
from lcm.detect import (
    Boot,
    Distro,
    Hardware,
    Storage,
    SystemInfo,
    detect_boot,
    family_of,
    parse_os_release,
)
from lcm.mapping import Database, MappingStats
from lcm.profile import ConfigSpec, PackageSpec, Profile, UserSpec
from lcm.util import LcmError, parse_size, safe_join


def make_storage(**overrides) -> Storage:
    values = dict(
        root_source="/dev/nvme0n1p2[/@]",
        root_fstype="btrfs",
        root_options="subvol=/@,compress=zstd",
        root_subvol="@",
        pool_device="/dev/nvme0n1p2",
        pool_uuid="11111111-2222-3333-4444-555555555555",
        luks=False,
        luks_device=None,
        luks_uuid=None,
        esp_device="/dev/nvme0n1p1",
        esp_mount="/boot/efi",
        esp_uuid="ABCD-1234",
        esp_disk="/dev/nvme0n1",
        esp_partition=1,
        esp_free_bytes=512 * 1024 * 1024,
        free_bytes=100 * 1024**3,
        total_bytes=500 * 1024**3,
        btrfs_free_bytes=90 * 1024**3,
        home_separate=True,
        home_source="/dev/nvme0n1p2[/@home]",
        home_subvol="@home",
        home_uuid="11111111-2222-3333-4444-555555555555",
        home_fstype="btrfs",
    )
    values.update(overrides)
    return Storage(**values)


def make_system(**overrides) -> SystemInfo:
    distro = Distro(
        id="fedora",
        name="Fedora Linux",
        version="44",
        id_like=(),
        family="fedora",
    )
    values = dict(
        distro=distro,
        storage=make_storage(),
        boot=Boot(
            uefi=True,
            secure_boot=False,
            loader="uki",
            entries=[],
            esp_mount="/boot/efi",
        ),
        hardware=Hardware(
            cpu="Test CPU",
            memory_bytes=16 * 1024**3,
            gpus=["AMD Radeon"],
            gpu_vendors=["amd"],
            wifi=[],
            out_of_tree_modules=[],
            virtualization=None,
            kernel="6.0.0-test",
        ),
        users=[],
    )
    values.update(overrides)
    return SystemInfo(**values)


class TestOsRelease(unittest.TestCase):
    def test_quotes_and_comments(self):
        data = parse_os_release(
            '# comment\nID=fedora\nNAME="Fedora Linux"\nVERSION_ID=44\nID_LIKE="rhel centos"\n'
        )
        self.assertEqual(data["ID"], "fedora")
        self.assertEqual(data["NAME"], "Fedora Linux")
        self.assertEqual(data["ID_LIKE"], "rhel centos")

    def test_family(self):
        self.assertEqual(family_of("pikaos"), "debian")
        self.assertEqual(family_of("cachyos"), "arch")
        self.assertEqual(family_of("nobara"), "fedora")
        self.assertEqual(family_of("unknown"), "unknown")
        self.assertEqual(family_of("weird", "debian"), "debian")


class TestDetectBoot(unittest.TestCase):
    def test_non_uefi_does_not_crash(self):
        from unittest.mock import patch

        with patch("lcm.detect.os.path.isdir", return_value=False):
            boot = detect_boot(make_storage())
        self.assertFalse(boot.uefi)
        self.assertEqual(boot.entries, [])


class TestMapping(unittest.TestCase):
    def setUp(self):
        self.db = Database()

    def test_database_has_content(self):
        self.assertGreater(len(self.db.canonical_ids()), 100)

    def test_exact_distro_override(self):
        result = self.db.resolve("firefox", "debian", "debian")
        self.assertEqual(result.native, "firefox-esr")
        self.assertEqual(result.confidence, "exact")

    def test_family_fallback(self):
        result = self.db.resolve("firefox", "debian", "pikaos")
        self.assertEqual(result.native, "firefox-esr")

    def test_flatpak_only(self):
        result = self.db.resolve("discord", "arch", "arch")
        self.assertIsNone(result.native)
        self.assertEqual(result.flatpak, "com.discordapp.Discord")
        self.assertTrue(result.installable)

    def test_unknown(self):
        result = self.db.resolve("not-a-real-package", "arch")
        self.assertFalse(result.installable)
        self.assertEqual(result.confidence, "unknown")

    def test_reverse_lookup_and_same_family(self):
        result = self.db.resolve_raw("firefox", "fedora", "arch")
        self.assertEqual(result.canonical, "firefox")
        self.assertEqual(result.native, "firefox")
        same = self.db.resolve_raw("some-local-pkg", "arch", "arch")
        self.assertEqual(same.native, "some-local-pkg")
        self.assertEqual(same.confidence, "same-family")

    def test_stats(self):
        stats = MappingStats()
        stats.add(self.db.resolve("firefox", "arch"))
        stats.add(self.db.resolve("discord", "arch"))
        self.assertEqual(stats.total, 2)
        self.assertEqual(stats.native, 1)
        self.assertEqual(stats.flatpak, 1)
        self.assertEqual(stats.percent, 100.0)


class TestProfile(unittest.TestCase):
    def test_roundtrip(self):
        profile = Profile(
            name="test",
            users=[UserSpec(name="alice", uid=1000, groups=["wheel"])],
            packages=PackageSpec(
                native=["firefox", "git"], flatpak=["org.mozilla.firefox"]
            ),
            config=ConfigSpec(etc=["NetworkManager/system-connections"], home=[".config"]),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.lcm.yaml"
            profile.save(path)
            loaded = Profile.load(path)
        self.assertEqual(loaded.name, "test")
        self.assertEqual(loaded.users[0].name, "alice")
        self.assertEqual(loaded.packages.native, ["firefox", "git"])
        self.assertEqual(loaded.config.home, [".config"])

    def test_rejects_future_version(self):
        with self.assertRaises(LcmError):
            Profile.from_dict({"lcm": 99})

    def test_system_package_filter(self):
        from lcm.profile import is_system_package

        self.assertTrue(is_system_package("kernel-core"))
        self.assertTrue(is_system_package("amd-gpu-firmware"))
        self.assertTrue(is_system_package("aubio-devel"))
        self.assertFalse(is_system_package("firefox"))


class TestSizes(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(parse_size("1GiB"), 1024**3)
        self.assertEqual(parse_size("150 MiB"), 150 * 1024**2)
        self.assertEqual(parse_size("10G"), 10 * 1024**3)


class TestSafety(unittest.TestCase):
    def test_safe_join_rejects_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(LcmError):
                safe_join(Path(tmp), "/etc/passwd")

    def test_safe_join_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(LcmError):
                safe_join(Path(tmp), "../outside")
            with self.assertRaises(LcmError):
                safe_join(Path(tmp), "a/../../outside")

    def test_safe_join_accepts_normal(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = safe_join(Path(tmp), "a/b")
            self.assertTrue(str(result).startswith(str(Path(tmp).resolve())))


class TestBundle(unittest.TestCase):
    def test_create_verify_inspect(self):
        profile = Profile(
            name="bundle-test",
            users=[UserSpec(name="alice", uid=1000)],
            packages=PackageSpec(native=["git"]),
        )
        system = make_system()
        packages = {"capture": {"fidelity": "high", "notes": []}}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "test.lcmb"
            written = bundle.create(
                out, profile, packages, system, include_payload=False
            )
            self.assertTrue(written.exists())
            self.assertEqual(oct(written.stat().st_mode & 0o777), "0o600")
            self.assertEqual(bundle.verify(written), [])
            data = bundle.inspect(written)
            self.assertEqual(data["manifest"]["format"], 1)
            loaded = bundle.load(written)
            try:
                self.assertEqual(loaded.profile.name, "bundle-test")
                self.assertEqual(loaded.profile.packages.native, ["git"])
                self.assertFalse(loaded.manifest["counts"]["native"] == 0)
            finally:
                loaded.cleanup()

    def test_tamper_detected(self):
        profile = Profile(name="tamper", users=[UserSpec(name="alice")])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "t.lcmb"
            bad = Path(tmp) / "bad.lcmb"
            bundle.create(out, profile, {}, make_system(), include_payload=False)

            # Rewrite the archive with a modified profile so the checksum
            # mismatch is deterministic (flipping random gzip bytes can land
            # in padding and still decompress to the same content).
            import io
            import tarfile

            with tarfile.open(out, "r:gz") as source, tarfile.open(
                bad, "w:gz"
            ) as target:
                for member in source.getmembers():
                    if member.isfile():
                        payload = source.extractfile(member).read()
                        if member.name == "profile.yaml":
                            payload = payload.replace(b"tamper", b"hacked")
                        target.addfile(member, io.BytesIO(payload))
                    else:
                        target.addfile(member)

            problems = bundle.verify(bad)
            self.assertTrue(problems)
            self.assertTrue(any("mismatch" in item for item in problems))


class TestHomeCapture(unittest.TestCase):
    def test_full_home_includes_user_data_and_skips_junk(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            files = [
                "Documents/note.txt",
                "Pictures/pic.png",
                ".thunderbird/prefs.js",
                ".config/app/settings.ini",
                ".local/share/fonts/font.ttf",
                ".cache/blob/junk",
                "Downloads/big.iso",
                "Games/save.dat",
                ".local/share/Steam/steamapps/game.bin",
                ".local/share/lutris/game.yml",
                ".local/share/Trash/files/deleted",
                ".lcm-backup/stale.tar",
                ".config/google-chrome/Default/Cache/blob",
            ]
            for relative in files:
                path = home / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative, encoding="utf-8")

            out = Path(tmp) / "home.tar"
            bundle._tar_tree(home, ["."], DEFAULT_NEVER, out)
            with tarfile.open(out) as archive:
                names = {member.name for member in archive.getmembers()}

            for relative in (
                "Documents/note.txt",
                "Pictures/pic.png",
                ".thunderbird/prefs.js",
                ".config/app/settings.ini",
                ".local/share/fonts/font.ttf",
            ):
                self.assertIn(relative, names)

            for prefix in (
                ".cache",
                "Downloads",
                "Games",
                ".local/share/Steam",
                ".local/share/lutris",
                ".local/share/Trash",
                ".lcm-backup",
                ".config/google-chrome/Default/Cache",
            ):
                self.assertFalse(
                    any(
                        name == prefix or name.startswith(prefix + "/")
                        for name in names
                    ),
                    f"{prefix} leaked into the full-home capture",
                )

    def test_overlapping_patterns_do_not_duplicate_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            (home / "Documents").mkdir(parents=True)
            (home / "Documents/note.txt").write_text("note", encoding="utf-8")
            out = Path(tmp) / "home.tar"
            bundle._tar_tree(home, [".", "Documents"], DEFAULT_NEVER, out)
            with tarfile.open(out) as archive:
                names = [member.name for member in archive.getmembers()]
            self.assertEqual(len(names), len(set(names)))
            self.assertIn("Documents/note.txt", names)

    def test_never_matches_multi_component_prefix(self):
        self.assertTrue(_never(".local/share/Steam/apps/x", DEFAULT_NEVER))
        self.assertTrue(_never(".local/share/Trash/files/x", DEFAULT_NEVER))
        self.assertFalse(_never(".local/share/fonts/x", DEFAULT_NEVER))
        self.assertFalse(_never(".cache-notes/x", [".cache"]))
        self.assertTrue(_never(".config/app/Default/Cache/blob", ["Cache"]))


class TestHomeOptions(unittest.TestCase):
    def test_full_home_replaces_the_allowlist_and_keeps_junk_excludes(self):
        profile = Profile(config=ConfigSpec(home=[".config"], never=[".cache"]))
        _apply_home_options(
            profile, argparse.Namespace(full_home=True, include_home=[])
        )
        self.assertEqual(profile.config.home, ["."])
        self.assertTrue(set(DEFAULT_NEVER).issubset(profile.config.never))

    def test_include_home_adds_relative_paths(self):
        profile = Profile(config=ConfigSpec(home=[".config"]))
        _apply_home_options(
            profile,
            argparse.Namespace(
                full_home=False, include_home=["Documents", "Projects/notes"]
            ),
        )
        self.assertEqual(
            profile.config.home, [".config", "Documents", "Projects/notes"]
        )

    def test_include_home_overrides_a_default_exclusion(self):
        profile = Profile(
            config=ConfigSpec(home=[], never=["Downloads", ".cache"])
        )
        _apply_home_options(
            profile,
            argparse.Namespace(
                full_home=False, include_home=["Downloads/taxes.pdf"]
            ),
        )
        self.assertIn("Downloads/taxes.pdf", profile.config.home)
        self.assertNotIn("Downloads", profile.config.never)
        self.assertIn(".cache", profile.config.never)

    def test_include_home_rejects_absolute_and_traversal(self):
        profile = Profile(config=ConfigSpec(home=[".config"]))
        for bad in ("/etc", "../outside"):
            with self.assertRaises(LcmError):
                _apply_home_options(
                    profile, argparse.Namespace(full_home=False, include_home=[bad])
                )


class TestCliParsing(unittest.TestCase):
    def test_import_is_an_alias_for_restore(self):
        args = build_parser().parse_args(["import", "bundle.lcmb"])
        self.assertEqual(args.func.__name__, "cmd_restore")
        self.assertEqual(args.bundle, "bundle.lcmb")

    def test_export_full_home_flags(self):
        args = build_parser().parse_args(
            [
                "export",
                "out.lcmb",
                "--full-home",
                "--include-home",
                "Documents",
                "--include-home",
                "Projects",
            ]
        )
        self.assertTrue(args.full_home)
        self.assertEqual(args.include_home, ["Documents", "Projects"])


class TestRestoreFormatDetection(unittest.TestCase):
    def test_bundle_magic_and_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gz = root / "bundle.lcm"
            gz.write_bytes(b"\x1f\x8b" + b"rest")
            self.assertTrue(_looks_like_bundle(gz))
            tar = root / "plain.lcm"
            tar.write_bytes(b"\0" * 257 + b"ustar" + b"\0" * 100)
            self.assertTrue(_looks_like_bundle(tar))
            profile = root / "profile.lcm"
            profile.write_text("lcm: 1\nname: test\n")
            self.assertFalse(_looks_like_bundle(profile))


class TestAssessment(unittest.TestCase):
    def test_healthy_system_is_green(self):
        profile = Profile(
            name="a",
            users=[UserSpec(name="alice")],
            packages=PackageSpec(native=["firefox"]),
        )
        assessment = analyze(
            make_system(), "fedora", Database(), profile, {"fidelity": "high"}
        )
        self.assertEqual(assessment.verdict, "green")
        self.assertEqual(assessment.target_family, "fedora")

    def test_non_btrfs_is_red(self):
        profile = Profile(name="a", users=[UserSpec(name="alice")])
        system = make_system(storage=make_storage(root_fstype="ext4"))
        assessment = analyze(system, "arch", Database(), profile)
        self.assertEqual(assessment.verdict, "red")
        codes = {finding.code for finding in assessment.findings}
        self.assertIn("storage.fstype", codes)

    def test_unknown_target_is_red(self):
        profile = Profile(name="a", users=[UserSpec(name="alice")])
        assessment = analyze(make_system(), "plan9", Database(), profile)
        self.assertEqual(assessment.verdict, "red")

    def test_space_estimate_grows_with_packages(self):
        small = Profile(name="s", packages=PackageSpec(native=["git"]))
        large = Profile(
            name="l", packages=PackageSpec(native=[f"pkg{i}" for i in range(200)])
        )
        self.assertLess(needed_space_bytes(small), needed_space_bytes(large))


class TestPkgs(unittest.TestCase):
    def test_clean_dedupes_and_sorts(self):
        self.assertEqual(
            pkgs._clean([" git ", "git", "", "# comment", "curl"]),
            ["curl", "git"],
        )


class TestRestoreExtraction(unittest.TestCase):
    def _tar(self, path: Path, entries) -> None:
        with tarfile.open(path, "w") as archive:
            for name, kind, value in entries:
                info = tarfile.TarInfo(name)
                if kind == "dir":
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                elif kind == "file":
                    payload = value.encode()
                    info.size = len(payload)
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(payload))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = value
                    archive.addfile(info)

    def test_relative_symlink_is_kept_and_absolute_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tar_path = root / "payload.tar"
            self._tar(
                tar_path,
                [
                    (".config", "dir", ""),
                    (".config/conf", "file", "hello=1\n"),
                    (".config/rel", "symlink", "conf"),
                    (".config/abs", "symlink", "/usr/share/theme"),
                ],
            )
            home = root / "home"
            home.mkdir()
            count, notes = _extract(
                tar_path, home, root / "backup", [], apply=True
            )
            self.assertTrue((home / ".config/conf").is_file())
            self.assertTrue((home / ".config/rel").is_symlink())
            self.assertFalse((home / ".config/abs").is_symlink())
            self.assertEqual(count, 3)
            self.assertTrue(any("unsafe symlink" in note for note in notes))

    def test_excluded_paths_are_not_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tar_path = root / "payload.tar"
            self._tar(
                tar_path,
                [
                    (".config", "dir", ""),
                    (".config/conf", "file", "hello=1\n"),
                    (".cache", "dir", ""),
                    (".cache/junk", "file", "junk"),
                    (".local/share/Steam", "dir", ""),
                    (".local/share/Steam/game", "file", "game"),
                ],
            )
            home = root / "home"
            home.mkdir()
            count, _notes = _extract(
                tar_path, home, root / "backup", DEFAULT_NEVER, apply=True
            )
            self.assertTrue((home / ".config/conf").is_file())
            self.assertFalse((home / ".cache/junk").exists())
            self.assertFalse((home / ".local/share/Steam/game").exists())
            self.assertEqual(count, 2)

    def test_existing_symlink_ancestor_does_not_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            outside = root / "outside"
            home.mkdir()
            outside.mkdir()
            (home / ".config").symlink_to(outside, target_is_directory=True)
            tar_path = root / "payload.tar"
            self._tar(
                tar_path,
                [
                    (".config/evil", "symlink", "target"),
                    (".config/passwd", "file", "x"),
                ],
            )
            count, notes = _extract(
                tar_path, home, root / "backup", [], apply=True
            )
            self.assertFalse((outside / "evil").exists())
            self.assertFalse((outside / "passwd").exists())
            self.assertTrue(any("path escape" in note for note in notes))

    def test_bundle_rejects_top_level_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tar_path = root / "evil.tar"
            self._tar(
                tar_path,
                [
                    ("evil", "symlink", "../../outside"),
                    ("evil/passwd", "file", "x"),
                ],
            )
            with tarfile.open(tar_path) as archive:
                with self.assertRaises(LcmError):
                    bundle._safe_extract(archive, root / "out")


if __name__ == "__main__":
    unittest.main()
