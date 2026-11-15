from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

from release_metadata import release_notes, validate_ref


SCRIPT = Path(__file__).with_name("release_metadata.py").resolve()
REPOSITORY = SCRIPT.parents[2]


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "0.12.1"\n', encoding="utf-8"
        )

    def test_matching_tag_and_release_branch(self):
        for name, kind in (("v0.12.1", "tag"), ("release-0.12.1", "branch")):
            with self.subTest(name=name):
                self.assertEqual(validate_ref(name, kind, self.root), "0.12.1")

    def test_mismatched_version_is_refused(self):
        for name, kind in (("v0.12.0", "tag"), ("release-0.12.0", "branch")):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "does not match workspace"):
                    validate_ref(name, kind, self.root)

    def test_wrong_prefix_or_ref_type_is_refused(self):
        for name, kind in (
            ("release-0.12.1", "tag"),
            ("v0.12.1", "branch"),
            ("0.12.1", "tag"),
            ("v0.12.1", "other"),
        ):
            with self.subTest(name=name, kind=kind):
                with self.assertRaises(ValueError):
                    validate_ref(name, kind, self.root)

    def test_curated_notes_only_include_the_matching_release(self):
        (self.root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n\nFuture work\n\n"
            "## [0.12.1] - 2026-11-15\n\nHire Bella without linking mail.\n\n"
            "## [0.12.0] - 2026-11-13\n\nPrevious release\n",
            encoding="utf-8",
        )
        self.assertEqual(
            release_notes("0.12.1", self.root),
            "## [0.12.1] - 2026-11-15\n\nHire Bella without linking mail.",
        )

    def test_missing_changelog_uses_generated_notes(self):
        self.assertEqual(release_notes("0.12.1", self.root), "")
        self.run_release_helper()

    def test_missing_version_section_uses_generated_notes(self):
        (self.root / "CHANGELOG.md").write_text(
            "## [0.12.0] - 2026-11-13\n\nPrevious release\n", encoding="utf-8"
        )
        self.assertEqual(release_notes("0.12.1", self.root), "")
        self.run_release_helper()

    def run_release_helper(self):
        notes = self.root / "notes.md"
        notes.write_text("Stale notes must not be reused", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "v0.12.1", "tag", "--notes-file", str(notes)],
            cwd=self.root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(notes.read_text(encoding="utf-8"), "")

    def test_workspace_lock_versions_match_the_release(self):
        cargo = tomllib.loads((REPOSITORY / "Cargo.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((REPOSITORY / "Cargo.lock").read_text(encoding="utf-8"))
        version = cargo["workspace"]["package"]["version"]
        for member in cargo["workspace"]["members"]:
            manifest = tomllib.loads(
                (REPOSITORY / member / "Cargo.toml").read_text(encoding="utf-8")
            )
            name = manifest["package"]["name"]
            packages = [package for package in lock["package"] if package["name"] == name]
            self.assertEqual(len(packages), 1, name)
            self.assertEqual(packages[0]["version"], version, name)


if __name__ == "__main__":
    unittest.main()
