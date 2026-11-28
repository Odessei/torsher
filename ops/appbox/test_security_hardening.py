import os
import datetime
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scan_git_history import blocked_path, commit_range


class GitHistoryTest(unittest.TestCase):
    def test_private_filename_policy(self):
        for name in (".env", "apps/server/.env.local", "config/.env.prod",
                     ".env.production", ".env.appbox", ".env.test", "key.pem"):
            self.assertTrue(blocked_path(name))
        for name in (".env.example", ".env.prod.example", "apps/server/.env.test", "env.d.ts"):
            self.assertFalse(blocked_path(name))

    def test_missing_or_unrelated_base_keeps_intermediate_history(self):
        with tempfile.TemporaryDirectory() as temp:
            old_dir = Path.cwd()
            def git(*args):
                return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()
            try:
                os.chdir(temp)
                git("init")
                git("config", "user.email", "test@example.test")
                git("config", "user.name", "History fixture")
                git("commit", "--allow-empty", "-m", "root")
                base = git("rev-parse", "HEAD")
                git("commit", "--allow-empty", "-m", "second")
                git("commit", "--allow-empty", "-m", "third")
                self.assertEqual(len(git("rev-list", commit_range(base)).splitlines()), 2)
                git("update-ref", "refs/remotes/origin/main", base)
                self.assertEqual(
                    len(git("rev-list", commit_range("", "refs/remotes/origin/main")).splitlines()), 2,
                )
                for value in ("", "0" * 40, "f" * 40):
                    self.assertEqual(len(git("rev-list", commit_range(value)).splitlines()), 3)
                git("checkout", "--detach", base)
                git("commit", "--allow-empty", "-m", "replacement")
                self.assertEqual(len(git("rev-list", commit_range("")).splitlines()), 2)
            finally:
                os.chdir(old_dir)


@unittest.skipUnless(os.name == "posix", "Appbox requires Unix file and daemon interfaces")
class AppboxHardeningTest(unittest.TestCase):
    def test_database_timestamp_rejects_stale_and_missing_metadata(self):
        from security import VulnerabilityDatabaseError, database_timestamp
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            now = datetime.datetime(2026, 1, 3, tzinfo=datetime.timezone.utc)
            with self.assertRaises(VulnerabilityDatabaseError):
                database_timestamp(cache, now)
            (cache / "db").mkdir()
            metadata = cache / "db" / "metadata.json"
            metadata.write_text(json.dumps({"UpdatedAt": "2026-01-01T00:00:00+00:00"}))
            self.assertEqual(database_timestamp(cache, now), "2026-01-01T00:00:00+00:00")
            with self.assertRaises(VulnerabilityDatabaseError):
                database_timestamp(cache, now + datetime.timedelta(seconds=1))

    def test_database_timestamp_accepts_trivy_rfc3339_on_python_310(self):
        from security import database_timestamp
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "db").mkdir()
            metadata = cache / "db" / "metadata.json"
            now = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)
            for value, expected in (
                ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00"),
                ("2026-01-01T00:00:00.7Z", "2026-01-01T00:00:00.700000+00:00"),
                ("2026-01-01T00:00:00.637500001Z", "2026-01-01T00:00:00.637500+00:00"),
                ("2026-01-01T00:00:00.12+01:00", "2026-01-01T00:00:00.120000+01:00"),
            ):
                with self.subTest(value=value):
                    metadata.write_text(json.dumps({"UpdatedAt": value}))
                    self.assertEqual(database_timestamp(cache, now), expected)

    def test_tag_digest_and_registry_port(self):
        from pilot import image_repository
        digest = "sha256:" + "a" * 64
        refs = {
            "registry.example.test:5000/team/image:v1.2": "registry.example.test:5000/team/image",
            f"registry.example.test:5000/team/image:1.2@{digest}": "registry.example.test:5000/team/image",
            f"repo@{digest}": "repo",
            "proxy:latest": "proxy",
        }
        for reference, expected in refs.items():
            self.assertEqual(image_repository(reference), expected)

    def test_kev_alias_keeps_both_identifiers(self):
        from security import finding_priority, findings
        item = {
            "VulnerabilityID": "GHSA-xxxx-yyyy-zzzz", "VendorIDs": ["CVE-2025-12345"],
            "Severity": "HIGH", "FixedVersion": "2.0.0",
        }
        hit, = findings({"Results": [{"Vulnerabilities": [item]}]})
        self.assertEqual(hit["advisory"], "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(hit["aliases"], ["CVE-2025-12345"])
        self.assertEqual(finding_priority(hit, {"CVE-2025-12345"}, True), ("urgent_review", True))

    def test_cookie_rejects_links_and_unsafe_modes(self):
        from gate import read_cookie
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session"
            path.write_bytes(b"fixture")
            path.chmod(0o600)
            self.assertEqual(read_cookie(path), b"fixture")
            alias = path.with_name("alias")
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                read_cookie(alias)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_cookie(path)
