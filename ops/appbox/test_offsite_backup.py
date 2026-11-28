from pathlib import Path
import tarfile
import tempfile
import unittest

from offsite_backup import BACKUP_FILES, archive_snapshot


class OffsiteBackupTests(unittest.TestCase):
    def test_archive_has_exact_members_and_private_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in BACKUP_FILES:
                (root / name).write_bytes(("fixture " + name).encode())
            package = root / "bundle.tar.gz"
            archive_snapshot(root, package)
            with tarfile.open(package) as tar:
                self.assertEqual(tar.getnames(), list(BACKUP_FILES))
                self.assertTrue(all(entry.mode == 0o600 and not entry.uname for entry in tar))

    def test_empty_key_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in BACKUP_FILES:
                (root / name).write_bytes(b"fixture")
            (root / "session.key").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "nonempty"):
                archive_snapshot(root, root / "bundle.tar.gz")
