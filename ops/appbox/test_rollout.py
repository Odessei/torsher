import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest

from rollout import digest, quick_check, snapshot, verify_package


def tar(path, members):
    with tarfile.open(path, "w") as package:
        for name, data in members.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            package.addfile(item, io.BytesIO(data))


def descriptor(data):
    return {"digest": digest(data), "size": len(data)}


class RolloutTests(unittest.TestCase):
    def test_snapshot_includes_committed_wal_and_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "live.db"
            (root / "session.key").write_bytes(b"fixture session")
            (root / "secret.key").write_bytes(b"fixture secret")
            writer = sqlite3.connect(source)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE history (value TEXT)")
                writer.execute("INSERT INTO history VALUES ('committed')")
                writer.commit()
                self.assertTrue((root / "live.db-wal").is_file())
                target = root / "snapshot"
                snapshot(source, target)
                with sqlite3.connect(target / "torsher.db") as restored:
                    quick_check(restored)
                    self.assertEqual(
                        restored.execute("SELECT value FROM history").fetchall(),
                        [("committed",)],
                    )
                restored.close()
                self.assertEqual((target / "session.key").read_bytes(), b"fixture session")
                self.assertEqual((target / "secret.key").read_bytes(), b"fixture secret")
            finally:
                writer.close()

    def test_package_rejects_mismatched_config_and_corrupt_layer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = "a" * 40
            config = json.dumps({
                "os": "linux", "architecture": "amd64",
                "config": {"Labels": {"org.opencontainers.image.revision": sha}},
            }).encode()
            layer = b"layer"
            manifest = json.dumps({
                "config": descriptor(config), "layers": [descriptor(layer)],
            }).encode()
            item = {**descriptor(manifest), "platform": {"os": "linux", "architecture": "amd64"}}
            index = json.dumps({"manifests": [item]}).encode()
            oci = root / "oci.tar"
            docker = root / "docker.tar"
            members = {"index.json": index, **{
                "blobs/" + digest(data).replace(":", "/"): data
                for data in (config, layer, manifest)
            }}
            tar(oci, members)
            tar(docker, {
                "manifest.json": json.dumps([{
                    "Config": "config.json", "RepoTags": ["torsher-appbox:" + sha],
                }]).encode(),
                "config.json": config,
            })
            self.assertEqual(verify_package(oci, docker, digest(config), sha)["manifestDigest"],
                             digest(manifest))
            self.assertEqual(verify_package(oci, docker, digest(manifest), sha)["configID"],
                             digest(config))
            with self.assertRaisesRegex(ValueError, "image ID"):
                verify_package(oci, docker, digest(b"unexpected"), sha)
            members["blobs/" + digest(layer).replace(":", "/")] = b"other"
            tar(oci, members)
            with self.assertRaisesRegex(ValueError, "blob digest"):
                verify_package(oci, docker, digest(config), sha)
