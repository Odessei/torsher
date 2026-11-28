"""Prepare and verify an Appbox rollout without changing running containers."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tarfile
import time


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def quick_check(conn):
    if conn.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
        raise ValueError("SQLite quick_check failed")


def snapshot(source, target):
    """Use SQLite's online backup API and check that the keys stayed stable."""
    deadline = time.monotonic() + 60

    def check_time(*_):
        if time.monotonic() > deadline:
            raise TimeoutError("SQLite backup exceeded its time budget")

    names = ("session.key", "secret.key")
    keys = {name: (source.parent / name).read_bytes() for name in names}
    if not all(keys.values()):
        raise ValueError("required key is empty")

    target.mkdir(mode=0o700)
    database = target / "torsher.db"
    src = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
    dest = sqlite3.connect(database)
    try:
        src.backup(dest, pages=128, progress=check_time, sleep=0.1)
        quick_check(dest)
    finally:
        src.close()
        dest.close()
    os.chmod(database, 0o600)

    for name, key in keys.items():
        if (source.parent / name).read_bytes() != key:
            raise ValueError("a key changed during snapshot")
    for name, key in keys.items():
        with (target / name).open("xb") as stream:
            os.chmod(target / name, 0o600)
            stream.write(key)


def blob(archive, descriptor, retain):
    expected = descriptor["digest"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", expected):
        raise ValueError("invalid OCI descriptor")
    name = expected.replace(":", "/")
    value = hashlib.sha256()
    data = bytearray()
    with archive.extractfile("blobs/" + name) as stream:
        if archive.getmember("blobs/" + name).size != descriptor["size"]:
            raise ValueError("OCI blob size mismatch")
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
            if retain:
                data.extend(chunk)
    if "sha256:" + value.hexdigest() != expected:
        raise ValueError("OCI blob digest mismatch")
    return bytes(data)


def verify_package(oci_path, docker_path, config_id, sha):
    with tarfile.open(oci_path) as archive:
        with archive.extractfile("index.json") as stream:
            index_data = stream.read()
        index = json.loads(index_data)
        selected = [
            item for item in index["manifests"]
            if item.get("platform", {}).get("os") == "linux"
            and item.get("platform", {}).get("architecture") == "amd64"
        ]
        if len(selected) != 1:
            raise ValueError("expected a single linux/amd64 manifest")
        descriptor = selected[0]
        manifest = json.loads(blob(archive, descriptor, True))
        config = blob(archive, manifest["config"], True)
        for layer in manifest["layers"]:
            blob(archive, layer, False)
    settings = json.loads(config)
    if (settings["os"], settings["architecture"]) != ("linux", "amd64"):
        raise ValueError("image architecture mismatch")
    if settings["config"]["Labels"]["org.opencontainers.image.revision"] != sha:
        raise ValueError("image revision mismatch")
    if config_id not in (manifest["config"]["digest"], descriptor["digest"]):
        raise ValueError("Docker loaded image ID differs from OCI")
    with tarfile.open(docker_path) as archive:
        with archive.extractfile("manifest.json") as stream:
            images = json.load(stream)
        if len(images) != 1 or "torsher-appbox:" + sha not in images[0]["RepoTags"]:
            raise ValueError("Docker archive image tag mismatch")
        with archive.extractfile(images[0]["Config"]) as stream:
            if stream.read() != config:
                raise ValueError("Docker archive config differs from OCI")
    return {"indexSHA256": digest(index_data), "manifestDigest": descriptor["digest"],
            "configID": manifest["config"]["digest"], "runnerImageID": config_id, "revision": sha}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    copy = commands.add_parser("snapshot")
    copy.add_argument("source", type=Path)
    copy.add_argument("target", type=Path)
    verify = commands.add_parser("verify-package")
    verify.add_argument("directory", type=Path)
    verify.add_argument("revision")
    args = parser.parse_args()
    if args.command == "snapshot":
        snapshot(args.source, args.target)
        print("SQLite snapshot and key copy verified")
    else:
        path = args.directory
        config_id = (path / "config-id.txt").read_text().strip()
        result = verify_package(path / "image.oci.tar", path / "image.docker.tar",
                                config_id, args.revision)
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
