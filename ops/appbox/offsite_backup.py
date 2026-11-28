"""Create and upload a private, encrypted Torsher backup."""

import argparse
import contextlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tarfile
import tempfile

from rollout import quick_check


BACKUP_FILES = ("torsher.db", "session.key", "secret.key")
COPY_BACKUP = """
const fs = require('node:fs');
const { DatabaseSync, backup } = require('node:sqlite');
async function main() {
  process.umask(0o077);
  const names = ['session.key', 'secret.key'];
  const keys = names.map(name => fs.readFileSync('/source/' + name));
  if (keys.some(key => !key.length)) throw Error('Empty key');
  const source = new DatabaseSync('/source/torsher.db', { readOnly: true });
  await backup(source, '/snapshot/torsher.db');
  source.close();
  fs.chmodSync('/snapshot/torsher.db', 0o600);
  for (const [index, name] of names.entries()) {
    if (!keys[index].equals(fs.readFileSync('/source/' + name))) throw Error('Key changed');
    fs.writeFileSync('/snapshot/' + name, keys[index], { flag: 'wx', mode: 0o600 });
  }
}
main().catch(() => process.exit(1));
"""


def run(args, timeout, **kwargs):
    result = subprocess.run(args, timeout=timeout, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(Path(args[0]).name + " failed")
    return result.stdout


def check_config(path):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("configuration file must be private and owned by the current user")


def container_snapshot(container, target):
    current, = json.loads(run(["docker", "inspect", container], 15))
    env = dict(value.split("=", 1) for value in current["Config"]["Env"])
    database = Path(env["DATABASE_PATH"])
    if database.name != "torsher.db" or not database.is_absolute():
        raise ValueError("unsupported database location")
    mounts = {Path(m["Destination"]): Path(m["Source"]) for m in current["Mounts"]}
    mount = next((path for path in database.parents if path in mounts), None)
    if mount is None:
        raise ValueError("database storage mount not found")
    source = mounts[mount] / database.parent.relative_to(mount)
    run([
        "docker", "run", "--rm", "--network", "none", "--user", "0:0",
        "--mount", f"type=bind,src={source},dst=/source,readonly",
        "--mount", f"type=bind,src={target},dst=/snapshot",
        "--entrypoint", "node", current["Image"], "-e", COPY_BACKUP,
    ], 90)
    with contextlib.closing(sqlite3.connect((target / "torsher.db").as_uri() + "?mode=ro", uri=True)) as db:
        quick_check(db)


def archive_snapshot(source, archive):
    with tarfile.open(archive, "x:gz") as tar:
        for name in BACKUP_FILES:
            info = tar.gettarinfo(str(source / name), arcname=name)
            if not info.isreg() or info.size == 0:
                raise ValueError("snapshot component must be a nonempty regular file")
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o600
            with (source / name).open("rb") as stream:
                tar.addfile(info, stream)


def back_up(settings, state):
    destination = settings["rclone_destination"]
    if not re.fullmatch(r"[a-zA-Z0-9_-]+:[^:\r\n]+", destination):
        raise ValueError("expected a configured rclone remote and prefix")
    check_config(Path(settings["rclone_config"]))
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = datetime.now(timezone.utc).strftime("torsher-%Y%m%dT%H%M%S%fZ.tar.gz.age")
    final = state / name
    with tempfile.TemporaryDirectory(prefix=".snapshot-", dir=state) as temporary:
        directory = Path(temporary)
        source = directory / "db"
        source.mkdir(mode=0o700)
        container_snapshot(settings.get("container", "torsher-torsher-1"), source)
        plain = directory / "snapshot.tar.gz"
        archive_snapshot(source, plain)
        encrypted = directory / "encrypted.age"
        run(["age", "--recipients-file", settings["recipients_file"], "-o", str(encrypted), str(plain)], 120)
        os.chmod(encrypted, 0o600)
        encrypted.rename(final)
    for old in sorted(state.glob("torsher-*.tar.gz.age"), reverse=True)[14:]:
        old.unlink()
    rclone = ["rclone", "--config", settings["rclone_config"]]
    run([*rclone, "copy", str(state), destination, "--include", "/torsher-*.tar.gz.age"], 900)
    run([*rclone, "check", str(state), destination,
         "--include", "/" + name, "--one-way", "--download"], 900)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    try:
        check_config(args.config)
        back_up(json.loads(args.config.read_text()), args.state.resolve())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError, sqlite3.Error) as exc:
        print(f"offsite backup failed ({type(exc).__name__})")
        return 1
    print("offsite backup stored and content verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
