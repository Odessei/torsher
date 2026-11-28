#!/usr/bin/env python3
"""Determine the complete Git range and reject private tracked filenames."""

import argparse
from pathlib import PurePosixPath
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(("git", *args))


def commit_range(base, fallback=""):
    if git("rev-parse", "--is-shallow-repository").strip() != b"false":
        raise ValueError("Full Git history is required for secret scanning")
    git("rev-parse", "--verify", "HEAD^{commit}")
    if re.fullmatch(r"[a-f0-9]{40}", base):
        verify = subprocess.run(
            ("git", "cat-file", "-e", f"{base}^{{commit}}"), capture_output=True
        )
        if verify.returncode == 0:
            return f"{base}..HEAD"
    if fallback.startswith("refs/remotes/origin/"):
        anchor = subprocess.run(
            ("git", "rev-parse", "--verify", fallback + "^{commit}"), capture_output=True
        )
        if anchor.returncode == 0:
            return f"{anchor.stdout.decode().strip()}..HEAD"
    return "HEAD"


def blocked_path(path):
    normalized = path.casefold()
    name = PurePosixPath(normalized).name
    if name == ".env" or name.startswith(".env."):
        return not (name.endswith(".example") or normalized == "apps/server/.env.test")
    return bool(re.fullmatch(r"id_(?:ed25519|rsa)", name) or
                re.search(r"\.(?:sqlite3?|db|p12|pfx|pem|key|age)$", name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="")
    parser.add_argument("--fallback-ref", default="")
    args = parser.parse_args()
    try:
        selected = commit_range(args.base, args.fallback_ref)
        if selected == "HEAD":
            print("::notice::Base commit unavailable. Scanning all commits reachable from HEAD.", file=sys.stderr)
        names = git(
            "log", "--format=", "--name-only", "-z", "--diff-merges=first-parent",
            "--diff-filter=ACMRT", selected, "--",
        ).decode("utf-8", errors="surrogateescape")
        if any(blocked_path(path) for path in names.split("\0") if path):
            raise ValueError("A private file type appears in the selected Git history")
    except (ValueError, subprocess.CalledProcessError) as e:
        parser.exit(1, f"::error::{e}\n")
    print(selected)


if __name__ == "__main__":
    main()
