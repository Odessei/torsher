#!/usr/bin/env python3
"""Report a rollout decision without changing containers."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from security import DIGEST, Journal, run

RECENT_WINDOW = "180s"
READ_ACTIVITY = """
const fs = require('node:fs');
const cookie = fs.readFileSync(0, 'utf8').trim();
if (!cookie || /[\\r\\n]/.test(cookie)) process.exit(2);
const read = async (path) => {
  const response = await fetch('http://127.0.0.1:8080'+path, {
    headers: {cookie}, signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw Error('activity check unavailable');
  return response.json();
};
Promise.all([read('/api/settings/torrent'), read('/api/devices')]).then(([torrent, devices]) => {
  if (!Number.isInteger(torrent.activeStreams) || torrent.activeStreams < 0 || !Array.isArray(devices.items)) process.exit(2);
  console.log(JSON.stringify({openStreams:torrent.activeStreams, recentDevices:devices.items.filter(i=>i.watching===true).length}));
}).catch(()=>process.exit(2));
"""


def recent_playback(log):
    for line in log.splitlines():
        if not line.startswith(b"{"):
            continue
        try:
            record = json.loads(line)
            event = record.get("event")
            if event == "playback.playing":
                return True
            if event != "playback.snapshot":
                continue
            detail = record.get("details") or {}
            if isinstance(detail, str):
                detail = json.loads(detail)
            media = detail.get("media") or {}
            if media.get("paused") is False:
                return True
        except (AttributeError, ValueError):
            continue
    return False


def activity(cookie):
    target = "torsher-torsher-1"
    response = subprocess.run(
        ("docker", "exec", "-i", target, "node", "-e", READ_ACTIVITY),
        input=cookie, capture_output=True, timeout=12, check=True,
    )
    values = json.loads(response.stdout)
    log = subprocess.run(
        ("docker", "logs", "--since", RECENT_WINDOW, target),
        capture_output=True, timeout=18, check=True,
    )
    values["recentPlayback"] = recent_playback(log.stdout + b"\n" + log.stderr)
    return values


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--old-digest", required=True)
    parser.add_argument("--candidate-digest", required=True)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--stdin", action="store_true")
    source.add_argument("--cookie-file", type=Path)
    args = parser.parse_args()
    if not re.fullmatch("[a-f0-9]{40}", args.sha):
        parser.error("expected a full source commit")
    if not all(DIGEST.fullmatch(x) for x in (args.old_digest, args.candidate_digest)):
        parser.error("expected pinned digests")
    journal = Journal(args.state)
    values = {}
    try:
        cookie = b""
        if args.stdin:
            cookie = sys.stdin.buffer.read(8193)
        elif args.cookie_file:
            mode = args.cookie_file.stat().st_mode
            if stat.S_ISREG(mode) and mode & 0o077 == 0 and not args.cookie_file.is_symlink():
                with args.cookie_file.open("rb") as stream:
                    cookie = stream.read(8193)
        if not cookie or len(cookie) > 8192:
            raise ValueError("activity credentials unavailable")
        values = activity(cookie)
        decision = ("deferred_active_viewing"
                    if any(values.values()) else "awaiting_approval")
    except (subprocess.SubprocessError, OSError, ValueError):
        decision = "deferred_activity_unverified"
    journal.write("release_gate", service="traefik", sha=args.sha, pr=args.pr,
                  oldDigest=args.old_digest, candidateDigest=args.candidate_digest,
                  activity=values, decision=decision)
    journal.summarize(f"traefik release gate: {decision}; report only")
    print(decision)


if __name__ == "__main__":
    main()
