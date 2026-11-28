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

RECENT_WINDOW = "180s"
READ_ACTIVITY = """
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

async function localOwnerCookie() {
  const database = process.env.DATABASE_PATH;
  if (!database || !isAbsolute(database)) throw Error('owner database unavailable');
  if (!process.env.SECRET_KEY) {
    process.env.SECRET_KEY = readFileSync(join(dirname(database), 'session.key'), 'utf8').trim();
  }

  const db = new DatabaseSync(database, {readOnly:true});
  let owners;
  try {
    owners = db.prepare('SELECT id, session_version FROM users LIMIT 2').all();
  } finally {
    db.close();
  }
  if (owners.length !== 1 || typeof owners[0].id !== 'string'
      || !Number.isInteger(owners[0].session_version)) throw Error('owner unavailable');
  const {ACCESS_TOKEN_COOKIE} = await import('./server/src/config.ts');
  const {signToken} = await import('./server/src/utils/token.ts');
  return ACCESS_TOKEN_COOKIE+'='+signToken(owners[0].id, 'user_access', owners[0].session_version);
}

async function read(path, cookie) {
  const response = await fetch('http://127.0.0.1:8080'+path, {
    headers: {cookie}, redirect: 'error', signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw Error('activity check unavailable');
  return response.json();
}

async function main() {
  const supplied = readFileSync(0, 'utf8').trim();
  if (/[\\r\\n]/.test(supplied)) throw Error('invalid session header');
  const cookie = supplied || await localOwnerCookie();
  const [torrent, devices] = await Promise.all([
    read('/api/settings/torrent', cookie), read('/api/devices', cookie),
  ]);
  if (!Number.isInteger(torrent.activeStreams) || torrent.activeStreams < 0 || !Array.isArray(devices.items)) process.exit(2);
  console.log(JSON.stringify({openStreams:torrent.activeStreams, recentDevices:devices.items.filter(i=>i.watching===true).length}));
}
main().catch(()=>process.exit(2));
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


def read_cookie(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077):
            raise ValueError("cookie file must be private and owned by this user")
        return stream.read(8193)


def activity(cookie=b"", target="torsher-torsher-1"):
    response = subprocess.run(
        ("docker", "exec", "-i", "--workdir", "/app", target,
         "node", "--input-type=module", "-e", READ_ACTIVITY),
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
    from security import DIGEST, Journal

    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--old-digest", required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--service", choices=("traefik", "torsher"), default="traefik")
    parser.add_argument("--torsher-container", default="torsher-torsher-1")
    parser.add_argument("--traefik-container", default="traefik")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--stdin", action="store_true")
    source.add_argument("--cookie-file", type=Path)
    args = parser.parse_args()
    if not re.fullmatch("[a-f0-9]{40}", args.sha):
        parser.error("expected a full source commit")
    if not all(DIGEST.fullmatch(x) for x in (args.old_digest, args.candidate_digest)):
        parser.error("expected pinned digests")
    if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name)
               for name in (args.torsher_container, args.traefik_container)):
        parser.error("expected Docker container names")
    journal = Journal(args.state)
    values = {}
    try:
        cookie = b""
        if args.stdin:
            cookie = sys.stdin.buffer.read(8193)
        elif args.cookie_file:
            cookie = read_cookie(args.cookie_file)
        if len(cookie) > 8192 or ((args.stdin or args.cookie_file) and not cookie.strip()):
            raise ValueError("activity credentials unavailable")
        values = activity(cookie, args.torsher_container)
        decision = ("deferred_active_viewing"
                    if any(values.values()) else "awaiting_approval")
    except (subprocess.SubprocessError, OSError, ValueError):
        decision = "deferred_activity_unverified"
    target = args.traefik_container if args.service == "traefik" else args.torsher_container
    journal.write("release_gate", service=args.service, container=target, sha=args.sha, pr=args.pr,
                  oldDigest=args.old_digest, candidateDigest=args.candidate_digest,
                  activity=values, decision=decision)
    journal.summarize(f"{args.service} release gate: {decision}; report only")
    print(decision)


if __name__ == "__main__":
    main()
