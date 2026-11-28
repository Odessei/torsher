#!/usr/bin/env python3
"""Exercise the candidate and rollback image in a disposable network namespace."""

import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from security import ADVISORY, DIGEST, Journal, docker_json, findings, report, run, version

HERE = Path(__file__).resolve().parent
BACKEND = """
const http = require('node:http')
http.createServer((req, res) => {
  if (req.url === '/video' && req.headers.range === 'bytes=0-2') {
    res.writeHead(206, {'Content-Range': 'bytes 0-2/6'})
    res.end('abc')
  } else if (req.url === '/playlist') {
    res.writeHead(200, {'Content-Type':'application/vnd.apple.mpegurl'})
    res.end('#EXTM3U\\n#EXTINF:1,\\nsegment')
  } else if (req.url === '/session') {
    res.end(req.headers['x-forwarded-proto'] === 'http' ? 'inside' : 'bad')
  } else {
    res.end('ok')
  }
}).listen(18080, '127.0.0.1')
"""
PROBE = """
const assert = require('node:assert/strict');
const http = require('node:http');
const request = (host, path, headers = {}) => new Promise((resolve, reject) => {
  const req = http.get({hostname: '127.0.0.1', port: 18081, path,
                        headers: {Host: host, ...headers}}, res => {
    let text = '';
    res.setEncoding('utf8');
    res.on('data', chunk => { text += chunk; });
    res.on('end', () => resolve({status: res.statusCode, headers: res.headers, text}));
    res.on('error', reject);
  });
  req.on('error', reject);
  req.setTimeout(3000, () => req.destroy());
});
(async () => {
  const trusted = await request('trusted.example.test','/session');
  assert.equal(trusted.status, 200, 'trusted route');
  assert.equal(trusted.text, 'inside', 'trusted forwarding');
  const denied = await request('outside.example.test','/session',{'x-forwarded-for':'127.0.0.1'});
  assert.equal(denied.status, 403, 'outside route');
  const media = await request('trusted.example.test','/video',{range:'bytes=0-2'});
  assert.equal(media.status, 206, 'range status');
  assert.equal(media.headers['content-range'], 'bytes 0-2/6');
  assert.equal(media.text, 'abc');
  const hls = await request('trusted.example.test','/playlist');
  assert.equal(hls.status, 200, 'hls status');
  assert.match(hls.text, /^#EXTM3U/);
})().catch((err) => { console.error(err.message); process.exit(1); });
"""


@contextlib.contextmanager
def container(name, *args):
    run("docker", "run", "-d", "--rm", "--name", name, *args, timeout=45)
    try:
        yield
    finally:
        subprocess.run(("docker", "rm", "-f", name), capture_output=True, timeout=30, check=False)


def pinned(ref):
    if "@" not in ref or not DIGEST.fullmatch(ref.rsplit("@", 1)[-1]):
        raise ValueError("expected immutable image reference")
    return ref


def image_repository(ref):
    name = ref.split("@", 1)[0]
    registry_path, separator, tail = name.rpartition("/")
    repository = tail.split(":", 1)[0]
    if not repository:
        raise ValueError("image repository is missing")
    return registry_path + separator + repository


def local_image(ref, pull=False):
    try:
        obj = docker_json("image", "inspect", ref)[0]
    except subprocess.CalledProcessError:
        if not pull:
            raise
        run("docker", "pull", "--platform", "linux/amd64", ref, timeout=350)
        obj = docker_json("image", "inspect", ref)[0]
    digest = ref.rsplit("@", 1)[-1]
    if not any(repo.endswith("@" + digest) for repo in obj.get("RepoDigests") or []):
        raise ValueError("image digest not present locally")
    return obj["Id"]


def proxy_smoke(backend_name, image_id, config, suffix):
    proxy = f"appbox-pilot-proxy-{suffix}"
    with container(
        proxy, "--network", f"container:{backend_name}", "--entrypoint", "traefik",
        "--mount", f"type=bind,src={config},dst=/pilot.yaml,readonly", image_id,
        "--entrypoints.web.address=:18081", "--providers.file.filename=/pilot.yaml",
        "--log.level=ERROR",
    ):
        for _ in range(12):
            try:
                run("docker", "exec", backend_name, "node", "-e", PROBE, timeout=6)
                return
            except subprocess.CalledProcessError:
                time.sleep(1)
        raise RuntimeError("synthetic access, Range or HLS probe failed")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--trivy")
    parser.add_argument("--candidate-only", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch("[a-f0-9]{40}", args.sha):
        parser.error("--sha must be a full commit")
    journal = Journal(args.state)
    plan = json.loads((HERE / "traefik-pilot.json").read_text())
    candidate = pinned(json.loads((HERE / "compose.traefik-pilot.json").read_text())["services"]["traefik"]["image"])
    backend = pinned(json.loads((HERE / "compose.images.json").read_text())["services"]["torsher"]["image"])
    baseline = pinned(image_repository(candidate) + "@" + plan["oldDigest"])
    if not candidate.endswith("@" + plan["candidateDigest"]):
        raise ValueError("candidate settings disagree")
    journal.write("pilot_started", service="traefik", sha=args.sha, pr=args.pr,
                  source="vendor-advisory", oldVersion=version(plan["oldVersion"]),
                  candidateVersion=version(plan["candidateVersion"]),
                  oldDigest=plan["oldDigest"], candidateDigest=plan["candidateDigest"],
                  decision="pending_approval")
    for item in plan["advisories"]:
        if ADVISORY.fullmatch(item["id"]):
            journal.write("advisory", service="traefik", sha=args.sha, pr=args.pr,
                          advisory=item["id"], severity=item["severity"],
                          fixed=version(item["fixed"]), hasFix=True)
    try:
        candidate_id = local_image(candidate, pull=True)
        backend_id = local_image(backend, pull=True)
        old_id = None if args.candidate_only else local_image(baseline)
        with tempfile.TemporaryDirectory(prefix="pilot-", dir=journal.root) as path:
            config = Path(path) / "pilot.yaml"
            config.write_text(json.dumps({
                "http": {
                    "routers": {
                        "trusted": {"rule": "Host(\u0060trusted.example.test\u0060)", "service": "media", "middlewares": ["allow"]},
                        "outside": {"rule": "Host(\u0060outside.example.test\u0060)", "service": "media", "middlewares": ["deny"]},
                    },
                    "middlewares": {
                        "allow": {"ipAllowList": {"sourceRange": ["127.0.0.1/32"]}},
                        "deny": {"ipAllowList": {"sourceRange": ["192.0.2.0/24"]}},
                    },
                    "services": {"media": {"loadBalancer": {"servers": [{"url": "http://127.0.0.1:18080"}]}}},
                },
            }), encoding="utf-8")
            config.chmod(0o644)
            if args.trivy:
                data = report(["image", "--image-src", "docker"], args.trivy,
                              journal.root / "cache", Path(path) / "candidate.json", candidate_id)
                hits = list(findings(data))
                journal.write("candidate_scan", service="traefik", sha=args.sha, pr=args.pr,
                              candidateDigest=plan["candidateDigest"], findings=len(hits))
                for hit in hits:
                    journal.write("candidate_finding", service="traefik", sha=args.sha, **hit)
            suffix = uuid.uuid4().hex[:10]
            backend_name = f"appbox-pilot-backend-{suffix}"
            with container(backend_name, "--network", "none", "--entrypoint", "node",
                           backend_id, "-e", BACKEND):
                proxy_smoke(backend_name, candidate_id, config, suffix + "-new")
                if old_id:
                    proxy_smoke(backend_name, old_id, config, suffix + "-rollback")
        journal.write("pilot_finished", service="traefik", sha=args.sha, pr=args.pr,
                      candidateDigest=plan["candidateDigest"], rollbackDigest=plan["oldDigest"],
                      dependencies=["synthetic-backend", "file-provider", "ip-allowlist"],
                      tests=["trusted", "outside", "range-206", "hls-manifest"],
                      rollbackTested=old_id is not None, result="passed",
                      decision="pending_approval", production="untouched")
        journal.summarize(f"traefik pilot passed; rollback={'tested' if old_id else 'not requested'}; awaits approval")
    except (subprocess.SubprocessError, OSError, RuntimeError, ValueError):
        journal.write("pilot_finished", service="traefik", sha=args.sha, pr=args.pr,
                      result="error", decision="hold", production="untouched")
        journal.summarize("traefik pilot failed; production untouched")
        print("Traefik pilot failed. See the sanitized journal.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
