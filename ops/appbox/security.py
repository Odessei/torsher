#!/usr/bin/env python3
"""Read-only Appbox image and mounted artifact audit."""

import argparse
import collections
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid

DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
ADVISORY = re.compile(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]{14})")
LEVELS = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CODE_MOUNTS = re.compile(
    r"/(?:app/(?:server/src/[A-Za-z0-9_./-]+\.ts|packages/release-parser/src/files\.ts|"
    r"tv/dist|web/\.output/public)|usr/local/bin/torsher-engine)"
)
HOST_PACKAGES = (
    "apache2", "openssh-server", "openssl", "docker-ce", "docker-ce-rootless-extras",
    "docker-compose-plugin", "slirp4netns", "uidmap",
)
MAX_LOG_BYTES = 5 * 1024 * 1024
KEEP_LOGS = 6
MAX_DB_AGE = datetime.timedelta(hours=48)


def run(*command, timeout=30):
    return subprocess.run(command, timeout=timeout, capture_output=True, check=True).stdout


def docker_json(*args):
    return json.loads(run("docker", *args))


def rotate(file):
    if not file.exists() or file.stat().st_size < MAX_LOG_BYTES:
        return
    for number in range(KEEP_LOGS - 1, 0, -1):
        older = file.with_suffix(file.suffix + f".{number}")
        if older.exists():
            older.replace(file.with_suffix(file.suffix + f".{number + 1}"))
    file.replace(file.with_suffix(file.suffix + ".1"))


class Journal:
    def __init__(self, root, run_id=None):
        self.root = root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.run_id = run_id or uuid.uuid4().hex

    def write(self, event, **fields):
        row = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "runId": self.run_id,
            "event": event,
            **fields,
        }
        with (self.root / "journal.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            target = self.root / "journal.jsonl"
            rotate(target)
            with target.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")

    def summarize(self, line):
        with (self.root / "journal.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            target = self.root / "summary.log"
            rotate(target)
            with target.open("a", encoding="utf-8") as fp:
                fp.write(f"{datetime.datetime.now(datetime.timezone.utc).isoformat()} {self.run_id} {line}\n")


def version(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9.+~:_-]{1,96}", value) else None


def image_inventory():
    containers = run("docker", "ps", "-q").decode().split()
    for item in docker_json("inspect", *containers) if containers else []:
        name = item["Name"].lstrip("/")
        if name.startswith("appbox-pilot-"):
            continue
        image_id = item["Image"]
        if not DIGEST.fullmatch(image_id):
            raise ValueError("unexpected image ID")
        img = docker_json("image", "inspect", image_id)[0]
        labels = item["Config"].get("Labels") or {}
        service = labels.get("com.docker.compose.service") or name
        sources = labels.get("com.docker.compose.project.config_files", "").split(",")
        yield item["Id"], {
            "service": version(service) or "unknown",
            "version": version((img["Config"].get("Labels") or {}).get("org.opencontainers.image.version")),
            "imageId": image_id,
            "manifestDigests": sorted({digest.split("@")[-1] for digest in img.get("RepoDigests") or [] if DIGEST.fullmatch(digest.split("@")[-1])}),
            "compose": [name for p in sources if (name := version(Path(p).name))],
            "source": "rootless-docker",
            "exposure": {"traefik": "reverse-proxy", "torsher": "restricted-ingress"}.get(service, "internal-or-unclassified"),
            "publishedBindings": any((item["HostConfig"].get("PortBindings") or {}).values()),
            "artifacts": [m["Destination"] for m in item["Mounts"]
                          if CODE_MOUNTS.fullmatch(m["Destination"]) and not m["RW"]],
        }


class VulnerabilityDatabaseError(ValueError):
    pass


def database_timestamp(cache, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        metadata = json.loads((cache / "db" / "metadata.json").read_text(encoding="utf-8"))
        timestamp = metadata["UpdatedAt"]
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        timestamp = re.sub(r"\.(\d+)(?=[+-]\d{2}:\d{2}$)",
                           lambda match: "." + match[1][:6].ljust(6, "0"), timestamp)
        updated = datetime.datetime.fromisoformat(timestamp)
        if not updated.tzinfo or not -datetime.timedelta(minutes=5) <= now - updated <= MAX_DB_AGE:
            raise ValueError("Vulnerability database timestamp is stale or invalid")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise VulnerabilityDatabaseError("Missing, invalid or stale Trivy vulnerability database") from error
    return updated.isoformat()


def report(command, trivy, cache, output, target):
    run(trivy, "--cache-dir", str(cache), *command, "--scanners", "vuln",
        "--no-progress", "--parallel", "1", "--format", "json",
        "--output", str(output), "--timeout", "8m", target, timeout=510)
    updated = database_timestamp(cache)
    data = json.loads(output.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("SchemaVersion") != 2:
        raise ValueError("Trivy did not return scan results")
    data["databaseUpdatedAt"] = updated
    return data


def findings(data):
    for result in data.get("Results") or []:
        for item in result.get("Vulnerabilities") or []:
            vuln = item.get("VulnerabilityID", "")
            if not ADVISORY.fullmatch(vuln):
                continue
            severity = item.get("Severity", "UNKNOWN")
            fixed = item.get("FixedVersion") or ""
            identities = {vuln}
            for field in ("VendorIDs", "Aliases"):
                values = item.get(field)
                if isinstance(values, list):
                    identities.update(x for x in values if isinstance(x, str) and ADVISORY.fullmatch(x))
            yield {
                "advisory": vuln,
                "aliases": sorted(identities - {vuln}),
                "package": package_name(item.get("PkgName")),
                "installed": version(item.get("InstalledVersion")),
                "fixed": [v for value in fixed.split(",") if (v := version(value.strip()))],
                "hasFix": bool(fixed),
                "severity": severity if severity in LEVELS else "UNKNOWN",
            }


def package_name(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9@/._+-]{1,200}", value) else None


def finding_priority(hit, exploited, exposed):
    identities = (hit["advisory"], *hit.get("aliases", ()))
    kev = None if exploited is None else any(identity in exploited for identity in identities)
    if kev and exposed and hit["hasFix"]:
        return "urgent_review", kev
    if kev or hit["severity"] in ("CRITICAL", "HIGH"):
        return "expedited_review", kev
    return "review", kev


def artifact_checksum(path):
    hashes = hashlib.sha256()
    entries = [path] if path.is_file() else sorted(path.rglob("*"))
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            continue
        hashes.update(str(entry.relative_to(path)).encode() + b"\0")
        with entry.open("rb") as fp:
            while chunk := fp.read(1024 * 1024):
                hashes.update(chunk)
    return "sha256:" + hashes.hexdigest()


def scan(args):
    state = args.state
    journal = Journal(state)
    with (state / "scan.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            journal.write("scan_skipped", reason="another_scan_running")
            journal.summarize("skipped: another scan running")
            return 0
        return scan_once(args, journal)


def known_exploited(journal):
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        with urllib.request.urlopen(url, timeout=12) as response:
            data = json.loads(response.read(8 * 1024 * 1024))
        ids = {item["cveID"] for item in data["vulnerabilities"]}
        journal.write("catalog", source="cisa-kev", entries=len(ids))
        return ids
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        journal.write("catalog_error", source="cisa-kev", decision="manual_review")
        return None


def scan_once(args, journal):
    errors = high = seen = total = 0
    scan_cache = {}
    journal.write("scan_started")
    exploited = known_exploited(journal)
    try:
        for container, meta in image_inventory():
            service = meta["service"]
            seen += 1
            journal.write("inventory", **meta)
            with tempfile.TemporaryDirectory(prefix="scan-", dir=journal.root) as directory:
                work = Path(directory)
                for artifact in meta["artifacts"]:
                    dest = work / "artifacts" / artifact.lstrip("/")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        run("docker", "cp", f"{container}:{artifact}", str(dest), timeout=90)
                        journal.write("artifact", service=service, target=artifact,
                                      checksum=artifact_checksum(dest))
                    except (subprocess.SubprocessError, OSError):
                        errors += 1
                        journal.write("scan_error", service=service, target=artifact,
                                      reason="artifact_read_failed")
                jobs = [("image", ["image", "--image-src", "docker"], meta["imageId"])]
                if (work / "artifacts").exists():
                    jobs.append(("mounted_artifacts", ["rootfs"], str(work / "artifacts")))
                for kind, command, target in jobs:
                    try:
                        if kind == "image" and target in scan_cache:
                            data = scan_cache[target]
                        else:
                            data = report(command, args.trivy, journal.root / "cache",
                                          work / "trivy.json", target)
                            if kind == "image":
                                scan_cache[target] = data
                        hits = list(findings(data))
                        counts = dict(collections.Counter(i["severity"] for i in hits))
                        total += len(hits)
                        high += sum(i["severity"] in ("HIGH", "CRITICAL") for i in hits)
                        journal.write("scan_result", service=service, version=meta["version"],
                                      imageId=meta["imageId"], manifestDigests=meta["manifestDigests"],
                                      kind=kind, counts=counts, databaseUpdatedAt=data["databaseUpdatedAt"],
                                      results=len(data.get("Results") or []),
                                      decision="review_findings" if hits else "no_findings")
                        for hit in hits:
                            exposed = meta["exposure"] != "internal-or-unclassified" or meta["publishedBindings"]
                            priority, kev = finding_priority(hit, exploited, exposed)
                            journal.write("finding", service=service, imageId=meta["imageId"],
                                          kind=kind, priority=priority, knownExploited=kev,
                                          exposure=meta["exposure"], **hit)
                    except VulnerabilityDatabaseError:
                        errors += 1
                        journal.write("scan_error", service=service, kind=kind,
                                      reason="stale_or_missing_vulnerability_database")
                    except (subprocess.SubprocessError, OSError, ValueError):
                        errors += 1
                        journal.write("scan_error", service=service, kind=kind,
                                      reason="scanner_or_database_failed")
        for package in HOST_PACKAGES:
            try:
                output = run("apt-cache", "policy", package).decode()
                fields = dict(re.findall(r"^\s*(Installed|Candidate):\s+(\S+)", output, re.M))
                journal.write("host_package", package=package, owner="provider",
                              installed=version(fields.get("Installed")),
                              candidate=version(fields.get("Candidate")),
                              decision="provider_review")
            except (subprocess.SubprocessError, OSError):
                errors += 1
                journal.write("scan_error", package=package, reason="host_inventory_failed")
    except (subprocess.SubprocessError, OSError, ValueError, KeyError):
        errors += 1
        journal.write("scan_error", reason="inventory_failed")
    journal.write("scan_finished", services=seen, findings=total,
                  highOrCritical=high, errors=errors, decision="report_only")
    journal.summarize(f"scanned={seen} findings={total} high_or_critical={high} errors={errors} mode=report-only")
    return int(bool(errors))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path.home() / ".local/state/appbox-security")
    parser.add_argument("--trivy", default="trivy")
    args = parser.parse_args()
    raise SystemExit(scan(args))


if __name__ == "__main__":
    main()
