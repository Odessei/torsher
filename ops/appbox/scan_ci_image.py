#!/usr/bin/env python3
"""Scan a local CI image and write public-safe, revision-bound evidence."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import tempfile

from security import DIGEST, finding_priority, findings, known_exploited, report, run


class CaptureCatalog:
    def write(self, event, **_fields):
        if event == "catalog_error":
            print("::warning::CISA KEV is unavailable. Review applicable advisories manually.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--manifest-digest")
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sqlite", action="store_true")
    args = parser.parse_args()

    try:
        sha = run("git", "rev-parse", "HEAD").decode().strip()
        image = run("docker", "image", "inspect", "--format", "{{.Id}}", args.image).decode().strip()
        if not re.fullmatch(r"[a-f0-9]{40}", sha) or not DIGEST.fullmatch(image):
            raise ValueError("Invalid revision or image ID")
        if args.manifest_digest and not DIGEST.fullmatch(args.manifest_digest):
            raise ValueError("Invalid registry manifest digest")
        with tempfile.TemporaryDirectory(prefix="ci-image-") as directory:
            work = Path(directory)
            data = report(["image", "--image-src", "docker"], args.trivy, work / "cache",
                          work / "trivy.json", image)

        kev = known_exploited(CaptureCatalog())
        records = []
        for hit in findings(data):
            priority, exploited = finding_priority(hit, kev, args.sqlite)
            records.append({**hit, "priority": priority, "knownExploited": exploited})
        evidence = {
            "check": "trivy",
            "sha": sha,
            "imageId": image,
            "manifestDigest": args.manifest_digest,
            "databaseUpdatedAt": data["databaseUpdatedAt"],
            "knownExploitedCatalogAvailable": kev is not None,
            "counts": dict(Counter(hit["severity"] for hit in records)),
            "decision": "review_findings" if records else "no_findings",
            "findings": records,
        }
        if args.sqlite:
            sqlite = run(
                "docker", "run", "--rm", "--network", "none", "-w", "/app/server",
                "--entrypoint", "node", image, "-e",
                "const db = new (require('better-sqlite3'))(':memory:');"
                " console.log(db.prepare('SELECT sqlite_version() AS version').get().version);",
            ).decode().strip()
            if not re.fullmatch(r"\d+\.\d+\.\d+", sqlite):
                raise ValueError("Unexpected SQLite version")
            evidence["sqliteVersion"] = sqlite
        args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({key: value for key, value in evidence.items() if key != "findings"}))
        urgent = sorted({hit["advisory"] for hit in records if hit["knownExploited"]
                         or (hit["hasFix"] and hit["severity"] in ("HIGH", "CRITICAL"))})
        if urgent:
            print(f"::warning::{len(urgent)} KEV or fixable high/critical findings. See scan evidence.")
            for advisory in urgent:
                print(advisory)
    except (subprocess.SubprocessError, OSError, ValueError) as error:
        message = str(error) if type(error) is ValueError else type(error).__name__
        raise SystemExit(f"::error::Image scan could not produce valid evidence ({message})") from None


if __name__ == "__main__":
    main()
