#!/usr/bin/env python3
"""Collect GitHub security evidence and reconcile it with the private Appbox journal."""

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}")
ADVISORY = re.compile(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})")
SHA = re.compile(r"[a-f0-9]{40}")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
VERSION = re.compile(r"[A-Za-z0-9._+:-]{1,96}")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml")
LANGUAGE = re.compile(r"/language:[a-z0-9+-]+")
ALERTS = {
    "dependabot": "dependabot/alerts",
    "code-scanning": "code-scanning/alerts",
    "secret-scanning": "secret-scanning/alerts",
}
ALERT_STATES = {"open", "fixed", "resolved", "dismissed", "auto_dismissed"}
MAX_INPUT = 16 * 1024 * 1024


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def positive(value):
    return type(value) is int and value > 0


def valid_repo(name):
    return matches(REPOSITORY, name) and name.split("/")[-1] not in {".", ".."}


def advisories(values):
    return sorted({value for value in values if matches(ADVISORY, value)})


def incident_for_alert(repo, kind, number):
    return f"{repo}:{kind}:{number}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, token):
        if not token or not token.isascii() or any(char.isspace() for char in token):
            raise ValueError("GitHub requires a read credential")
        self.opener = urllib.request.build_opener(NoRedirect())
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "appbox-security-journal",
            "X-GitHub-Api-Version": "2026-03-10",
        }

    def get(self, path, *, version=None):
        self.next_page = None
        headers = self.headers if version is None else {**self.headers, "X-GitHub-Api-Version": version}
        try:
            with self.opener.open(
                urllib.request.Request("https://api.github.com" + path, headers=headers),
                timeout=20,
            ) as response:
                link = re.search(r'<([^>]+)>; rel="next"', response.headers.get("Link", ""))
                if link:
                    url = urllib.parse.urlsplit(link.group(1))
                    current = path.split("?")[0]
                    named = re.fullmatch(r"/repos/[^/]+/[^/]+(/.+)", current)
                    numbered = named and re.fullmatch(r"/repositories/\d+" + re.escape(named[1]), url.path)
                    if url.scheme != "https" or url.netloc != "api.github.com" or (
                        url.path != current and not numbered
                    ):
                        return 0, None
                    self.next_page = url.path + "?" + url.query
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, None
        except (OSError, ValueError):
            return 0, None

    def pages(self, path, object_key=None):
        separator = "&" if "?" in path else "?"
        path += separator + "per_page=100"
        records = []
        seen = set()
        for _ in range(100):
            seen.add(path)
            status, data = self.get(path)
            if status != 200:
                return status, []
            rows = data.get(object_key, []) if object_key else data
            if not isinstance(rows, list):
                return 0, []
            records.extend(rows)
            path = self.next_page
            if not path:
                return 200, records
            if path in seen:
                return 0, []
        return 0, []


def compact_alert(repo, kind, row):
    number = row.get("number")
    state = row.get("state")
    if not positive(number) or state not in ALERT_STATES:
        return None
    advisory = row.get("security_advisory") or {}
    ids = advisories([
        advisory.get("ghsa_id"), advisory.get("cve_id"),
        *(item.get("value") for item in advisory.get("identifiers") or []),
    ]) if kind == "dependabot" else []
    return {"repository": repo, "kind": kind, "number": number, "status": state, "advisories": ids}


def compact_analysis(repo, row):
    number = row.get("id")
    sha = row.get("commit_sha")
    language = row.get("category")
    if (
        row.get("tool", {}).get("name") != "CodeQL"
        or not positive(number)
        or not matches(SHA, sha)
        or not matches(LANGUAGE, language)
    ):
        return None
    return {
        "repository": repo, "kind": "codeql", "number": number, "sha": sha,
        "language": language.removeprefix("/language:"),
        "status": "error" if row.get("error") else "completed",
        "findings": max(0, row.get("results_count") or 0),
    }


def deployment_target(target):
    if not matches(VERSION, target.get("service")):
        raise ValueError("A deployment target requires a service")
    expected = target.get("digest")
    version = target.get("version")
    if expected is not None and not matches(DIGEST, expected):
        raise ValueError("Invalid deployment digest")
    if version is not None and not matches(VERSION, version):
        raise ValueError("Invalid deployment version")
    if expected is None and version is None:
        raise ValueError("A deployment target requires a digest or version")
    return {"service": target["service"], "digest": expected, "version": version}


def validated_plan(entry, repositories):
    repo = entry.get("repository")
    if repo not in repositories or not positive(entry.get("pr")) or not matches(SHA, entry.get("sha")):
        raise ValueError("A fix requires a configured repository, PR number and exact SHA")
    paths = entry.get("workflows") or []
    if not paths or not all(matches(WORKFLOW, name) for name in paths):
        raise ValueError("A fix requires exact workflow paths")
    ids = advisories(entry.get("advisories") or [])
    kind, number = entry.get("kind"), entry.get("number")
    keys = set(ids)
    for key in entry.get("keys") or []:
        if not isinstance(key, str):
            continue
        key_repo, separator, tail = key.partition(":")
        key_kind, _, key_number = tail.partition(":")
        if separator and key_repo == repo and key_kind in ALERTS and re.fullmatch(r"[1-9][0-9]{0,17}", key_number):
            keys.add(key)
    if kind in ALERTS and positive(number):
        keys.add(incident_for_alert(repo, kind, number))
    if not keys:
        raise ValueError("A fix must refer to a GitHub alert or advisory")
    vendor = entry.get("advisoryRepository")
    if vendor is not None and not valid_repo(vendor):
        raise ValueError("Invalid advisory repository")
    return {
        "repository": repo, "pr": entry["pr"], "sha": entry["sha"],
        "workflows": sorted(set(paths)), "advisories": ids, "keys": sorted(keys),
        "target": deployment_target(entry.get("target") or {}),
        "advisoryRepository": vendor,
    }


def check_fix(api, plan):
    repo, sha = plan["repository"], plan["sha"]
    root = "/repos/" + repo
    # The 2026 API omits the merge commit SHA. Use the version that exposes it.
    status, pr = api.get(f"{root}/pulls/{plan['pr']}", version="2022-11-28")
    if status != 200:
        return {**plan, "merged": False, "ci": "pr_unavailable", "checks": []}
    merged = pr.get("merged") is True and pr.get("merge_commit_sha") == sha
    linked_sha = merged or (pr.get("state") == "open" and pr.get("head", {}).get("sha") == sha)
    if not linked_sha:
        return {**plan, "merged": False, "ci": "sha_mismatch", "checks": []}
    status, runs = api.pages(f"{root}/actions/runs?head_sha={sha}", "workflow_runs")
    if status != 200:
        return {**plan, "merged": merged, "ci": "checks_unavailable", "checks": []}
    checks = []
    for path in plan["workflows"]:
        eligible = [
            run for run in runs
            if run.get("path") == path and run.get("head_sha") == sha and positive(run.get("id"))
            and (run.get("head_repository") or {}).get("full_name", "").casefold() == repo.casefold()
            and (not merged or run.get("head_branch") == pr.get("base", {}).get("ref"))
        ]
        if not eligible:
            checks.append({"workflow": path, "status": "missing"})
            continue
        latest = max(eligible, key=lambda run: run["id"])
        outcome = latest.get("conclusion")
        result = (
            "pending" if latest.get("status") != "completed"
            else "passed" if outcome == "success" else "failed"
        )
        checks.append({"workflow": path, "status": result, "number": latest["id"]})
    result = (
        "passed" if all(check["status"] == "passed" for check in checks)
        else "failed" if any(check["status"] == "failed" for check in checks)
        else "pending"
    )
    return {**plan, "merged": merged, "ci": result, "checks": checks}


def collect(api, repositories, plan):
    if not repositories or not all(valid_repo(repo) for repo in repositories):
        raise ValueError("Invalid GitHub repository")
    report = {"repositories": repositories, "queries": [], "alerts": [], "analyses": [], "fixes": [], "advisories": []}
    for repo in repositories:
        root = "/repos/" + repo
        for kind, path in ALERTS.items():
            query = "?hide_secret=true" if kind == "secret-scanning" else ""
            status, rows = api.pages(f"{root}/{path}{query}")
            report["queries"].append({"repository": repo, "kind": kind, "httpStatus": status})
            report["alerts"].extend(item for row in rows if (item := compact_alert(repo, kind, row)))
        status, data = api.get(f"{root}/code-scanning/analyses?per_page=100")
        report["queries"].append({"repository": repo, "kind": "codeql", "httpStatus": status})
        if status == 200:
            latest = {}
            for row in data:
                item = compact_analysis(repo, row)
                if item:
                    key = (item["sha"], item["language"])
                    latest.setdefault(key, item)
            report["analyses"].extend(latest.values())
    known = set()
    for entry in plan:
        fix = validated_plan(entry, repositories)
        report["fixes"].append(check_fix(api, fix))
        for advisory in fix["advisories"]:
            if advisory in known or not advisory.startswith("GHSA-"):
                continue
            status, data = api.get("/advisories/" + advisory)
            vendor = fix["advisoryRepository"] if status == 404 else None
            if vendor:
                status, data = api.get(f"/repos/{vendor}/security-advisories/{advisory}")
            if status == 200 and data.get("ghsa_id") == advisory:
                report["advisories"].append({
                    "repository": fix["repository"], "kind": "github-advisory",
                    "advisories": advisories([advisory, data.get("cve_id")]), "status": "published",
                    "advisoryRepository": vendor,
                })
                known.add(advisory)
    return report


def signal(row):
    repo, kind = row.get("repository"), row.get("kind")
    if not valid_repo(repo):
        raise ValueError("Invalid repository in report")
    ids = advisories(row.get("advisories") or [])
    if kind == "github-advisory":
        ghsa = next((item for item in ids if item.startswith("GHSA-")), None)
        if not ghsa:
            raise ValueError("A GitHub advisory must have a GHSA identifier")
        vendor = row.get("advisoryRepository")
        if vendor is not None and not valid_repo(vendor):
            raise ValueError("Invalid advisory repository")
        url = (
            f"https://github.com/{vendor}/security/advisories/{ghsa}"
            if vendor else f"https://github.com/advisories/{ghsa}"
        )
        return {
            "repository": repo, "kind": kind, "status": "published", "advisories": ids,
            "url": url,
        }
    number, state = row.get("number"), row.get("status")
    if kind not in ALERTS or not positive(number) or state not in ALERT_STATES:
        raise ValueError("Invalid GitHub security alert")
    return {
        "repository": repo, "kind": kind, "number": number, "status": state, "advisories": ids,
        "url": f"https://github.com/{repo}/security/{kind}/{number}",
    }


def alias_index(rows):
    aliases = {}
    for row in rows:
        ids = set(row["advisories"])
        if ids:
            group = ids.union(*(aliases.get(key, set()) for key in ids))
            for key in group:
                aliases[key] = group
    return aliases


def clean_fix(item, repositories):
    result = validated_plan(item, repositories)
    checks = []
    for check in item.get("checks") or []:
        path = check.get("workflow")
        state = check.get("status")
        number = check.get("number")
        if path in result["workflows"] and state in {"pending", "passed", "failed", "missing"}:
            clean = {"workflow": path, "status": state}
            if positive(number):
                clean["url"] = f"https://github.com/{result['repository']}/actions/runs/{number}"
            checks.append(clean)
    ci = item.get("ci")
    if ci == "passed" and not all(
        any(row["workflow"] == path and row["status"] == "passed" and "url" in row for row in checks)
        for path in result["workflows"]
    ):
        raise ValueError("CI success requires verifiable workflow runs")
    if ci not in {"passed", "pending", "failed", "sha_mismatch", "pr_unavailable", "checks_unavailable"}:
        raise ValueError("Invalid fix CI status")
    return {
        **result, "ci": ci, "merged": item.get("merged") is True, "checks": checks,
        "url": f"https://github.com/{result['repository']}/pull/{result['pr']}",
    }


def observed_deployment(fix, inventory):
    target = fix["target"]
    services = [row for row in inventory or [] if row.get("service") == target["service"]]
    actual = {
        "service": target["service"],
        "observed": sorted([
            {"digest": row["imageId"], "version": row["version"] if matches(VERSION, row.get("version")) else None}
            for row in services if matches(DIGEST, row.get("imageId"))
        ], key=lambda row: row["digest"]),
    }
    if fix["ci"] != "passed":
        return {"status": "awaiting_ci", **actual}
    if not fix["merged"]:
        return {"status": "awaiting_merge", **actual}
    if inventory is None:
        return {"status": "inventory_unavailable", **actual}
    for row in services:
        found = [row.get("imageId"), *(row.get("manifestDigests") or [])]
        if target["digest"] and target["digest"] not in found:
            continue
        if target["version"] and target["version"] != row.get("version"):
            continue
        return {
            "status": "confirmed", "service": target["service"],
            "digest": target["digest"] or row.get("imageId"), "version": row.get("version"),
        }
    return {"status": "awaiting_observed_release", **actual}


def incidents(report, inventory, local_advisories):
    repositories = report["repositories"]
    if not repositories or not all(valid_repo(repo) for repo in repositories):
        raise ValueError("Invalid report repositories")
    alerts = [signal(row) for row in report["alerts"] + report["advisories"]]
    if any(row["repository"] not in repositories for row in alerts):
        raise ValueError("Unexpected repository in security report")
    fixes = [clean_fix(item, repositories) for item in report["fixes"]]
    by_alias = alias_index(alerts)
    groups = defaultdict(list)
    for row in alerts:
        ids = row["advisories"]
        group = by_alias.get(ids[0]) if ids else None
        key = min(group, key=lambda value: (not value.startswith("CVE-"), value)) if group else (
            incident_for_alert(row["repository"], row["kind"], row["number"])
        )
        groups[key].append(row)
    for key, sources in sorted(groups.items()):
        ids = sorted(by_alias.get(key, set()))
        keys = {key, *ids}
        keys.update(
            incident_for_alert(row["repository"], row["kind"], row["number"])
            for row in sources if "number" in row
        )
        linked = [fix for fix in fixes if keys.intersection(fix["keys"])]
        local_match = bool(keys.intersection(local_advisories))
        linked = [
            {
                "repository": f["repository"], "pr": f["pr"], "sha": f["sha"],
                "url": f["url"], "ci": f["ci"], "checks": f["checks"],
                "appbox": observed_deployment(f, inventory),
            }
            for f in linked
        ]
        yield key, {
            "incident": key, "advisories": ids,
            "sources": sorted(sources, key=lambda row: row["url"]), "localScannerMatch": local_match,
            "detected": "github",
            "ci": phase({fix["ci"] for fix in linked}, "pending"),
            "appbox": phase({fix["appbox"]["status"] for fix in linked}, "awaiting_observed_release"),
            "fixes": linked,
        }


def phase(states, partial):
    if not states:
        return "awaiting_fix"
    return next(iter(states)) if len(states) == 1 else partial


def existing_advisories(state):
    results = set()
    for file in sorted(state.glob("journal.jsonl*")):
        if not file.is_file():
            continue
        with file.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("event") in {"finding", "advisory", "candidate_finding"}:
                    aliases = row.get("aliases", [])
                    identifiers = [row.get("advisory", row.get("id"))]
                    if isinstance(aliases, list):
                        identifiers.extend(aliases)
                    results.update(value for value in identifiers if matches(ADVISORY, value))
    return results


def analysis_check(row, repositories):
    repo, sha = row.get("repository"), row.get("sha")
    number, language = row.get("number"), row.get("language")
    status, count = row.get("status"), row.get("findings")
    if (
        repo not in repositories or not matches(SHA, sha) or not positive(number)
        or not matches(LANGUAGE, f"/language:{language}") or status not in {"completed", "error"}
        or type(count) is not int or count < 0
    ):
        raise ValueError("Invalid CodeQL evidence")
    return {
        "repository": repo, "kind": "codeql", "number": number, "sha": sha, "language": language,
        "status": status, "findings": count, "url": f"https://github.com/{repo}/security/code-scanning",
    }


def ingest(report, journal, inventory):
    import fcntl
    import tempfile

    root = journal.root
    state_path = root / "github-evidence.json"
    with (root / "github-evidence.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        # Reconcile a previous append if the importer was interrupted before replacing its index.
        for candidate in (root / "journal.jsonl.1", root / "journal.jsonl"):
            if not candidate.exists():
                continue
            with candidate.open(encoding="utf-8") as stream:
                for line in stream:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if row.get("event") in {"github_incident", "github_check"} and "evidenceKey" in row:
                        previous[row["evidenceKey"]] = {
                            key: val for key, val in row.items()
                            if key not in {"time", "runId", "event", "evidenceKey"}
                        }
        changes = [("github_incident", key, row) for key, row in incidents(report, inventory, existing_advisories(root))]
        for row in report["analyses"]:
            check = analysis_check(row, report["repositories"])
            key = f"{check['repository']}:codeql:{check['number']}"
            changes.append(("github_check", key, check))
        count = 0
        for event, key, row in changes:
            if previous.get(key) != row:
                journal.write(event, evidenceKey=key, **row)
                previous[key] = row
                count += 1
        for query in report.get("queries") or []:
            repo, kind, status = query.get("repository"), query.get("kind"), query.get("httpStatus")
            if repo in report["repositories"] and kind in {*ALERTS, "codeql"} and type(status) is int and status != 200:
                journal.write("github_query_unavailable", repository=repo, kind=kind, httpStatus=status)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as stream:
            temp = Path(stream.name)
            json.dump(previous, stream, ensure_ascii=True, sort_keys=True)
        try:
            temp.replace(state_path)
        finally:
            temp.unlink(missing_ok=True)
        journal.summarize(f"github evidence: {count} new or changed records; notifications handled by existing policy")
        return count


def read_token(path):
    if path:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError("The GitHub credential must be a private regular file")
        return path.read_text(encoding="ascii").strip()
    return sys.stdin.buffer.read(4097).decode("ascii").strip()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    fetch = sub.add_parser("collect")
    fetch.add_argument("--repo", action="append", required=True)
    fetch.add_argument("--plan", type=Path)
    fetch.add_argument("--token-file", type=Path)
    apply = sub.add_parser("ingest")
    apply.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "collect":
        plan = json.loads(args.plan.read_text(encoding="utf-8")) if args.plan else []
        print(json.dumps(collect(GitHub(read_token(args.token_file)), args.repo, plan)))
        return
    from subprocess import SubprocessError

    from security import Journal, image_inventory

    payload = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(payload) > MAX_INPUT:
        parser.error("The evidence report exceeds the allowed size")
    report = json.loads(payload)
    try:
        inventory = [row for _, row in image_inventory()]
    except (OSError, SubprocessError, ValueError):
        inventory = None
    journal = Journal(args.state)
    count = ingest(report, journal, inventory)
    print(f"GitHub evidence: {count} new or changed records ({journal.run_id})")


if __name__ == "__main__":
    main()
