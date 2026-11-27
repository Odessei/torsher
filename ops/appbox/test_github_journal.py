import json
import os
from pathlib import Path
import tempfile
import unittest

from github_journal import check_fix, collect, incidents, ingest, validated_plan

REPO = "sample/project"
CVE = "CVE-2026-999999"
GHSA = "GHSA-xxxx-yyyy-zzzz"
COMMIT = "a" * 40
CANDIDATE = "sha256:" + "a" * 64
CURRENT = "sha256:" + "b" * 64
WORKFLOW = ".github/workflows/ci.yml"


def plan_entry():
    return {
        "repository": REPO, "pr": 3, "sha": COMMIT,
        "workflows": [WORKFLOW], "advisories": [GHSA],
        "advisoryRepository": "sample/vendor",
        "target": {"service": "proxy", "digest": CANDIDATE},
    }


class FixtureGitHub:
    def __init__(self, merged=False, checks=None):
        self.merged = merged
        self.requests = []
        self.checks = checks or [self.run()]

    @staticmethod
    def run(id=19, sha=COMMIT, status="completed", conclusion="success"):
        return {
            "id": id, "path": WORKFLOW, "head_sha": sha, "status": status,
            "conclusion": conclusion, "head_repository": {"full_name": REPO},
            "head_branch": "main",
        }

    def get(self, path, *, version=None):
        self.requests.append(path)
        if path.endswith("/pulls/3"):
            response = {
                "state": "closed" if self.merged else "open",
                "merged": self.merged,
                "head": {"sha": COMMIT}, "base": {"ref": "main"},
            }
            if version == "2022-11-28":
                response["merge_commit_sha"] = COMMIT
            return 200, response
        if path == "/repos/sample/vendor/security-advisories/" + GHSA:
            return 200, {"ghsa_id": GHSA, "cve_id": CVE}
        if "/code-scanning/analyses?" in path:
            return 200, [{
                "tool": {"name": "CodeQL"}, "id": 7, "commit_sha": COMMIT,
                "category": "/language:go", "results_count": 2, "error": "",
            }]
        return 404, None

    def pages(self, path, object_key=None):
        self.requests.append(path)
        if "dependabot/alerts" in path:
            return 200, [
                {
                    "number": number, "state": "open",
                    "security_advisory": {"ghsa_id": GHSA, "cve_id": CVE},
                    "body": "private fixture text",
                }
                for number in (4, 5)
            ]
        if "secret-scanning/alerts" in path:
            return 200, [{"number": 6, "state": "open", "secret": "private fixture text"}]
        if "/actions/runs?" in path:
            return 200, self.checks
        return 200, []


class JournalTest(unittest.TestCase):
    def test_redaction_and_advisory_correlation(self):
        api = FixtureGitHub()
        report = collect(api, [REPO], [plan_entry()])
        self.assertNotIn("private fixture text", json.dumps(report))
        self.assertIn(f"/repos/{REPO}/secret-scanning/alerts?hide_secret=true", api.requests)
        linked = dict(incidents(report, [], {CVE}))
        self.assertEqual(2, len(linked))
        self.assertTrue(linked[CVE]["localScannerMatch"])
        self.assertEqual(3, len(linked[CVE]["sources"]))
        self.assertEqual("passed", linked[CVE]["ci"])
        self.assertEqual("awaiting_merge", linked[CVE]["appbox"])
        self.assertEqual(f"https://github.com/sample/vendor/security/advisories/{GHSA}",
                         next(row["url"] for row in linked[CVE]["sources"] if row["kind"] == "github-advisory"))

    def test_an_exact_merged_sha_and_running_digest_are_required(self):
        report = collect(FixtureGitHub(merged=True), [REPO], [plan_entry()])
        current = [{"service": "proxy", "imageId": CURRENT}]
        candidate = [{"service": "proxy", "imageId": CURRENT, "manifestDigests": [CANDIDATE]}]
        self.assertEqual("awaiting_observed_release", dict(incidents(report, current, set()))[CVE]["appbox"])
        self.assertEqual("inventory_unavailable", dict(incidents(report, None, set()))[CVE]["appbox"])
        self.assertEqual("confirmed", dict(incidents(report, candidate, set()))[CVE]["appbox"])
        report["fixes"][0]["merged"] = False
        self.assertEqual("awaiting_merge", dict(incidents(report, candidate, set()))[CVE]["appbox"])

    def test_several_advisories_for_one_pr_remain_separate_incidents(self):
        other = "GHSA-2222-3333-4444"
        report = collect(FixtureGitHub(), [REPO], [plan_entry()])
        report["fixes"][0]["advisories"].append(other)
        report["advisories"].append({
            "repository": REPO, "kind": "github-advisory", "advisories": [other],
        })
        rows = dict(incidents(report, [], set()))
        self.assertIn(CVE, rows)
        self.assertIn(other, rows)
        self.assertEqual(3, rows[other]["fixes"][0]["pr"])

    def test_previous_green_run_cannot_override_a_pending_or_failed_run(self):
        for status, conclusion, expected in (
            ("in_progress", None, "pending"),
            ("completed", "failure", "failed"),
        ):
            with self.subTest(status=status):
                checks = [
                    FixtureGitHub.run(),
                    FixtureGitHub.run(id=20, status=status, conclusion=conclusion),
                    FixtureGitHub.run(id=21, sha="b" * 40),
                ]
                result = check_fix(FixtureGitHub(checks=checks), validated_plan(plan_entry(), [REPO]))
                self.assertEqual(expected, result["ci"])
                self.assertEqual(20, result["checks"][0]["number"])

    @unittest.skipUnless(os.name == "posix", "The Appbox journal uses Unix file locks")
    def test_import_is_idempotent_and_records_new_runtime_evidence(self):
        from security import Journal

        report = collect(FixtureGitHub(merged=True), [REPO], [plan_entry()])
        with tempfile.TemporaryDirectory() as temp:
            journal = Journal(Path(temp))
            current = [{"service": "proxy", "imageId": CURRENT}]
            fixed = [{"service": "proxy", "imageId": CANDIDATE}]
            self.assertEqual(3, ingest(report, journal, current))
            self.assertEqual(0, ingest(report, journal, current))
            self.assertEqual(1, ingest(report, journal, fixed))
            rows = [json.loads(line) for line in (journal.root / "journal.jsonl").read_text().splitlines()]
            self.assertEqual(["awaiting_observed_release", "confirmed"], [
                row["appbox"] for row in rows if row.get("incident") == CVE
            ])


if __name__ == "__main__":
    unittest.main()
