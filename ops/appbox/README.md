# Appbox maintenance

This directory contains publishable manifests. The live Compose project and its
credentials belong on the host. The image-only manifests do not replace the
live volumes, network or reverse proxy configuration.

## Dependencies and ownership

| Function | Runtime dependencies |
| --- | --- |
| Login, invites and sessions | Provider Apache and TLS, Traefik, Torsher, SQLite, session keys |
| Catalogue | Torsher, TMDB metadata and configured credentials |
| Search and torrent metadata | Torsher, Prowlarr or Jackett, configured indexers, FlareSolverr for selected sources |
| Playback | Traefik, Torsher, persistent library, torrent engine, tracker and peers for live downloads, FFmpeg for HLS |

The host kernel, Apache, host packages and service launcher policy belong to the
provider. Traefik has no Compose project label on the reference host. Treat its
live replacement as a manual operation until the lifecycle owner and supported
procedure are confirmed. The four application services use Compose. Their
settings and library volumes stay attached across image changes.

The running Torsher base image may contain read-only release overrides. The
scanner records their hashes and scans the selected code, TV/web assets and
engine binary separately. Runtime directories, SQLite files, secret files,
indexer settings and invite databases are out of scope for the artifact copy.
JavaScript bundle hashes identify the code even when a binary scan cannot infer
package identities. OSV covers the supported package manifests and lockfiles.

## Reports and update decisions

Run the systemd user timer in report-only mode. The journal lives under
`~/.local/state/appbox-security/`. Read `summary.log` for each run and
`journal.jsonl` for findings, data sources, versions, release identifiers,
errors and decisions. Both rotate after 5 MiB with six archives. The user
systemd journal retains unit exit status. Critical findings appear locally in
the JSONL report. External alert delivery awaits the owner's channel choice.

Findings count scanner records. Correlate duplicates and verify the affected
feature against the vendor advisory before assigning an operational priority.
A CISA KEV match, a reachable route and an available fix raise the priority.
An unavailable KEV feed is recorded separately. An advisory without a fix
remains open in the journal. Ubuntu package candidates describe the local apt
index. The provider must verify backports, planned kernel reboots and the
running versions of services outside this rootless Docker account.

Renovate checks npm, Go, Gradle and the pinned container images. A custom
manager extracts tags and digests from the Compose JSON manifests in this
directory. Changes go through a PR. CI scans the pinned Compose images,
records lockfile advisory results and builds a single Torsher image containing
the maintained patches. GitHub can require workflow approval for PRs created
with the repository token. Use a tested registry digest for a rollout.
The Dockerfile pins the base images. Package mirrors and build timestamps can
still change the byte-level output of an independent rebuild.

## Pilot and rollout

`pilot.py` checks the pinned Traefik candidate in an isolated network
namespace. On Appbox it starts the previous local digest against the same
fixture to check rollback. The fixture covers trusted access, outside denial
with a supplied forwarding header, Range and HLS manifest transport. It does
not use production labels, tracker accounts or private hostnames.

`gate.py` is report-only. It reads the Torsher open-stream counter, connected
device activity and recent playback events. A live Range request counts even
when the viewer made no recent API request. Use `--stdin` for a short-lived
owner session passed securely or `--cookie-file` with a private file outside
the repository. Unknown activity and active viewing both defer the plan.

Before enabling release automation, approve the exact update policy and match
the reviewed commit, tested registry digest and intended dependencies in the
private GitOps manifest. Eligible automatic releases are limited to approved
patch classes that preserve schema, data formats and access rules. Group any
required dependency changes in one candidate. Major versions, migrations,
format changes, access changes and provider-owned services require review.

Before any application rollout, use isolated copies or synthetic data to test
actual Torsher login, removed-access denial, active guest routes if enabled,
configured indexer search and metadata, local and test torrent playback,
seek, Range, HLS and preserved viewer state. Test restore with a compatible
backup before any migration. Keep the prior image and matching configuration.
After rollout verify the actual image digest and rerun the relevant probes.
Roll back and hold the dependency group if a post-rollout check fails. Remove
release overrides only after the fork image is shown to contain their behavior.

Keep real service addresses, keys and registry credentials outside this repo.
Use Compose `env_file` or mounted secrets at runtime. The Appbox image workflow
does not supply a TMDB key or other production secret to the build.

## GitHub evidence in the private journal

Use Dependabot alerts for detection and Renovate for update PRs. Keep
Dependabot security-update PRs disabled. GitHub manages its own notifications.
The journal collector adds context to existing scanner findings and sends no
additional notifications.

`github_journal.py collect --repo OWNER/REPO` reads alerts and CodeQL results.
Supply a credential over stdin or use `--token-file` with a private file for
read-only unattended collection. Restrict a dedicated credential to the
selected repositories and the GitHub permissions needed to read Dependabot,
code scanning, secret scanning, pull requests and Actions. Secret Scanning
requests use GitHub's redacted response mode. The output contains allowlisted
metadata only.

Pass the collector's JSON to `github_journal.py ingest --state <state-dir>`
over stdin on Appbox. Run the importer with the same account and state
directory as `security.py`. It records GitHub URLs, alert and advisory IDs,
analysis SHAs and release evidence in the existing JSONL journal. Related CVE
and GHSA identifiers are grouped into one incident. Identical polls reuse the
existing evidence entry. A read failure leaves the previous evidence in place
and records the failed query.

Use `--plan <private-fixes.json>` on the collector to associate an advisory
or alert with a fix. This example shows the input format. The repository names,
SHA and digest are placeholders.

```json
[
  {
    "repository": "example/project",
    "advisories": ["GHSA-xxxx-yyyy-zzzz"],
    "advisoryRepository": "example/vendor",
    "pr": 12,
    "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "workflows": [".github/workflows/ci.yml"],
    "target": {"service": "proxy", "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  }
]
```

For an individual GitHub alert, supply its `kind` (`dependabot`,
`code-scanning` or `secret-scanning`) and `number`. Use the tested PR head
while the PR is open. After merge, record the exact merge SHA and evidence
from CI on the base branch. The importer marks Appbox `confirmed` only
after successful CI for that merged revision and a matching running image.
Supply a digest for a rebuild or fork and use a version only for a distinct
vendor release. Keep the plan and the journal outside the public repository.
