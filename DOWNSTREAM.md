# Odessei fork

The original project is [torsher-app/torsher](https://github.com/torsher-app/torsher).
The fork keeps its changes in `main` as Git commits. Sync upstream Torsher
checks the original `main` daily and opens a pull request when there are new
commits. It can also be run from the Actions tab.

For a sync PR, approve the CI workflow if GitHub prompts and merge with
**Create a merge commit** after CI passes. This keeps upstream commits in the
fork's history, so the next sync only includes new changes.

If an upstream PR conflicts, create a branch from the fork's `main`, merge
`upstream/main` locally, resolve conflicts and open a PR from that branch.
Use a merge commit there too. The sync job reports when it finds that
`main` already contains the upstream commits.

Repository Actions must allow workflows to create pull requests. The sync
workflow uses the repository's built-in GitHub token with read access to
contents and write access to pull requests.
## Deployment settings

Keep account credentials, service addresses, keys, invite links and live
configuration outside the repository. The Secret scan workflow checks new Git
commits for credentials and database files.

Set `TORSHER_COMPLETE_TORRENT_ON_PLAYBACK=1` in the server environment to keep
and complete the selected torrent in the background when its player opens.
Playback keeps its normal streaming behavior when there is insufficient space.