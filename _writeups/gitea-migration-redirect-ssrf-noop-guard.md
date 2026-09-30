---
title: "Gitea: The Migration SSRF Guard That Did Nothing"
date: 2026-09-28
target: "go-gitea/gitea"
severity: High
identifier: "CVE-2026-57894"
advisory_url: "https://github.com/go-gitea/gitea/security/advisories/GHSA-82f7-87hm-852x"
summary: "CVE-2026-57894 was an SSRF in Gitea's repository migration: the URL is checked against the allow/block policy, then the transfer is handed to git, which follows the first HTTP redirect by default. The function meant to disable redirect-following, HandleGitCmdHTTPRedirection, shipped as an empty no-op — so the 1.27.0 'fix' left the bug fully exploitable through v1.27.3."
---

## Summary

`CVE-2026-57894` (`GHSA-82f7-87hm-852x`) is a server-side request forgery
in Gitea's repository migration and pull-mirror feature. Gitea validates the
**initial** URL of a migration against its allow/block-list policy, but the
actual data transfer is delegated to the `git` CLI — which follows the first
HTTP redirect by default. A URL that passes the policy can `301`/`302` to a
host the policy explicitly blocks, and Gitea imports whatever that second
host serves.

The advisory was marked patched in `1.27.0`. It wasn't. The function that is
supposed to disable redirect-following was present, wired into every relevant
call site, and completely empty — its body was a block of commented-out code
ending in a `FIXME`. The bug remained reachable, byte-for-byte, through the
then-latest tagged release `v1.27.3` and `main`, until a proper fix landed in
late September 2026.

## Background

Gitea lets a user migrate an external repository by URL, and lets it keep a
repository in sync as a scheduled *pull mirror*. Because the server itself
fetches the URL, both features are classic SSRF surfaces, so Gitea gates them
behind a policy: `services/migrations/migrate.go`'s `IsMigrateURLAllowed`
resolves the submitted host and rejects anything on `BLOCKED_DOMAINS`, or
anything in a private/loopback range when `ALLOW_LOCALNETWORKS = false`.

The catch is that `IsMigrateURLAllowed` only ever sees the host the user
**submitted**. The bytes are actually pulled by `git`, invoked as a
subprocess, and `git` follows HTTP redirects on its own. So the interesting
question is whether Gitea disables that redirect-following. It has a function
for exactly that purpose.

## The vulnerability

The redirect guard lives in `modules/git/redirection.go`:

```go
// modules/git/redirection.go
func HandleGitCmdHTTPRedirection(cmd *gitcmd.Command, targets ...string) {
	// Protect from SSRF vector (e.g. migrating from an attacker URL).
	// cmd.AddConfig("http.followRedirects", "false")
	// However, we can't do so at the moment:
	// this fails due to 301: git -c http.followRedirects=false clone -v https://gitlab.com/{owner}/{repo}
	// this succeeds:         git -c http.followRedirects=false clone -v https://gitlab.com/{owner}/{repo}.git
	// FIXME: GIT-CLONE-HTTP-REDIRECT-SSRF: need a complete solution in the future
}
```

The whole body is commented out. It is called from exactly the places you'd
expect — `modules/git/repo.go` for the clone, and three times in
`services/mirror/mirror_pull.go` for scheduled pull-mirror fetches — so the
hook point is correct. There is simply no protection behind it. The intended
`git -c http.followRedirects=false` was disabled because it broke the very
common `https://host/owner/repo` → `https://host/owner/repo.git` redirect, and
nothing was put in its place.

That leaves the two halves of the check disconnected:

- `IsMigrateURLAllowed` validates the **submitted** host, up front.
- `git` performs the transfer and follows the **first redirect** to wherever it
  points — a host that was never re-validated against the policy.

Checking the released code confirmed this was the shipping state, not an
unreleased regression: `git show v1.27.3:modules/git/redirection.go` returned
the same empty function, byte for byte.

## Impact

Any authenticated user who can create a migration or a pull mirror — the
default for an ordinary account on an instance with open registration — can
point Gitea at an attacker-controlled endpoint that `301`-redirects to an
internal or explicitly blocked Git-over-HTTP host, and have the server fetch
and import that repository's contents.

The exploitation shape is straightforward:

1. An administrator blocks an internal host (via `BLOCKED_DOMAINS`, or simply
   by leaving `ALLOW_LOCALNETWORKS = false`). A direct migration from that host
   is correctly rejected — `422 You can not import from disallowed hosts.`
2. The attacker stands up an ordinary public endpoint that answers every
   request with a `301` redirect to the blocked host's `.git` endpoint.
3. The attacker migrates from that public redirector. It passes the policy
   check, `git` follows the redirect, and the migration succeeds — `201 Created`.
4. The blocked repository's contents now sit, byte-for-byte (identical blob
   SHAs), inside the attacker's own repository, readable through the normal API.

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N` — **High**, matching the original
advisory. Pull mirrors make it persistent: a scheduled `git fetch` keeps
following the same redirect, so new commits on the target keep flowing to the
attacker over time. The reachable set is anything the *server* can talk to —
internal Git services, cloud metadata endpoints exposing a Git-over-HTTP
surface, or any host an admin deliberately put on the block-list.

## The fix

A blanket `http.followRedirects=false` was never viable, because it breaks the
legitimate `.git`-suffix redirect that many Git hosts issue. The complete fix
took a different route: **PR #39426, `fix(git)!: use internal proxy for all git
operations`** (merged 2026-09-29), routes every git operation through an
internal proxy so that each hop can be validated, closing both the
redirect-following gap and the related DNS-rebinding hole where the host that
passes validation differs from the host that is finally connected to.

For instances that cannot yet take that release, the advisory was updated with
mitigation guidance (fronting git's outbound traffic with a proxy that enforces
the host policy). If you run Gitea and allow non-admins to create migrations or
pull mirrors, update to a release containing #39426, or apply the proxy
mitigation in the meantime.

## Timeline

- 2026-07-13 — `CVE-2026-57894` / `GHSA-82f7-87hm-852x` published, marked patched in `1.27.0`.
- 2026-09-12 — Reported to Gitea that the `1.27.0` fix was incomplete: `HandleGitCmdHTTPRedirection` is an empty no-op and the SSRF is still reproducible through `v1.27.3` and `main`.
- 2026-09-28 — Advisory updated with mitigation guidance for older versions; issue confirmed as actively tracked.
- 2026-09-29 — Proper fix merged (#39426, internal proxy for all git operations).

## Disclosure

Public advisory: [GHSA-82f7-87hm-852x](https://github.com/go-gitea/gitea/security/advisories/GHSA-82f7-87hm-852x)
(`CVE-2026-57894`). Fix: [go-gitea/gitea#39426](https://github.com/go-gitea/gitea/pull/39426).
