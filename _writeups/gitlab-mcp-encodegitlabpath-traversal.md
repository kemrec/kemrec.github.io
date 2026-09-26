---
title: "encodeGitLabPath Never Blocks ../: Path Traversal to Arbitrary GitLab API Endpoints"
date: 2026-09-23
target: "zereight/gitlab-mcp"
severity: High
identifier: "GHSA-m682-5gg2-5rc9"
advisory_url: "https://github.com/zereight/gitlab-mcp/security/advisories/GHSA-m682-5gg2-5rc9"
summary: "A patch meant to fix a path-traversal bug in gitlab-mcp's download tools doesn't actually block '../' segments, letting any caller redirect requests to arbitrary GitLab API endpoints under the operator's token."
---

## Summary

`zereight/gitlab-mcp` is an MCP server that lets an LLM client call GitLab's
API on an operator's behalf — list projects, download release assets, pull
job artifacts, and so on, using a token configured on the server side. Two
of its tools, `download_release_asset` and `get_job_artifact_file`, plus two
HTTP download-proxy routes, build a GitLab API URL by splicing in a
caller-supplied path. A previous advisory against this exact code
(GHSA-4rm9-rfp2-j39q) already found that the raw path could escape its
intended prefix via `../` segments, and the maintainer shipped a fix:
a helper called `encodeGitLabPath` that "encodes" the path before use.

The fix doesn't work. `encodeGitLabPath` never touches a `..` segment,
so the traversal it was written to stop is still live — in the exact
function it patched, plus three more call sites that share the same
helper.

## Background

`encodeGitLabPath` and `encodeGitLabPathSegment` exist to safely handle a
path that legitimately contains `/`-separated segments (a nested file
path inside a release or artifact) without turning every `/` into `%2F`,
which would break normal multi-segment paths:

```typescript
function encodeGitLabPathSegment(value: string): string {
  return encodeURIComponent(decodeURIComponent(value));
}
function encodeGitLabPath(value: string): string {
  return value.split("/").map(encodeGitLabPathSegment).join("/");
}
```

The idea is: split on `/`, percent-encode each piece on its own, rejoin.
That should stop a segment from containing anything that lets it break out
of its slot in the URL.

## The vulnerability

`encodeURIComponent` treats `.` as an *unreserved* character — it is
specified to never encode it. Split `"../../../../user"` on `/` and you get
`["..", "..", "..", "..", "user"]`; run `encodeGitLabPathSegment` on each
piece and every one of them comes back completely unchanged, because
there is nothing in a `..` segment for `encodeURIComponent` to encode.
Rejoining reproduces the exact input string. The "encoding" step does
nothing at all to a dot-segment payload.

The result is then embedded in a template literal and handed to
`new URL(...)` — which *does* collapse dot-segments, per RFC 3986 §5.2.4.
That's the one part of the URL spec `encodeGitLabPath` needed to defend
against, and it doesn't.

Four call sites reproduce this pattern, all reachable and all unpatched
at the time of reporting:

```typescript
// 1. downloadReleaseAsset() — the exact function GHSA-4rm9 was filed against
`${apiUrl}/projects/${encodeURIComponent(projectId)}/releases/${encodeGitLabPathSegment(tagName)}/downloads/${encodeGitLabPath(directAssetPath)}`

// 2. getJobArtifactFile() — inlines the identical split/map/join logic
//    instead of calling the shared helper, but is exactly as vulnerable
`${apiUrl}/projects/${encodeURIComponent(projectId)}/jobs/${encodeGitLabPathSegment(jobId)}/artifacts/${encodedArtifactPath}`

// 3. downloads/proxy.ts "attachment" route (filename query param)
`${apiUrl}/projects/${encodeURIComponent(projectId)}/uploads/${encodeGitLabPathSegment(secret)}/${encodeGitLabPath(filename)}`

// 4. downloads/proxy.ts "release-asset" route (direct_asset_path query param)
`${apiUrl}/projects/${encodeURIComponent(projectId)}/releases/${encodeURIComponent(tagName)}/downloads/${encodeGitLabPath(directAssetPath)}`
```

A minimal proof of concept needs no live GitLab instance at all — the
escape happens purely in URL construction, before any network request:

```js
function encodeGitLabPathSegment(value) {
  return encodeURIComponent(decodeURIComponent(value));
}
function encodeGitLabPath(value) {
  return value.split("/").map(encodeGitLabPathSegment).join("/");
}

const apiUrl = "https://gitlab.example.com/api/v4";
const directAssetPath = "../../../../user"; // attacker-controlled

const url = `${apiUrl}/projects/1/releases/v1.0.0/downloads/${encodeGitLabPath(directAssetPath)}`;
console.log(new URL(url).toString());
// -> https://gitlab.example.com/api/v4/projects/user
```

The intended `/projects/{id}/releases/{tag}/downloads/` prefix disappears
entirely; the request lands on `/api/v4/projects/user` instead.

## Impact

Any caller of `download_release_asset` or `get_job_artifact_file` — or
either affected HTTP download-proxy route — can redirect the request the
server makes, carrying the operator's real GitLab token, to an arbitrary
`GET /api/v4/...` endpoint instead of the intended download. That reaches
things like `/api/v4/user` (the token owner's account details) or other
projects' and groups' data the calling tool was never meant to expose.
Since this is an MCP tool argument, the value doesn't have to come from a
deliberately malicious human operator — an LLM client steered by a
prompt-injected instruction can supply it just as easily.

The scope is limited to the operator's own configured GitLab host — this
is request-path forgery within that instance, not external SSRF — but
within that scope, it turns a narrowly-scoped download feature into a way
to read anything the configured token can read.

## Timeline

- **2026-09-16** — Reported to the maintainer via GitHub's private
  security-advisory reporting, with a runnable proof of concept covering
  all four call sites.
- **2026-09-23** — Advisory published as `GHSA-m682-5gg2-5rc9`, High (CVSS
  3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5).
- Fixed in **2.1.65**.

## Disclosure

Full advisory: [GHSA-m682-5gg2-5rc9](https://github.com/zereight/gitlab-mcp/security/advisories/GHSA-m682-5gg2-5rc9).
