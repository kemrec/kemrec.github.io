---
title: "SiYuan: GLOBALROOT Device Alias Bypasses the Sensitive-Path Guard"
date: 2026-10-13
target: "siyuan-note/siyuan"
severity: High
identifier: "GHSA-gg3p-r4g8-vxg2"
advisory_url: "https://github.com/siyuan-note/siyuan/security/advisories/GHSA-gg3p-r4g8-vxg2"
summary: "SiYuan's v3.8.7 fix for a Windows path-namespace bypass added an alias normalization that strips only the literal backslash prefix spellings it knew about; the device-namespace form — the GLOBALROOT device alias — survives it, matches no denylist entry, and reproduces the original chain: an API caller walks the workspace conf (API token, TLS private key) into the publicly served assets directory. Fixed in v3.8.7 after a same-day report."
---

## Summary

SiYuan guards its file-copying endpoints with a sensitive-path denylist
(`util.IsSensitivePath`). A previous advisory, GHSA-6gmc (High, 7.5), showed
that a Windows `\\?\`-prefixed path slips past that denylist; the v3.8.7 fix
answered with `resolveNamespaceAlias()` — a normalization that runs before the
denylist and reduces Windows path-namespace spellings to plain Win32 paths.

The normalization only strips the literal spellings it knows: `\\?\` and
`\\.\`, plus the `UNC\` marker and local admin shares. It leaves the
**device-namespace** form alone. `\\?\GLOBALROOT\Device\HarddiskVolumeN\...`
loses its `\\?\` prefix during normalization and becomes
`GLOBALROOT\Device\HarddiskVolumeN\...` — a relative-looking path that matches
none of the denylist prefixes. Windows itself accepts the original spelling at
the layer the kernel's Go code uses (`CreateFileW`), so the file is copied:

`POST /api/import/importStdMd` with the aliased path as `localPath` walks the
workspace `conf` directory into `data/assets/`, and the kernel serves it back
on `GET /assets/` without authentication. The `conf.json` contains the API
token; the copied material also includes the TLS private key.

## Background

SiYuan is a local-first note-taking application that runs a Go kernel as a
local HTTP server (port 6808 by default). Several endpoints accept absolute
**local paths** and copy files into the workspace: the markdown import API
(`/api/import/importStdMd`) and the MCP file/asset tools. Because those paths
can point anywhere on the machine, the kernel evaluates every one of them
against `util.IsSensitivePath` — a denylist covering the workspace `conf`
directory (API token, TLS keys), home-directory dotfiles (`.ssh`,
`.git-credentials`, `.env`, cloud CLI credentials), and system directories.

GHSA-6gmc (published 2026-10-09, reported separately) demonstrated that the
denylist was purely lexical: `\\?\C:\...\<workspace>\conf` normalizes at the
Win32 layer to the same file, but the string never matches a
`c:\...\<workspace>\conf` prefix. The v3.8.7 fix (commits `98487d43db`,
`9ffcc73423`) added `resolveNamespaceAlias()` to solve the class, not just the
one spelling.

## The vulnerability

The fix normalizes by **stripping known prefixes** rather than resolving the
path to its volume-local equivalent:

```go
// kernel/util/path.go (v3.8.7) — resolveNamespaceAlias()
// strips only the literal spellings:
//   \\?\   \\.\
// then filepath.Clean
```

`\\?\GLOBALROOT\Device\HarddiskVolume3\<ws>\conf` survives every step of the
guard:

1. `resolveNamespaceAlias()` strips `\\?\`, leaving
   `GLOBALROOT\Device\HarddiskVolume3\<ws>\conf`. `Clean` treats it as a
   relative path and keeps it as-is.
2. The first `isSensitivePath()` check lowercases and compares prefixes:
   `globalroot\device\harddiskvolume3\<ws>\conf` matches nothing — the
   denylist entries are `d:\<ws>\conf`, `c:\windows\system32\...`,
   `/home/.../.ssh`, and so on.
3. The wrapper's second look,
   `ResolveLongestExistingParent(p)` + re-check, also misses: the path exists,
   so the resolver preserves the volume spelling, the re-check strips `\\?\`
   again, and lands on the same non-matching string.

The same gap exists in the sibling spellings: `\\.\GLOBALROOT\...`, the
forward-slash form `//?/GLOBALROOT/...` (which `Clean` canonicalizes back to
the `\\?\` form, then misses again), and the shadow-copy family
(`HarddiskVolumeShadowCopyN`). The volume index varies per machine and is
enumerable by trial — the attacker needs no prior knowledge of the mapping.

The bypass reproduces the original advisory's full end-to-end chain. On a
Windows 10 host with SiYuan `v3.8.7-beta.3` (the build carrying the 6gmc fix),
with a fresh workspace:

**Control — the plain workspace conf path is refused:**

```
POST /api/import/importStdMd
  {"notebook":"<id>","toPath":"/","localPath":"C:\\Users\\<user>\\...\\ws\\conf"}
→ {"code":-1,"msg":"import from local path [...] failed: local path is sensitive path","data":null}
```

**Bypass — the same call through the device alias:**

```
POST /api/import/importStdMd
  {"notebook":"<id>","toPath":"/",
   "localPath":"\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Users\\<user>\\...\\ws\\conf"}
→ {"code":0,"msg":"","data":null}
```

**Result — the secrets land in the served assets directory:**

```
data/assets/: conf-*.json  (workspace config; API token byte-identical to the source)
             cert-*.pem    (-----BEGIN CERTIFICATE-----)
             ca-*.key      (-----BEGIN EC PRIVATE KEY-----)
GET /assets/conf-*.json → HTTP 200
```

The API token grants full control of the instance; the TLS key (with its
certificate) allows impersonating the instance's HTTPS endpoint.

## Impact

The guard exists to make "copy this local file into my workspace" safe to
expose to API callers. After the fix, one spelling — a device-namespace alias
that Windows resolves like any other path — still defeats it, so the same
preconditions as the original advisory apply: a caller able to invoke the
import API (or the MCP file tool) can read the workspace configuration and TLS
material out of `data/assets/`, and the same form reaches `~/.ssh`, `~/.env`,
`~/AppData`, and the rest of the denylist's territory on Windows.

The advisory rates it `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5
High** (CWE-41 → CWE-22; secondary CWE-184), mirroring the vendor's own
scoring of the advisory this one extends.

## The fix

The advisory lists the fix as shipping in **v3.8.7** (the release line that
was in beta at publication time; the build this bypass was verified against,
`v3.8.7-beta.3`, still carries the incomplete normalization). The suggested
direction was either to resolve `GLOBALROOT`/`Device\HarddiskVolumeN` forms to
their mounted drive letters (`QueryDosDevice` /
`GetVolumeNameForVolumeMountPoint`) before the denylist runs, or to reject
device-namespace prefixes outright at the API/MCP boundary — they are never
legitimate for user-supplied file paths. The advisory also carries a
regression list: `\\?\GLOBALROOT\...`, `\\.\GLOBALROOT\...`, the
forward-slash spelling, lowercase volume names, and `HarddiskVolumeShadowCopyN`
forms of each denied prefix.

## Timeline

- **2026-10-13** — Verified end-to-end on a real Windows 10 host against
  `v3.8.7-beta.3` (control refused / alias accepted / token byte-identical /
  HTTP 200 readback); reported via GitHub's private vulnerability reporting.
- **2026-10-13** — Advisory published the same day:
  `GHSA-gg3p-r4g8-vxg2`, High (CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5, CWE-41/CWE-22/CWE-184), no CVE
  assigned.

## Disclosure

Full advisory: [GHSA-gg3p-r4g8-vxg2](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-gg3p-r4g8-vxg2)
(published 2026-10-13; High; no CVE assigned; credits this report). The fix
ships in the v3.8.7 line per the advisory. This writeup describes behavior
verified against `v3.8.7-beta.3` on Windows 10 22H2, using a fresh workspace;
the prior advisory in the chain is
[GHSA-6gmc-424x-xgpm](https://github.com/siyuan-note/siyuan/security/advisories/GHSA-6gmc-424x-xgpm)
(fix commits `98487d43db` and `9ffcc73423`).
