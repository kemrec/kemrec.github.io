---
title: "django-allauth's Rate Limiter Overran by Up to 200x Under Concurrency"
date: 2026-09-11
target: "pennersr/django-allauth"
severity: High
identifier: "django-allauth 65.19.3"
advisory_url: "https://github.com/pennersr/django-allauth/blob/65.19.3/ChangeLog.rst"
summary: "django-allauth's rate limiter read-modify-wrote its counters with no atomic operation, so concurrent requests overwrote each other's hits — for TOTP, the only thing standing between a stolen password and a working session."
---

## Summary

django-allauth's built-in rate limiter is the only thing standing between
an attacker who already has a password and a valid TOTP code — a 6-digit
number with a 30-second lifetime. The limiter's own docstring acknowledged
it could let "a few" extra requests through under concurrency and called
that an acceptable margin of error. It wasn't a few. At 1024 concurrent
requests against a 5-per-5-minutes limit, 984 got through — a 197x
overrun, scaling directly with how many requests an attacker sends at
once.

## Background

`allauth/mfa/base/internal/flows.py`'s `check_rate_limit` gates both TOTP
and WebAuthn login attempts through `allauth/core/internal/ratelimit.py`'s
`_consume_single_rate`, keyed per-user (`mfa-auth-user-<pk>`), defaulting
to 5 attempts per 300 seconds. Since `MFA_TOTP_TOLERANCE` defaults to 0,
this limiter is the *entire* defense against brute-forcing a 6-digit code
once an attacker already holds the password — normally an acceptable
design, because 5 guesses per window makes brute force impractical.

The module's docstring was explicit about the race and, incorrectly,
about its bound:

> you may occasionally observe slight overruns—such as 11 or 12 requests
> slipping through … exceeding the limit by a large margin is highly
> unlikely.

## The vulnerability

`_consume_single_rate` does a plain `cache.get` → compute → `cache.set`,
with no atomic operation, and writes back the *entire* timestamp list
rather than incrementing a counter. Two concurrent callers that both read
before either writes will both see room under the limit, and the second
write clobbers whatever the first one recorded — the classic
check-then-act race, just on a cache instead of a database row.

Measured against a Redis-backed limiter (the backend most production
deployments would actually run), with a 5-per-300s limit:

| Concurrent callers | Allowed | Expected | Overrun |
|---|---|---|---|
| 8 | 5 | 5 | 1x (correct) |
| 128 | 59 | 5 | 12x |
| 512 | 146 | 5 | 29x |
| 1024 | 984 | 5 | **197x** |

The overrun scales with attacker concurrency, not with a fixed small
constant the way the docstring described. It does converge after the
first burst — a second wave against the same already-exhausted window let
through zero further requests, so this is one large overshoot per window
rather than an unbounded leak. End-to-end against a real running
`/accounts/2fa/authenticate/` endpoint (concurrency capped lower than the
limiter-level test by what a single-process dev server can actually fire
simultaneously): 128 concurrent guesses got 65 evaluated against an
intended limit of 5, versus exactly 5 when the same guesses were sent
sequentially.

`LocMemCache` — a single-process in-memory cache — doesn't show this at
all; a single Python-level lock effectively serializes access to it
regardless of what the rate-limiter code itself does. The race only
becomes observable with a real shared cache backend, which is exactly
what a multi-worker production deployment requires. That's likely why the
docstring's stated bound, while wrong, wasn't obviously wrong from
whatever testing produced it.

## Impact

For an attacker who already has a victim's password, TOTP's only
remaining defense is that a 6-digit code has 300 seconds to be guessed
correctly out of a nominal 5 tries. A 197x overrun on that limit turns "5
guesses per 5-minute window" into "closer to a thousand guesses per
window" for anyone willing to fire enough concurrent requests — a
materially different brute-force cost against a 6-digit space.

## Fix

The maintainer's fix wraps the whole read-modify-write critical section
in a `cache.add()`-based mutex — a lock built from the one operation every
Django cache backend implements atomically, rather than a Redis-specific
`INCR`/Lua approach that wouldn't generalize across backends. Failing to
acquire the lock is treated as "over the limit," so the rate limiter fails
closed rather than open under lock contention.

Verified against the same concurrency sweep: exactly 5 requests allowed at
every concurrency level from 8 to 1024, both at the limiter level and
end-to-end over real HTTP, with legitimate TOTP codes still authenticating
normally and sequential requests still cutting off at exactly 5. The one
real trade-off worth naming: past a few hundred truly concurrent callers
on the same key, the lock queues and a 1024-way burst's wall time rises to
around 2.3 seconds — denials mostly shift from "over limit" to "lock
timeout," but the limiter still fails closed either way.

## Timeline

- **2026-09-11** — Reported by email (django-allauth's rate-limit
  documentation names email as the reporting channel; GitHub private
  vulnerability reporting isn't enabled on this repo).
- **2026-09-11** — Maintainer fixed the same day
  (`fix(ratelimit): atomic updates`), released in **65.19.3**, with a
  public security notice in the changelog crediting the report.

## Disclosure

No formal CVE/GHSA was filed for this one — django-allauth disclosed it
directly through a security notice in its own changelog, released the
same day as the fix:

> A known flaw in the built-in rate limiting was that the configured
> limits could be exceeded under a high volume of concurrent requests.
> This was documented as an acceptably small margin of error. However, as
> Kaya Emre Arikan (kemrec) demonstrated, the limits could be
> substantially exceeded under a sufficiently high volume of concurrent
> requests. This is now fixed by serializing rate limit updates.

Full changelog entry: [ChangeLog.rst, 65.19.3](https://github.com/pennersr/django-allauth/blob/65.19.3/ChangeLog.rst).
