---
title: "python-social-auth: Login CSRF in the Last.fm Backend"
date: 2026-09-30
target: "python-social-auth / social-core"
severity: Medium
identifier: "GHSA-99rw-f693-vv9r"
advisory_url: "https://github.com/python-social-auth/social-core/security/advisories/GHSA-99rw-f693-vv9r"
summary: "The LastFmAuth backend starts its login flow without storing anything in the session and accepts any callback token, so a token approved in the attacker's own browser can authenticate a victim's session as the attacker's Last.fm identity. The project's earlier login-CSRF campaign fixed four backends but never touched this one."
---

## Summary

`social-auth-core` (the backend engine behind `python-social-auth`, used by the
Django/Flask/… integrations) shipped a login-CSRF in its **Last.fm** backend:
`LastFmAuth` drives the whole authentication flow without ever binding it to the
browser session that started it.

- `auth_url()` returns the Last.fm authorization URL and stores **nothing** in
  the session — no `state`, no server-generated token.
- `auth_complete()` reads the `token` parameter straight from the callback,
  exchanges it for a Last.fm session, and logs the **current request's session**
  in as whoever approved that token.

So an attacker can approve the application in their own browser, capture the
callback URL, and get a victim's browser to open it. The victim ends up in a
fully authenticated session that belongs to the **attacker's** Last.fm identity.
Fixed in **5.2.0**.

## Background

`python-social-auth` runs third-party logins through per-provider *backends*.
For OAuth2 providers the framework already defends against login CSRF by
default: `BaseOAuth2` turns the `state` parameter on (`STATE_PARAMETER = True`),
stores a random value in the session when the flow starts, and
`validate_state()` rejects any callback whose `state` is missing, unknown, or
mismatched. That single check is what ties "the browser that began the flow" to
"the browser that came back on the callback."

Last.fm does not use OAuth2 — it has its own web-auth handshake with a `token`
parameter and an MD5-signed `auth.getSession` exchange — so it never inherited
that protection and needs its own equivalent. It didn't have one.

This is the same class the project fixed repeatedly during an earlier login-CSRF
campaign — LoginRadius (`GHSA-x7qq-23vw-7pfg`), Twilio, and the LINE backend
(`GHSA-526j-582w-7fm9`, itself published as an *incomplete fix* of the 5.0.0
round). The Last.fm flow was simply never part of that campaign.

## The vulnerability

`social_core/backends/lastfm.py`, identical in `5.1.1` and on `master` at the
time of reporting:

```python
def auth_url(self):
    return self.AUTH_URL.format(api_key=self.setting("KEY"))

@handle_http_errors
def auth_complete(self, *args, **kwargs):
    """Completes login process, must return user instance"""
    key, secret = self.get_key_and_secret()
    token = self.data["token"]

    signature = hashlib.md5(
        f"api_key{key}methodauth.getSessiontoken{token}{secret}".encode()
    ).hexdigest()

    response = self.get_json(
        "https://ws.audioscrobbler.com/2.0/",
        data={
            "method": "auth.getSession",
            "api_key": key,
            "token": token,
            "api_sig": signature,
            "format": "json",
        },
        method="POST",
    )

    kwargs.update({"response": response["session"], "backend": self})
    return self.strategy.authenticate(*args, **kwargs)
```

`auth_url()` writes nothing to `self.strategy.session_*`, and `auth_complete()`
consumes `self.data["token"]` with no comparison against any pre-flow session
value — there is not even a stored value that *could* be compared. Because the
callback is a plain, idempotent `GET` that carries only a `token`, no callback of
this backend can be distinguished as "the one this browser started." That is the
definition of login CSRF.

## Impact

- **Forced authentication.** Any visitor who can be lured into opening the
  crafted callback URL — a link, a meta-refresh, an `<img>`/iframe — lands in a
  session authenticated as the attacker's Last.fm account, without ever touching
  Last.fm themselves.
- **Attribution to the attacker.** Anything the victim then does in that session
  (uploads, profile edits, saved settings, payment details) accrues to — and is
  readable from — the attacker's account. In per-user apps the victim is also
  shown the attacker's data.
- **Account-linking escalation.** When an app links social identities onto an
  already-authenticated local account, the same flow binds the attacker's Last.fm
  identity to the victim's account, creating a persistent unauthorized login path
  — exactly the consequence the LINE advisory describes for this class.

The only precondition is that the Last.fm backend is enabled for login; no
special configuration and no account on the target app are required for the
victim. `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` — **Medium (5.4)**,
CWE-352.

## The fix

`5.2.0` gives the Last.fm flow its own session binding, mirroring the OAuth2
`state` mechanism (and the one-line LINE fix). `auth_url()` now generates a
state value and stores it in the session; `auth_complete()` calls
`validate_state()` before doing anything with the token:

```python
def validate_state(self):
    # rejects a callback whose state is missing / unknown / mismatched
    ...

def auth_complete(self, *args, **kwargs):
    self.validate_state()
    ...
```

A callback whose state the session never issued is now refused, so a token
approved in another browser can no longer complete a login in the victim's
session. Upgrade `social-auth-core` to **5.2.0** or later.

## Timeline

- 2026-09-26 — Reported to the maintainers via private advisory.
- 2026-09-30 — Fixed in `social-auth-core` 5.2.0; advisory `GHSA-99rw-f693-vv9r` published.

## Disclosure

Public advisory: [GHSA-99rw-f693-vv9r](https://github.com/python-social-auth/social-core/security/advisories/GHSA-99rw-f693-vv9r)
(no CVE assigned). Fixed in [social-auth-core 5.2.0](https://github.com/python-social-auth/social-core/releases/tag/5.2.0).
