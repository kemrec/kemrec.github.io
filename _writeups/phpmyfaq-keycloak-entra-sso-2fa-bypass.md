---
title: "phpMyFAQ: Keycloak and Entra ID SSO Logins Bypass the Two-Factor Token Step"
date: 2026-10-03
target: "thorsten/phpMyFAQ"
severity: High
identifier: "GHSA-8fvf-747v-qjr6"
advisory_url: "https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-8fvf-747v-qjr6"
summary: "phpMyFAQ's Keycloak and Entra ID SSO callbacks resolve the local account and grant a session without ever reading `twofactor_enabled`, so an account protected by TOTP two-factor logs in through SSO at single-factor strength. Reproduced live end to end on the Keycloak path — zero references to the token step — and fixed in ebca8fd."
---

## Summary

phpMyFAQ supports TOTP two-factor authentication and, separately, SSO login through
Keycloak and Microsoft Entra ID. When an account has TOTP enabled, every
login-completing path in the product is expected to stop at the token step — the
password path, the passkey path and the API path all consult `twofactor_enabled`,
and the passkey controller states the invariant in a code comment.

The two SSO callbacks do not. `KeycloakAuthenticationController::callback()` and
`AzureAuthenticationController::callback()` take the provider's verdict, resolve the
local account and then call `setLoggedIn(true)`, `updateSessionId(true)` and
`saveToSession()` directly. Neither ever reads `twofactor_enabled`, and neither arms
`2fa_pending_user_id`.

Result: a user with TOTP enabled who signs in through Keycloak (or Entra ID) is
granted a fully authenticated phpMyFAQ session after the first factor alone. The
second factor is never requested — the live run below shows zero references to the
token page anywhere in the flow — so SSO deployments effectively run at
single-factor strength for every account that believes it is protected by 2FA,
administrators included.

Reported privately and fixed the next day; the advisory was published on
**2026-10-03**, with the fix shipped in the `4.2.0-beta` tag.

## Background

phpMyFAQ is a PHP-based FAQ / knowledge-base application. Its 4.2 development line
added SSO login via Keycloak and Microsoft Entra ID alongside the existing TOTP
two-factor support, and an account can have both: a TOTP-enabled account that also
signs in through SSO.

The product's own rule is that a login path must not grant a session when
`twofactor_enabled` is set — it hands the browser to the token step
(`token?user-id=…`) instead, and the second factor is verified there. The passkey
controller spells the invariant out:

```php
// If the account has TOTP two-factor enabled, the passkey counts as the first factor only:
// defer to the token step instead of granting the session, mirroring the password
// login flow, so a passkey cannot bypass two-factor authentication.
if ((int) $currentUser->getUserData('twofactor_enabled') === 1) {
    ...
    $this->session->set('2fa_pending_user_id', $currentUser->getUserId());
    $this->session->set('2fa_pending_remember_me', false);
    return $this->json(['redirect' => $defaultUrl . 'token?user-id=' . $userId]);
}
```

Count of `twofactor_enabled` reads per login-completing path (at `4.2.0-alpha.2` → at
`main`):

| path | file | reads `twofactor_enabled` |
|---|---|---|
| password / session restore | `User/CurrentUser.php` | yes (3 → 3) |
| password | `User/UserAuthentication.php` | yes (1 → 1) |
| passkey | `Controller/Frontend/Api/WebAuthnController.php` | no in alpha.2 (0) → yes on `main` (1) |
| API | `Controller/Frontend/Api/LoginController.php` → authenticates through the service | gated by the service |
| **Keycloak SSO** | `KeycloakAuthenticationController.php` | **no (0 → 0)** |
| **Entra ID SSO** | `AzureAuthenticationController.php` | **no (0 → 0)** |

This is a sibling of a class the project has already accepted twice: both earlier
advisories concern *another login path that forgot the second factor* —
[GHSA-8gpw-xvpf-hvx5](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-8gpw-xvpf-hvx5)
(CVE-2026-56737, "two-factor authentication login bypasses the password factor") and
[GHSA-hvj7-4fmg-53cr](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-hvj7-4fmg-53cr)
("2FA Bypass via Remember-Me Cookie Issued Before Second Factor Verification"). The
fix commits for the first (`410208b9`, `5097dff3`, `6a69f6e2`) touch the password-path
files only; the two SSO callbacks were never brought into the 2FA model.

## The vulnerability

`KeycloakAuthenticationController::callback()`, after the local account is resolved
and its Keycloak subject checked (commit `09969d672`, the fix's parent):

```php
if (!$this->isLinkedToKeycloakSubject($user, $claims)) {
    // ... subject mismatch -> abort
}

$user->setLoggedIn(true);
$user->setAuthSource(AuthenticationSourceType::AUTH_KEYCLOAK->value);
$user->updateSessionId(true);
$user->saveToSession();          // <- no twofactor_enabled check, no 2fa_pending_user_id
$user->setTokenData([...]);
$user->setSuccess(true);
```

`AzureAuthenticationController::callback()` has the same shape. It even validates
that the local account is usable — blocked accounts are refused — but the 2FA state
is simply not part of that check:

```php
// Only the account the driver resolved for this identity may be logged in, and
// getUserById() refuses blocked accounts and the anonymous user.
$user = $this->getCurrentUserService();
$userId = $auth->getAuthenticatedUserId();
if ($userId <= 0 || !$user->getUserById($userId) || $user->getUserId() <= 0) {
    return $this->loginFailed();      // account-status check exists, 2FA check does not
}

$user->setLoggedIn(true);
$user->setAuthSource(AuthenticationSourceType::AUTH_AZURE->value);
$user->updateSessionId(true);
$user->saveToSession();
$user->setTokenData([...]);
$user->setSuccess(true);
```

Both callbacks are actively maintained code — the Entra ID path got its
account-status check recently, the Keycloak path got subject binding — so this is a
missing check, not an abandoned feature.

## Proof of concept

Everything below was run against the project's own published artifact: the container
image `ghcr.io/thorsten/phpmyfaq:nightly-2026-09-26` (headless install, MariaDB 11,
PHP 8.4.26), i.e. `main` at the date of the report. The environment:

- lab account `victim`: local password, `twofactor_enabled = 1`, TOTP secret set,
  `keycloak_sub` linked;
- a local mock OpenID provider answering exactly the endpoints phpMyFAQ itself
  requests (`/.well-known/openid-configuration`,
  `/protocol/openid-connect/auth|certs|token|userinfo`) with a properly RS256-signed
  `id_token`;
- no application code was modified.

One run, controls first, then the case:

```
CONTROL 1 - API password login, the SAME 2FA account   -> {"loggedin":false}  (second factor enforced)
CONTROL 2 - API password login, an account WITHOUT 2FA -> {"loggedin":true}   (mechanism works)

CASE      - Keycloak SSO login, the SAME 2FA account:
  1) GET /auth/keycloak/authorize -> 302 to the provider (state, nonce, PKCE)
  2) provider consent            -> 302 back with code + state
  3) GET /auth/keycloak/callback -> 302 to the default page
     home page with the returned session: "Logout" + ./user/ucp ./user/bookmarks ./user/chat
     faquser.last_login updated, auth_source=keycloak, access token stored
     token step performed? 0 references to the token page
```

The session the callback wrote contains the 2FA-protected account and the accepted
`id_token`, and contains no `2fa_pending_user_id` — the token step was never armed:

```
CURRENT_USER";i:2                   <- the 2FA-protected account, granted a session
pmf-oidc-id-assertion";s:817        <- the provider id_token was accepted and stored
2fa_pending_user_id occurrences: 0  <- the token step was never armed
```

A request with an unknown session id renders the guest navigation (`>Login<`), so the
logged-in reading is not a false positive. The provider log for the case contains
only discovery → authorize → token → certs → userinfo: nothing in the flow involves
TOTP.

## Impact

For every SSO-provisioned account with TOTP enabled, the second factor is
decorative. Anyone holding a valid Keycloak / Entra ID identity for that account — a
stolen IdP credential, a replayed IdP session, a compromised IdP account — receives a
full phpMyFAQ session: their own FAQ entries, bookmarks and profile, and
**administrator access when the account is an administrator** (2FA is mandatory-policy
material for admins in most deployments). The product's own `twofactor_enabled`
setting is never consulted on this path, so no amount of correct 2FA configuration by
the administrator changes the outcome.

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8, High**. The precondition —
a valid SSO identity for the target — is exactly the case two-factor is deployed to
defend against; on this path it adds nothing.

## The fix

Fixed in [`ebca8fd`](https://github.com/thorsten/phpMyFAQ/commit/ebca8fd141f7735830ac0c6043158cb5240d83b0)
("fix(auth): require the second factor on Keycloak and Entra ID logins", 2026-09-27),
which mirrors the password/passkey flow in both callbacks before the session is
granted:

```php
// A validated Keycloak identity counts as the first factor only. If the account has
// TOTP two-factor enabled, defer to the token step instead of granting the session,
// mirroring the password and passkey login flows, so single sign-on cannot bypass
// two-factor authentication.
if ((int) $user->getUserData('twofactor_enabled') === 1) {
    if ($user->isTwoFactorLockedOut()) {
        return $redirect;   // locked out -> no session, no fresh failure budget
    }
    $this->session->set('2fa_pending_user_id', $user->getUserId());
    $this->session->set('2fa_pending_remember_me', false);
    return new RedirectResponse(
        $this->configuration->getDefaultUrl() . 'token?user-id=' . $user->getUserId(),
    );
}
```

The fix was re-verified live on the same image, with exactly the commit's two
controller files overlaid (hash-verified byte-identical to the upstream blobs; the
image's unpatched files match the commit's parent, so the only delta under test was
this commit):

- **Keycloak, 2FA-enabled account:** the callback now stops at the token step — `302`
  to `/token?user-id=2`, the session carries `2fa_pending_user_id` with **no**
  `CURRENT_USER`, and a correct TOTP then completes the login normally (full session,
  `auth_source=keycloak`, `last_login` updated).
- **Accounts without 2FA:** SSO still completes directly — the new branch only
  applies when the flag is set.
- **Password path:** unchanged — the 2FA account is still refused, the non-2FA
  account still logs in.
- **Failure budget:** a valid SSO identity does not reset the counter, and a
  locked-out account gets no session — matching the comments in the code.

The Entra ID path carries the equivalent check; it was reviewed in the diff but
could not be live-tested against real Microsoft endpoints, so that one is
code-level only.

Shipped in the [`4.2.0-beta`](https://github.com/thorsten/phpMyFAQ/releases) tag
(2026-10-03) and in the development nightlies from 2026-09-28 onward. No stable
4.1.x release contains these controllers — the SSO feature only exists in the 4.2
line — so anyone running 4.2 development code should move to `4.2.0-beta` or a
post-fix development nightly.

## Timeline

- 2026-09-26 — Reported to the maintainer via GitHub private vulnerability reporting (GHSA-8fvf-747v-qjr6).
- 2026-09-27 — Fix merged (`ebca8fd`); the patched controllers re-verified live against the original PoC.
- 2026-10-03 — Advisory published; fix included in the `4.2.0-beta` tag.

## Disclosure

Public advisory:
[GHSA-8fvf-747v-qjr6](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-8fvf-747v-qjr6)
(no CVE assigned). Affects `phpmyfaq/phpmyfaq` `>= 4.2.0-alpha` and the project's
nightly images; fixed in
[`ebca8fd`](https://github.com/thorsten/phpMyFAQ/commit/ebca8fd141f7735830ac0c6043158cb5240d83b0),
shipped in the `4.2.0-beta` tag and in development nightlies from 2026-09-28 onward.

Related advisories for the same class in the same product:
[GHSA-8gpw-xvpf-hvx5](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-8gpw-xvpf-hvx5)
(CVE-2026-56737) and
[GHSA-hvj7-4fmg-53cr](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-hvj7-4fmg-53cr).
