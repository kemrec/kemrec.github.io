---
title: "Formie's Guest-Only Submission Gate Let Any Logged-In Member Overwrite Another User's Submission"
date: 2026-09-30
target: "verbb/formie"
severity: Medium
identifier: "GHSA-p696-447f-9258"
advisory_url: "https://github.com/verbb/formie/security/advisories/GHSA-p696-447f-9258"
summary: "Formie 3.1.31 fixed an unauthenticated submission-overwrite bug (GHSA-584p-f93j-wpgc) with a context check that only rejects guests. Through 3.1.43, any authenticated member holding no Control-Panel permission could still POST an arbitrary submissionId to the CP-classified submit route, overwrite and complete someone else's in-progress submission, and — with collectUser enabled — re-own the record to themselves."
---

## Summary

Formie is the form-builder plugin for Craft CMS. Its `submit` action accepts a `submissionId` parameter that lets a visitor resume an *incomplete* submission. An earlier advisory, [GHSA-584p-f93j-wpgc](https://github.com/verbb/formie/security/advisories/GHSA-584p-f93j-wpgc) ("Unauthenticated users can overwrite incomplete submissions via submit action"), reported that anyone could supply another visitor's `submissionId` and overwrite their in-progress submission. It was fixed in 3.1.31 / 2.2.23.

That fix is context-based, and it only rejects **guests**. Through the latest release at the time of writing, **3.1.43**, an authenticated member who holds *no* Control-Panel permission at all could still reach the same code path by sending the request to the plugin's Control-Panel-classified route (`/admin/actions/formie/submissions/submit`). On that route the guest rejection does not apply and the site-request-only ownership gate never runs, so the member overwrites — and, because the form has `collectUser` enabled, re-owns — another user's submission. This is [GHSA-p696-447f-9258](https://github.com/verbb/formie/security/advisories/GHSA-p696-447f-9258) (Medium, CVSS 6.5, CWE-639 / CWE-863).

## Background

Formie stores each in-progress multi-page submission with a `submissionId`, and the `submit` action lets a client resume one by sending that id back. Craft routes an action request in one of two "contexts": a **site request** (the normal front-end form post) or a **Control-Panel request**, selected by the URL prefix — anything under the configured CP trigger (`admin` by default) is a CP request, everything else is a site request. The distinction matters because a lot of Craft/Formie authorization logic branches on `Craft::$app->getRequest()->getIsSiteRequest()`.

The 3.1.31 fix for the anonymous-overwrite bug lives in `src/controllers/SubmissionsController.php`. It leans entirely on that context distinction, which is where the gap is.

## The vulnerability

Three facts about `SubmissionsController.php` on 3.1.43 combine into the bypass:

1. **The CP-context guard rejects only anonymous callers.** On a CP-classified request, a guest is turned away with `ForbiddenHttpException('Anonymous submissions are only permitted through the site request.')`. An authenticated member — even one with no CP access and no admin flag — passes this check.

2. **`_populateSubmission()` trusts the caller's `submissionId`.** It loads the submission named by the request without checking that the current user owns it, and, when the form has `collectUser` enabled, calls `$submission->setUser($user)` with the *current* user. The caller therefore becomes the owner of whatever submission they named.

3. **The ownership/session gate is scoped to site requests.** The validation that would normally force an owner/session match runs on the site-request path only. For a CP-classified request it is skipped, so the protection added in 3.1.31 simply isn't in effect on that route.

Put together: a logged-in member sends the resume request to the CP route instead of the site route, clears the only check that applies there (not being a guest), and lands in `_populateSubmission()` with an attacker-chosen `submissionId` and no ownership check.

The CP context is also reachable through a percent-encoded prefix — `/%61dmin/actions/formie/submissions/submit` (`%61` = `a`) triggers the same CP classification, so a naive string match on `admin` in front of the route does not help.

## Proof of concept

Verified live against product code, unmodified: Craft CMS 5.11.3 (Pro), verbb/formie **3.1.43**, PHP 8.2.26, MariaDB 11. Both actors, `victim` and `attacker`, are ordinary active members confirmed in-process to have `can('accessCp') === false` and `admin === false`. Every request carries a valid CSRF token from its own session.

| # | Actor | Route | HTTP | Effect |
|---|-------|-------|------|--------|
| A | victim (owner) | `POST /actions/formie/submissions/submit` | 302 | owner resumes their own submission — the gate is not broken in general |
| B | attacker (member) | same **site** route, victim's id | **403** | *"User is not permitted to perform this action"* — control; the site-route guard works |
| C | attacker | `POST /admin/actions/formie/submissions/submit`, victim's id | **302** | **bypass** — victim's submission overwritten |
| D | attacker | `POST /%61dmin/actions/formie/submissions/submit`, victim's id | **302** | **bypass** (percent-encoded CP trigger) — overwritten *and completed* |
| E | anonymous guest | `POST /admin/actions/...` | **403** | *"Anonymous submissions are only permitted through the site request."* — the only case the guard actually covers |

The observable write from request C, read straight back out of the database:

```
before:  userId=null   isIncomplete=true    values={"yourName":"VICTIM-NAME", ...}
after:   userId=4       isIncomplete=true    values={"yourName":"ATTACKER-CP", ...}
```

`userId` is the submission's owner. The CP-context POST rewrote the victim's answers and re-owned the record to the attacker's user id (id 4). Request D additionally flips `isIncomplete` to false — completing the submission — after which the victim can no longer resume it at all: a follow-up owner POST answers `400 No submission exists with the ID <n>`, because a completed submission is no longer resumable.

## Impact

Any authenticated user of the site — a self-registered member with the lowest possible privilege, no Control-Panel access, no admin flag — can overwrite the in-progress submission of any other user whose `submissionId` they can obtain or guess, corrupting its contents, completing it so the rightful owner is locked out, and (when `collectUser` is on) taking ownership of the record. It is an authorization/IDOR failure: CWE-639 (authorization bypass through a user-controlled key) and CWE-863 (incorrect authorization), scored `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = 6.5.

The root shape is worth calling out for anyone reviewing similar fixes: the 3.1.31 patch treated "is this a site request?" as a proxy for "is this an ordinary front-end visitor?" A Control-Panel request from a logged-in member with zero CP rights breaks that assumption — the context check and the privilege check are not the same thing, and gating on the former leaves the latter unenforced.

## Timeline

- 2026-09-24 — Reported to the maintainers via GitHub private vulnerability report
- 2026-09-30 — Advisory GHSA-p696-447f-9258 published (Medium, 6.5); affects `verbb/formie <= 3.1.43`

## Disclosure

Based entirely on the public advisory: [GHSA-p696-447f-9258](https://github.com/verbb/formie/security/advisories/GHSA-p696-447f-9258).
