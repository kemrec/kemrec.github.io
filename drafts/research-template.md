<!--
Template for a new research post (n-day notes). Research posts cover bugs that
were ALREADY fixed and public when you looked at them: patch-diff studies,
boundary checks, fix-completeness reviews. If the bug is still unfixed, or a
disclosure is in progress, it does NOT go here; it goes through coordinated
disclosure first.

1. Copy this file to ../_research/<slug>.md
2. Fill in the front matter and body
3. `date:` is the posting date (there is no advisory to match)
4. Delete this comment block
-->
---
title: "<Project>: <what the bug does>"
date: YYYY-MM-DD
target: "<project/vendor name>"
severity: Critical|High|Medium|Low
fixed: "X.Y.Z+"                    # first release carrying the fix
fix: "PR #NNNNN"                   # or commit sha
fix_url: "https://..."             # link to the public fix
identifier: ""                     # optional: CVE/GHSA, if one exists
advisory_url: ""                   # optional: public advisory/CVE record
summary: "<one-sentence summary of the finding>"
---

## Summary

What the bug is, in plain terms, and why it matters.

## Background

Minimal context needed to follow the bug.

## The bug

The vulnerable code path, the root cause, and the exact trust decision that
failed.

## Proof of concept

Steps and observed output on a vulnerable build vs a fixed build.

## Impact

What an attacker gains and under what preconditions.

## The fix

What the fix changes, and any completeness checks done on it.

## Timeline

- YYYY-MM-DD - fix merged
- YYYY-MM-DD - fixed release
- YYYY-MM-DD - verification / post

## Disclosure

State clearly that this is n-day research: fix already public, no report
filed by you. If a CVE exists, credit the original finder and note that the
post only adds the technical detail the advisory withheld.
