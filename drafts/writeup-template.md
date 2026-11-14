<!--
Template for a new writeup. Before publishing, confirm the advisory below is
ACTUALLY publicly disclosed (check the vendor's advisory page / CVE record /
GHSA directly, e.g. `gh api repos/<owner>/<repo>/security-advisories/<GHSA-id>`
and check its `credits` field too, not just `state`) — a finding being
"sent" or "accepted" is not the same as "published." Once confirmed:

1. Copy this file to ../_writeups/<slug>.md
2. Fill in the front matter and body
3. Set `date:` to the advisory's own `published_at` date (not today's date,
   so posts are dated to match when the advisory went public, meaning the
   blog reads as "this post went up the day the finding became public")
4. Title: keep it impact-forward and scannable, one clean header line. Lead
   with what the bug DOES or its consequence, not the mechanism, the AST node,
   or a raw function name. No run-on sentence that crams mechanism plus impact.
   The common house pattern is "Project: short impact phrase"; a punchy
   standalone line works too. No em or en dashes. If you retitle a post that
   is already live, change only the `title:` field and keep the slug/filename
   so the URL does not break. Good models: "A Spoofed Host Header Escalates Any
   Account to Administrator", "The Migration SSRF Guard That Did Nothing".
5. Delete this comment block
-->
---
title: "<Impact-forward header: what the bug does, not the mechanism. See note 4.>"
date: YYYY-MM-DD   # = advisory published_at date, NOT the day this post is written
target: "<project/vendor name>"
severity: Critical|High|Medium|Low
identifier: "CVE-YYYY-NNNNN"          # or GHSA-xxxx-xxxx-xxxx
advisory_url: "https://..."           # link to the PUBLIC advisory/CVE record
summary: "<one-sentence summary of the finding>"
---

## Summary

What the bug is, in plain terms, and why it matters.

## Background

Minimal context needed to follow the bug — what component, what it's for.

## The vulnerability

Technical detail: the vulnerable code path, the root cause, why the fix
(if any) works the way it does.

## Impact

Concrete exploitation scenario — what an attacker gains and under what
preconditions.

## Timeline

- YYYY-MM-DD — Reported to vendor
- YYYY-MM-DD — Vendor acknowledged / fixed
- YYYY-MM-DD — Advisory published

## Disclosure

Link to the public advisory / CVE record this writeup is based on.
