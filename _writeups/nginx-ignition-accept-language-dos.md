---
title: "Accept-Language CPU Exhaustion: The Gap Left by nginx-ignition's Previous DoS Fix"
date: 2026-09-24
target: "lucasdillmann/nginx-ignition"
severity: High
identifier: "GHSA-969c-hr69-6q97"
advisory_url: "https://github.com/lucasdillmann/nginx-ignition/security/advisories/GHSA-969c-hr69-6q97"
summary: "A previous fix for an Accept-Language DoS only bounded separator characters, not the number of language tags — leaving an unauthenticated 51x CPU amplification attack open."
---

## Summary

nginx-ignition ships a small i18n middleware that reads the
`Accept-Language` header on every request and picks the first language it
supports. An earlier advisory (GHSA-jr34-h97m-9hpx) showed that header
could be abused for a quadratic-cost CPU attack, and the maintainer added a
guard against it. That guard counts the wrong thing: it bounds the number
of `-`/`_` characters in the header, not the number of comma-separated
language tags or the header's total length. A header built from many
short, valid-but-unsupported tags sails straight past it and still costs
50x more CPU than the same number of bytes the server doesn't parse.

## Background

The middleware runs on every single request, unauthenticated, before
routing even happens:

```go
const maximumLanguageTags = 10

func i18nMiddleware(commands i18n.Commands) gin.HandlerFunc {
	return func(ginCtx *gin.Context) {
		lang := commands.DefaultLanguage()

		langHeader := ginCtx.GetHeader("Accept-Language")
		if strings.Count(langHeader, "-")+strings.Count(langHeader, "_") > maximumLanguageTags {
			langHeader = ""
		}

		tags, _, err := language.ParseAcceptLanguage(langHeader)
		if err == nil && len(tags) > 0 {
			for _, tag := range tags {
				if commands.Supports(tag) {
					lang = tag
					break
				}
			}
		}
```

The `maximumLanguageTags` check was added specifically to close the prior
advisory's exploit path — it assumes counting separator characters is a
good enough proxy for how expensive the header will be to process.

## The vulnerability

It isn't, for two reasons:

1. `golang.org/x/text`'s `ParseAcceptLanguage` splits the input on `,`
   *before* it ever looks at hyphens or underscores. A header made of
   thousands of comma-separated two-letter tags (`aa,aa,aa,...`) can have
   a hyphen/underscore count of exactly zero and still contain hundreds of
   thousands of tags.
2. When a tag parses successfully but doesn't match any language the
   server actually supports, the middleware's loop never breaks early — it
   calls `commands.Supports(tag)` for *every* tag, and each of those calls
   scans all 11 supported-language dictionaries.

So a 1 MB header of `aa,` repeated has a separator count of zero (no
hyphens, no underscores — the guard never fires), parses as ~333,000
valid-but-unsupported tags, and makes the middleware do a full
11-dictionary scan for every single one of them before giving up and
falling back to the default language.

Measured against the official `2.45.1` release binary, that header costs
**306 ms of server CPU per request** — versus **6 ms** for the same 1 MB
sent in a header nobody parses. A single connection sustaining that
traffic at 32.5 Mbit/s keeps **1.28 CPU cores** busy on the server the
entire time.

## Reachable path

No credentials, no session, no valid application state — a single HTTP
request to any path (the middleware is global, so the target endpoint
doesn't even need to exist):

```
GET /api/i18n HTTP/1.1
Host: target
Accept-Language: aa,aa,aa,... (1 MB)
```

## Impact

Unauthenticated, bandwidth-bounded CPU exhaustion against the
nginx-ignition API listener. One attacker connection uploading roughly
32.5 Mbit/s of `Accept-Language` header keeps more than one CPU core busy
on the server; two such connections saturate a two-vCPU host, three or
four saturate a four-core one — and since nginx-ignition typically shares
the box with the nginx instance it manages, that instance's availability
degrades along with it. Confidentiality and integrity are unaffected —
this is purely an availability issue.

## Suggested fix

Bound the two quantities the existing guard leaves open, before the header
ever reaches the parser:

```go
const (
	maximumLanguageTags = 10   // existing: separator cap
	maximumHeaderBytes  = 128  // new: real Accept-Language values are tiny
)

langHeader := ginCtx.GetHeader("Accept-Language")
if len(langHeader) > maximumHeaderBytes ||
	strings.Count(langHeader, "-")+strings.Count(langHeader, "_") > maximumLanguageTags ||
	strings.Count(langHeader, ",") > maximumLanguageTags {
	langHeader = ""
}
```

The middleware only ever needs the *first* tag it supports, so anything
past a handful of bytes is already more than a legitimate client would
ever send.

## Timeline

- **2026-09-23** — Reported via GitHub's private security-advisory
  reporting.
- **2026-09-23/24** — Fixed same day, shipped in **2.45.2**.
- **2026-09-24** — Advisory published as `GHSA-969c-hr69-6q97`, High (CVSS
  3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = 7.5).

## Disclosure

Full advisory: [GHSA-969c-hr69-6q97](https://github.com/lucasdillmann/nginx-ignition/security/advisories/GHSA-969c-hr69-6q97).
