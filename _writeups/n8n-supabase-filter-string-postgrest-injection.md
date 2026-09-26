---
title: "n8n's Supabase Node Filter Injection"
date: 2026-09-16
target: "n8n-io/n8n (Supabase node)"
severity: High
identifier: "GHSA-xrqg-3xcp-h45x"
advisory_url: "https://github.com/n8n-io/n8n/security/advisories/GHSA-xrqg-3xcp-h45x"
summary: "The Supabase node's 'Filters (String)' mode builds a PostgREST query with zero escaping, letting untrusted input widen a Get/Update/Delete beyond the row it was meant to target — a sibling of a filter-injection bug n8n had already fixed in a different mode."
---

## Summary

n8n's Supabase node offers two ways to filter which rows a `Get Many`,
`Update`, or `Delete` operation touches: a structured "Build Manually"
mode, and a raw "Filters (String)" mode where you write the PostgREST
filter expression yourself. n8n had already fixed a filter-injection bug
in "Build Manually." "Filters (String)" has the identical class of bug,
completely unescaped, and no safe alternative exists for that mode at all.

## Background

PostgREST — the query layer Supabase's REST API is built on — parses
filter expressions like `or=(email.eq.alice@example.com)` from the query
string. Certain characters (`,&=():@`) are structurally meaningful to that
parser, so any value inserted into a filter expression needs those
characters escaped or the expression's boundaries can be redrawn by
whoever controls the value.

"Filters (String)" mode takes exactly that risk and does nothing about it:

```typescript
if (filterType === 'string') {
    const filterString = this.getNodeParameter('filterString', i) as string;
    endpoint = `${endpoint}?${encodeURI(filterString)}`;
}
```

`filterString` is a normal n8n expression field, so a workflow commonly
builds it from external input — a webhook body, for instance — to
parameterize a lookup like:

{% raw %}
```
or=(email.eq.{{ $json.body.email }})
```
{% endraw %}

`encodeURI()` deliberately leaves PostgREST's reserved characters
unescaped; it isn't a security boundary here, it's meant for building
valid URLs out of already-trusted strings. There's no escaping function
anywhere in this path, and — unlike "Build Manually," which has a
parameterized, safe alternative — there's no safe equivalent for this mode
at all.

## The vulnerability

Feed the filter a value containing a comma, and the comma closes the
intended condition and opens a new, attacker-chosen one. Given a workflow
with:

{% raw %}
```
Filters (String) = or=(email.eq.{{ $json.body.email }})
```
{% endraw %}

a normal request `{"email": "alice@example.com"}` returns exactly Alice's
row, as intended. A request with:

```json
{"email": "nobody@x.com,id.gt.0"}
```

produces the filter `or=(email.eq.nobody@x.com,id.gt.0)` — the comma ends
the `email.eq.` condition and adds `id.gt.0`, an always-true condition on
every row's primary key. The query now matches every row in the table
instead of the zero rows a nonexistent email should have matched.

The same unescaped pattern exists identically in all three operations that
offer this mode — `Get Many`, `Update`, and `Delete` — so the same
technique that widens a read to every row also widens a delete to every
row: a single crafted request against a `Delete` operation using this
mode can empty the entire table in one call.

## Impact

Where a workflow builds a "Filters (String)" value from untrusted input,
whoever controls that input can widen the operation's scope from "the row
they were supposed to match" to "every row in the table" — reading rows
they shouldn't see, or updating or deleting rows they shouldn't be able to
touch at all.

## Fix

Fixed in **1.123.80**, **2.39.6**, and **2.40.1** — upgrade to one of
these versions or later.

If you can't upgrade immediately: audit workflows using "Filters
(String)" for any that build the filter from untrusted data, and switch
those to "Build Manually" instead, which uses parameterized filter
construction and isn't affected. Restricting access to whatever trigger
feeds the untrusted data (a webhook, for instance) is a partial mitigation
at best.

## Timeline

- Reported to `security@n8n.io`, n8n's vulnerability disclosure program.
- Passed initial triage; confirmed still present in the then-latest
  release before a status follow-up.
- **2026-09-16** — Advisory published as `GHSA-xrqg-3xcp-h45x`, High (CVSS
  4.0 `AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H` = 7.1).

## Disclosure

Full advisory: [GHSA-xrqg-3xcp-h45x](https://github.com/n8n-io/n8n/security/advisories/GHSA-xrqg-3xcp-h45x).
