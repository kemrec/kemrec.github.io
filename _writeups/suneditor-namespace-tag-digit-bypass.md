---
title: "SunEditor: a digit in a namespaced tag skips attribute cleaning"
date: 2026-11-01
target: "JiHong88/suneditor"
severity: "Medium"
identifier: "GHSA-6pm3-2q9w-2926"
advisory_url: "https://github.com/JiHong88/suneditor/security/advisories/GHSA-6pm3-2q9w-2926"
summary: "Three regexes disagree about what a namespaced tag looks like. One rejects `a:b`, one whitelists anything starting with `a`, and one skips attribute filtering for `a:1b`. The last one wins, so an onclick handler survives clean(). Fixed in 3.4.0."
---

## Summary

The fix for CVE-2026-59167 added `[a-z]+:[a-z]+` to SunEditor's disallowed tag list to block namespaced elements such as `<a:b>`. Three separate checks decide the fate of a tag, and all three use a different idea of what a namespaced tag is:

- `EXTRA_TAG_MAP` uses `[a-z]+:[a-z]+`, letters only.
- The element whitelist uses word boundaries, so the `a` alternative in `<a:...>` matches and the tag is treated as an allowed anchor.
- `_RE_XML_NS_TAG` uses `[a-z0-9]+:[a-z0-9]+`, letters and digits, and its match makes `#CleanElements` return early, skipping attribute filtering entirely.

`<a:1b onclick="...">` slips past the first, is spared by the second, and hits the early return in the third. The handler stays. The element renders, the user clicks it, and the script runs.

This is [GHSA-6pm3-2q9w-2926](https://github.com/JiHong88/suneditor/security/advisories/GHSA-6pm3-2q9w-2926), rated Medium and fixed in 3.4.0. The advisory credits 1diot9, kemrec and manus-use. The runs below are mine, against the npm packages.

## Background

SunEditor's `clean()` is a string-level sanitizer with a DOM step. It deletes disallowed tags by regex, deletes tags that are not on the whitelist, then walks the remaining elements to strip unsafe attributes, with a special case that leaves XML-namespaced tags alone so that things like `<svg:rect>` survive.

That special case is the dangerous one. `#CleanElements` starts with:

```javascript
if (_RE_XML_NS_TAG.test(m)) return m;
```

with `const _RE_XML_NS_TAG = /^<[a-z0-9]+:[a-z0-9]+/i;`. A tag that matches is returned untouched, so the `on*` handler strip below it never runs.

## The vulnerability

Take `<a:1b onclick="alert(document.cookie)">click</a:1b>` and follow it through the three checks.

**Check one, the disallowed list.** `src/core/schema/options.js` line 49:

```javascript
EXTRA_TAG_MAP: { script: false, style: false, meta: false, link: false, '[a-z]+:[a-z]+': false },
```

The pattern requires a letter after the colon. `1b` starts with a digit, so the tag is not deleted.

**Check two, the whitelist.** `createElementWhitelist` in `src/helper/converter.js` builds a negative lookahead out of the allowed tag names:

```javascript
new RegExp(`<\\/?\\b(?!\\b${list.replace(/\|/g, '\\b|\\b')}\\b)[^>]*>`, 'gi')
```

The allowed list contains `a`, so the lookahead tries `\ba\b`. In `a:1b`, the boundary between `a` and `:` is a word boundary, so the alternative matches, the lookahead fails, and the whole tag is left in place.

**Check three, the attribute pass.** `#CleanElements` tests the tag against `_RE_XML_NS_TAG`, which does accept digits after the colon. It matches, the function returns immediately, and the `on*` strip is skipped.

Three checks, three answers, and the permissive one is last.

A second payload shows the same gap from a different direction. `<b:1c onmouseover="...">` is spared by the same three checks, and then the text-style converter rewrites it into `<strong :1c="" src="/x" onmouseover="...">`. The handler migrates onto an ordinary `<strong>`, which no longer looks like a namespaced tag at all but keeps the attribute.

## Proof of concept

```html
<p><a:1b src="/x" onclick="alert(document.cookie)">click</a:1b></p>
<p><b:1c src="/x" onmouseover="alert(document.domain)">hover</b:1c></p>
```

```javascript
editor.$.html.set('<p><a:1b src="/x" onclick="window.__xss=(window.__xss||0)+1">click</a:1b></p>');
```

The same content works through paste and through the code view, because all three paths call the same `clean()`.

## Observed behaviour

Harness: official npm tarballs served from localhost, headless Chrome 154.0.8037.57, default editor options. Each payload's handler writes a unique marker into the host window, which the harness reads back after it dispatches the interaction.

On `suneditor@3.3.3`:

```
payload=ns-alnum-digit path=set
  HIT: {'doc': 'main', 'tag': 'a:1b', 'attrs': ['onclick=window.__xss=(window.__xss||0)+1', 'TAG=A:1B']}
  FLAGS: [1]
  CONTENT: <p><a:1b src="/x" onclick="window.__xss=(window.__xss||0)+1">click</a:1b></p>

payload=ns-branch-digit path=set
  HIT: {'doc': 'main', 'tag': 'strong', 'attrs': ['onmouseover=window.__xss=(window.__xss||0)+2']}
  FLAGS: [2]
  CONTENT: <p><strong :1c="" src="/x" onmouseover="window.__xss=(window.__xss||0)+2">hover</strong></p>
```

The negative controls in the same run show the boundaries of the bug. `<a:b onclick=...>` with letters only is deleted, output `""`. `<a1:b onclick=...>` is deleted with the text kept. `<img src=x onerror=...>` keeps the element and loses the handler. The digit after the colon is the only thing separating the working payload from the blocked ones.

On `suneditor@3.4.1`:

```
payload=ns-alnum-digit path=set
  HIT: {'doc': 'main', 'tag': 'a:1b', 'attrs': ['TAG=A:1B']}
  FLAGS: []
  CONTENT: <p><a:1b src="/x">click</a:1b></p>
```

The tag still survives as an unknown element, but the handler is gone and nothing fires. The `b:1c` variant now comes back as `<strong :1c="" src="/x">` with no `onmouseover`.

## Impact

Stored XSS in any application that renders editor content saved by another user. The payload needs one click or hover on the planted element, which is why the advisory rates it Medium rather than High, but the element can be dressed as ordinary content, a link, a file attachment label, or a call to action.

Once it runs, the script has the origin: cookies without `HttpOnly`, tokens in storage, authenticated fetch calls, the content of the page, and anything the application exposes to its own JavaScript.

## Fix

SunEditor 3.4.0 removes the disagreement. The namespace exception no longer returns before attribute filtering; tag handling was consolidated so that all three checks agree on the same character class, and the `on*` strip runs for whatever survives. If you are pinned to 3.3.x, run a real HTML sanitizer on the server side and treat `clean()` as a convenience, not a boundary.

## Timeline

- **2026-09-27**: reported privately as GHSA-692m-4688-45wp, together with the `srcdoc` placeholder bypass.
- **2026-10-20**: that private advisory closed as the maintainer split the report into separate advisories.
- **2026-10-23**: GHSA-6pm3-2q9w-2926 published, credit to 1diot9, kemrec and manus-use.
- **2026-11-01**: 3.4.0 and 3.4.1 verified against the original harness, handlers stripped on both payload variants.
