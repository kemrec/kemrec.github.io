---
title: "SunEditor: srcdoc survives the iframe placeholder rebuild in clean()"
date: 2026-11-01
target: "JiHong88/suneditor"
severity: High
identifier: "GHSA-q867-q2hw-f8gp"
advisory_url: "https://github.com/JiHong88/suneditor/security/advisories/GHSA-q867-q2hw-f8gp"
summary: "SunEditor rebuilds iframes from data-se-iframe-holder placeholders and copies every attribute except on* handlers and unsafe src values. srcdoc is copied as-is, so a crafted placeholder produces a same-origin iframe whose inline script runs on insert. Fixed in 3.4.0."
---

## Summary

SunEditor's sanitizer has a special path for iframes. When content contains a `<div data-se-iframe-holder="1" data-se-iframe-holder-attrs="{...}">` placeholder, `clean()` parses the JSON attribute document and rebuilds a real `<iframe>` from it. The rebuild filters two things: attributes whose name starts with `on`, and `src` values that fail an `_isSafeURL` protocol check. Every other key is passed straight to `setAttribute`.

`srcdoc` is one of those keys. A placeholder carrying `{"srcdoc":"<svg/onload=...>"}` becomes a live `<iframe srcdoc="<svg/onload=...>">`. A `srcdoc` document inherits the embedding page's origin, so the handler runs with full access to the host application: cookies, tokens in `localStorage`, and any action the page can take. No click is needed.

This is [GHSA-q867-q2hw-f8gp](https://github.com/JiHong88/suneditor/security/advisories/GHSA-q867-q2hw-f8gp), rated High (CVSS 3.1 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`, 8.1) and fixed in SunEditor 3.4.0. The advisory credits EclipsSec and kemrec as reporters; the analysis below is from my own harness runs against the npm packages.

## Background

The placeholder format is not an attack-only construct. It is how SunEditor itself round-trips iframes through copy and paste. `src/helper/clipboard.js` writes the `data-se-iframe-holder` / `data-se-iframe-holder-attrs` pair when the user copies an iframe, and `clean()` reads it back on paste to rebuild the element. Because the format is attacker-copyable text, anything the rebuild trusts is attacker-controlled.

`data-se-*` attributes are also on a blanket pass-through list, `REQUIRED_DATA_ATTRS`, which exists so the editor's own bookkeeping attributes survive sanitization. That is the first half of the bug: the attrs payload is never treated as untrusted input.

## The vulnerability

The rebuild loop in `src/core/logic/dom/html.js` (lines 335 to 349 in 3.3.3) does this:

```javascript
const attrs = JSON.parse(holder.getAttribute('data-se-iframe-holder-attrs'));
for (const [key, value] of Object.entries(attrs)) {
  if (/^on/i.test(key)) continue;
  if (key === 'src' && !_isSafeURL(String(value))) continue;
  iframe.setAttribute(key, value);
}
```

Two guards, and both are narrow:

- `/^on/i` catches `onload`, `onerror`, `onclick` and the rest of the classic handler family.
- The `src` check blocks `javascript:` and other unsafe schemes.

`srcdoc` matches neither. It is not an event handler and it is not `src`, so it reaches `setAttribute` unmodified. The value can be entity-encoded, `&lt;script&gt;...&lt;/script&gt;`, because the string-level `<script>` scrub runs before the DOM parse and before the entity decode. By the time the iframe is rebuilt, the attribute holds a real HTML document.

The iframe is then serialized back into the editor content and inserted with `skipCleaning: true`, so nothing re-examines it. The browser parses the `srcdoc` document in the host page's origin and runs its scripts.

## Proof of concept

Placeholder form, pasted or inserted:

```html
<p>before</p><div data-se-iframe-holder="1"
  data-se-iframe-holder-attrs='{"srcdoc":"&lt;script&gt;alert(document.domain)&lt;/script&gt;"}'>x</div>
```

API form:

```javascript
editor.$.html.set('<p>before</p><div data-se-iframe-holder="1" data-se-iframe-holder-attrs=\'{"srcdoc":"&lt;script&gt;window.__xss=(window.__xss||0)+888&lt;/script&gt;"}\'>x</div>');
```

Three entry paths reach the same rebuild: `$.html.set`, `$.html.insert`, and paste. The last one needs the user to paste, which is why the advisory carries `UI:R`; the two API paths need only that the host application loads user content, which is the normal use of an editor.

## Observed behaviour

Harness: the official npm tarballs, served from localhost, driven in headless Chrome 154.0.8037.57. The harness creates the editor with default options, loads each payload through `editor.$.html.set()`, then scans the live DOM and reads back a marker that the injected code writes.

On `suneditor@3.3.3`:

```
payload=srcdoc-entity-script path=set
  HIT: {'doc': 'main', 'tag': 'iframe', 'attrs': ['srcdoc=<script>window.__xss=(window.__xss||0)+888</script>']}
  FLAGS: [888]
  CONTENT: <p>before</p><p><iframe srcdoc="&lt;script&gt;window.__xss=(window.__xss||0)+888&lt;/script&gt;"></iframe></p>
```

`FLAGS: [888]` means the inline script ran. The harness never dispatches a click or hover at an iframe, so this executed on insertion.

The same run's negative control, a placeholder whose `src` is `javascript:`, produced `<iframe></iframe>` and no marker, which confirms the `src` guard works and isolates the gap to the attribute that has no guard.

On `suneditor@3.4.1`, the current npm `latest`:

```
payload=srcdoc-entity-script path=set
  HIT: {'doc': 'main', 'tag': 'iframe', 'attrs': []}
  FLAGS: []
  CONTENT: <p>before</p><p><iframe></iframe></p>
```

The iframe survives as an empty element, `srcdoc` is gone, and no marker fires. The other srcdoc variants in the same battery, raw `<script>` inside the JSON, `<img onerror>` with and without entity encoding, all come back with empty attribute lists and no flags.

## Impact

`srcdoc` inherits the embedding document's origin unless the iframe also carries a `sandbox` attribute without `allow-same-origin`. SunEditor does not add one. So the injected document is not a separate, restricted frame: it is script running as the host application.

That is stored XSS in the ordinary case. A content application saves editor output, another user opens the document, and the payload runs when the editor loads the content back. What the script can do is whatever the page can do: read cookies that are not `HttpOnly`, read tokens from storage, send authenticated requests, rewrite what the victim sees, and forward the content elsewhere.

The `UI:R` in the vector comes from the paste entry path. Hosts that call `$.html.set` or `$.html.insert` with untrusted content, which includes most server-rendered previews and import flows, do not need any interaction at all.

## Fix

SunEditor 3.4.0 closes it. The rebuilt iframe is now built from an explicit attribute allowlist rather than "everything except `on*` and bad `src`", so `srcdoc`, `sandbox`, `name` and `id` no longer ride along from the placeholder JSON. The advisory's suggested minimal diff was to add `srcdoc` to the reject list, but the allowlist is the durable shape: any future attribute that reaches a frame element is a decision someone has to make on purpose.

If you cannot upgrade, the workaround is to strip `data-se-iframe-holder` and `data-se-iframe-holder-attrs` in your paste hook, and to sanitize with a real HTML sanitizer before calling the insert or set APIs. A CSP `frame-src` allowlist limits where an injected frame can load from, but it does not stop inline `srcdoc` script, so it is not a substitute.

## Timeline

- **2026-09-27**: reported privately as GHSA-692m-4688-45wp, together with the namespaced-tag bypass.
- **2026-10-20**: that private advisory closed as the maintainer split the report into separate advisories.
- **2026-10-23**: GHSA-q867-q2hw-f8gp published, credit to EclipsSec and kemrec.
- **2026-11-01**: 3.4.0 and 3.4.1 verified against the original harness, all srcdoc variants blocked.
