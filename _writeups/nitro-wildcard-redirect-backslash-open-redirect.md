---
title: "Nitro: Open Redirect Through a Backslash in Wildcard Redirects"
date: 2026-11-02
target: "nitrojs/nitro"
severity: Medium
identifier: "GHSA-pqxc-r4h5-jc95"
advisory_url: "https://github.com/nitrojs/nitro/security/advisories/GHSA-pqxc-r4h5-jc95"
summary: "A wildcard redirect route rule whose target is /** copies the rest of the request path into the Location header. A remainder that starts with a backslash or a control character survives the runtime's slash normalization, so a link on the trusted host sends the victim's browser to an attacker-controlled origin."
---

## Summary

Nitro lets you express a redirect as a route rule. A rule like `"/old/**": { redirect: "/**" }` is meant to move a request within the same host: whatever path came in after `/old/` is forwarded to the root. The runtime builds the `Location` header by taking the request path, stripping the rule's prefix, and keeping the rest as a same-host path.

The problem is what counts as "a same-host path." The runtime only normalizes runs of forward slashes. A remainder that begins with a backslash, such as `/\evil.example`, passes through unchanged. Browsers treat `/\` exactly like `//` for HTTP and HTTPS, so the browser reads the `Location` as a scheme-relative URL and navigates to a different origin. The result is an open redirect where the link the victim clicks is on the trusted site and the destination is fully attacker-controlled.

This is `GHSA-pqxc-r4h5-jc95`, CVSS 3.1 6.1 (Medium), fixed in nitropack 2.13.6. There is no CVE.

## Background

Route rules are part of how Nitro apps, including Nuxt 3 and 4 built on nitropack 2, declare routing behavior. A `redirect` rule can carry a wildcard. When the target ends in `/**`, the runtime forwards the tail of the request path into the redirect target instead of sending everyone to a single fixed URL.

There was an earlier open-redirect fix in this same code, `GHSA-9phm-9p8f-hw5m`. That fix collapsed a leading double slash in the forwarded remainder, and only for the case where the rule has no strip base. So `/old//evil.example` is already handled: it comes out as `/evil.example`, a same-host path. The fact that the double-slash form is normalized is the tell. The runtime intends the remainder to stay a same-host reference. The backslash form reaches the same sink and was never covered.

## The vulnerability

The redirect branch lives in `src/runtime/internal/route-rules.ts`. In the published runtime it looks like this:

```js
if (routeRules.redirect) {
  let target = routeRules.redirect.to;
  if (target.endsWith("/**")) {
    let targetPath = event.path;
    const strpBase = routeRules.redirect._redirectStripBase;
    if (strpBase) {
      if (!isPathInScope(event.path.split("?")[0], strpBase)) {
        throw createError({ statusCode: 400 });
      }
      targetPath = withoutBase(targetPath, strpBase);   // ufo: strips /^\/+/ only
    } else if (targetPath.startsWith("//")) {
      targetPath = targetPath.replace(/^\/+/, "/");      // collapses forward slashes only
    }
    target = joinURL(target.slice(0, -3), targetPath);
  }
}
```

Two preconditions make the backslash reach the header.

First, the path is already percent-decoded by the time it gets here. h3 v1 exposes `event.path` as the decoded request path and protects only the encoded slash (`%2F`). So `%5C` becomes a literal backslash and `%09` becomes a literal tab before this code runs.

Second, neither branch normalizes anything but forward slashes. With no strip base, the code only acts when the path starts with `//`, and it only collapses runs of `/`. A remainder of `/\evil.example` does not start with `//`, so nothing touches it. With a strip base, `ufo`'s `withoutBase` ends in `"/" + input.slice(base.length).replace(/^\/+/, "")`, again forward slashes only, so the stripped remainder keeps its leading backslash. The scope check in front of it, `isPathInScope`, passes because WHATWG URL parsing normalizes the backslash to a slash before comparing, so the value looks in-scope while still carrying the raw backslash forward.

`joinURL` then glues the empty prefix of `/**` to `/\evil.example`, and `sendRedirect` writes it straight into `Location`. The same value is emitted in the HTML `<meta http-equiv="refresh">` fallback body, so the redirect fires even in a client that ignores the 3xx status.

The proxy rule, which shares the same decoded path, is not affected: its `isPathInScope` guard rejects backslash and encoded-dot traversal with a 400. Only the redirect rule lacked that normalization.

## Proof of concept

A minimal node-server app with the affected rule:

```js
// nitro.config.ts
export default defineNitroConfig({
  routeRules: {
    "/old/**": { redirect: "/**" },
  },
});
```

Build it, run `.output/server/index.mjs`, and send the encoded backslash on the wire:

```
$ curl -sD- -o /dev/null -g 'http://127.0.0.1:3000/old/%5Cevil.example'
HTTP/1.1 307 Temporary Redirect
location: /\evil.example
```

`/\evil.example` is a scheme-relative reference. A real browser opening `http://127.0.0.1:3000/old/%5Cevil.example` leaves the origin and lands on `https://evil.example/`.

The already-handled double-slash form is the control. It stays on-host:

```
$ curl -sD- -o /dev/null -g 'http://127.0.0.1:3000/old//evil.example'
location: /evil.example
```

Several encodings reach the same sink:

```
/old/\evil.example       -> location: /\evil.example       (raw backslash)
/old/%5Cevil.example     -> location: /\evil.example       (encoded)
/old/%5c%5cevil.example  -> location: /\\evil.example       (double backslash)
/old/%5C/evil.example    -> location: /\/evil.example       (backslash then slash)
```

A newline (`%0A`) case throws a 500 on Node rather than redirecting, so it is not exploitable there. The fix still covers it as defense in depth.

## Impact

Any site that serves Nitro with a `redirect` route rule whose target is exactly `/**`, and whose redirect is handled by the Nitro runtime rather than a platform's generated config, is affected. That includes Nuxt 3 and 4 apps on nitropack 2.

An attacker sends the victim a link on the trusted host, ending in something like `/old/%5Cevil.example`. The link's host is the victim's own trusted domain, which carries through reputation filters, mail scanners, and any allow-list that only checks the starting host. One click and the browser is on the attacker's origin. From there it is the usual open-redirect leverage: phishing from a trusted domain, and a stepping stone against OAuth redirect allow-lists or `Referer`-based origin assumptions that trust the first host. User interaction (the click) is required, which is why the score carries UI:R.

## The fix

nitropack 2.13.6 normalizes the leading run of the redirect remainder in both branches, collapsing any mix of slashes, backslashes, control characters, and their percent-encoded forms into a single `/` before the join. The emitted `Location` is then always a same-origin path.

If you cannot upgrade yet, give the redirect target a non-empty prefix, such as `/new/**` instead of `/**`, so the remainder can no longer start the authority. A redirect with `redirect: "/new/**"` comes out as `/new/\evil.example`, which stays on-host. Defining the redirect in your reverse proxy or platform config instead of a Nitro route rule also avoids the runtime path entirely.

## Timeline

- 2026-09-26: Reported to the maintainers.
- 2026-11-02: Fix released in nitropack 2.13.6 and advisory `GHSA-pqxc-r4h5-jc95` published.

## Disclosure

Public advisory: [GHSA-pqxc-r4h5-jc95](https://github.com/nitrojs/nitro/security/advisories/GHSA-pqxc-r4h5-jc95). Fixed in [nitropack 2.13.6](https://github.com/nitrojs/nitro/releases/tag/v2.13.6).
