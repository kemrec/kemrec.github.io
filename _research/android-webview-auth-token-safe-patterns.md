---
title: "Handing Auth Tokens to Android WebViews Without Handing Them to Attackers"
date: 2026-10-27
target: "Android / WebView security"
summary: "A field guide to giving an in-app Android WebView the user's session without giving it to an attacker: the origin-scoped pattern that holds, the handful of ways apps leak the token instead, and why the safe posture never rests on a single control. Built entirely from reading public open-source code."
---

## Why this is hard

A lot of Android apps embed a WebView that has to act as the signed-in user: an in-app help centre, a store admin panel, a payment or verification flow, a chat widget. To do that, the app hands the WebView something sensitive, a session cookie, a bearer token, or a JavaScript bridge the page can call to get one.

That is fine right up until the WebView loads a page the attacker influences. The moment attacker-controlled content runs in a WebView that is holding the user's token, the token is the attacker's. On a bank, a wallet, or a social account that is a one-click account takeover: the victim taps a link, an authenticated WebView opens, and the session walks out to a host the attacker controls.

So the whole problem reduces to two questions, and an app is only safe if it answers **both** correctly:

1. **What** does the WebView hold, and **how** is it exposed to the page?
2. **Which origins** can become the page in that WebView?

Get either wrong and the token leaks. Below is what "right" looks like, drawn from open-source apps that get it right, followed by the mistakes that show up when it goes wrong. Everything here is public source code anyone can read, and none of it is a report of an unfixed, confirmed exploit.

## The safe shape: `postMessage` to a specific origin

The strongest way to give a page a token is **not** a JavaScript interface with a `getToken()` method. It is the browser's own origin-scoped messaging: `WebViewCompat.postWebMessage(webView, message, targetOrigin)`, or in the page direction `window.postMessage(msg, targetOrigin)`.

The key is the `targetOrigin` argument. The platform **refuses to deliver** the message to a frame whose origin does not match it. So if you post the token with `targetOrigin = https://app.example.com`, and the page in the WebView has navigated, or been redirected, or been framed, to any other origin, the message is simply never delivered. The browser enforces the origin check for you, so you do not have to trust your own navigation tracking to be perfectly in sync.

The failure mode here is a single character: passing `"*"`, or `Uri.EMPTY`, or a `WebMessage` with no origin, as the target. That tells the platform "deliver to whatever is loaded," which is exactly the thing you are trying to prevent. **Never post a token with a wildcard target origin.**

Contrast this with `addJavascriptInterface` plus an `@JavascriptInterface` method that returns the token on demand. That method answers *any* page in the WebView, with no origin argument at all, so its safety depends entirely on question 2 being answered perfectly, every time, forever. The `postMessage` approach bakes the origin check into the delivery.

## The safe shape: exact-origin allowlists, re-checked on every navigation

When the app does gate which origins are trusted, to decide whether to attach a bridge, inject a cookie, or even load the URL at all, two properties separate the safe implementations from the leaky ones.

**Exact matching.** The trusted set is compared by full scheme, host and port equality, not by substring. Home Assistant's companion app, for example, decides "is this still my server?" with an exact origin comparison and routes anything else out to the external browser (`UrlUtil.hasSameOrigin`, and the external-URL handling in `FrontendViewModel`). An app that instead asks `host.endsWith(".example.com")` or `url.contains("example.com")` has quietly widened its trust boundary to every subdomain, and more on why that bites is below.

**Re-evaluation per navigation.** The check cannot run only when the WebView is first created. It has to run again in `shouldOverrideUrlLoading` for each navigation, so that a redirect or an in-page link to a foreign origin *detaches* the token or bridge before the new page runs. A trust decision made once at load time and never revisited is a trust decision the first redirect invalidates.

Deliver via origin-scoped `postMessage` **and** gate with an exact, per-navigation origin check, and the two layers cover each other: even if your navigation tracker lags, the browser's own `targetOrigin` enforcement still withholds the token from the wrong origin.

## Mistake 1: the token gets a `getToken()` with no origin check

A JavaScript interface whose method returns the session token, attached to a WebView that can navigate off the trusted origin, is the classic leak. The fix is either to stop exposing the token to the page at all, or to switch to origin-scoped `postMessage`, or, at minimum, to attach the interface only while the loaded origin is exactly the trusted one and detach it on every navigation away.

A softer version of the same mistake is attaching the bridge for a broader set of page "kinds" than necessary. Element's Android client, for instance, attaches its widget `postMessage` bridge only for admin-type widgets and replies to the page's *exact* `event.origin`, so a room widget pointed at a foreign URL gets no bridge and no token, because the scope is deliberately narrow.

## Mistake 2: injecting the cookie or `Authorization` header by host suffix

Several apps decide whether to attach the user's credential to an outbound request by testing the destination host. If that test is a suffix or substring match, such as `host.endsWith(".example.com")`, it matches every subdomain of the platform, including ones an attacker can register.

This is worth dwelling on because the exploitability is subtle. Consider an app that attaches a bearer token to any request whose host ends in `.example.com`, and a platform that hands out `*.example.com` subdomains to anyone (free blog hosts do exactly this). On paper the token now flows to `attacker.example.com`. In practice it may **still not be exploitable**, because:

- the attacker controls the *content* served at `attacker.example.com`, but not the HTTP server, so they cannot read the `Authorization` header off the inbound request;
- HTTP clients like OkHttp strip the `Authorization` header across a cross-host redirect;
- the credential cookies are `HttpOnly`, so page JavaScript cannot read them, and free subdomain tiers typically forbid custom JavaScript anyway.

So a suffix-matched allowlist is a **shape** bug, a trust boundary wider than intended, that only becomes a **leak** when the attacker can run a real server, or arbitrary JavaScript, at the allowed origin. The lesson cuts both ways. Defenders should still tighten the match to exact hosts as defence in depth, and anyone assessing such a pattern should check "can the attacker actually receive the secret here?" before calling it a vulnerability. A suffix match against a platform whose subdomains are fully attacker-controlled, with a custom server and custom JavaScript, is a genuine leak; the same match against locked-down platform-hosted subdomains is not.

## Mistake 3: no navigation gate on an authenticated WebView

The quietest mistake is an authenticated WebView whose `WebViewClient` never overrides navigation at all, returning `false` from `shouldOverrideUrlLoading` and letting the page go wherever links and redirects take it. As long as that WebView carries a cookie or token, every page it can reach is a page the credential can reach. Whether that is a real leak again depends on Mistake 2's question of whether the attacker can receive it, but the safe posture is simple: an authenticated WebView should keep navigation inside the trusted origin and push everything else to the system browser, where the app's credentials do not follow.

### A worked example: Frost for Facebook

Frost for Facebook is an open-source Facebook client, now discontinued, built as exactly this kind of authenticated WebView: it signs the user into facebook.com inside an in-app WebView and reuses that session as the user browses. Its public source makes a clean teaching case because it shows both halves of Mistake 3 at once, a credential living in the WebView and no host gate on where that WebView can go.

Its `WebViewClient.shouldOverrideUrlLoading` runs a short ladder of checks before falling through to the default, and none of them is a host allowlist. One branch asks only whether the URL "looks like" a full-size image link, using a plain substring test: the URL is treated as a Facebook image when it `contains("/photo/view_full_size/")` and `contains("fbid=")` (`utils/Utils.kt`). There is no host in that test and nothing anchoring the substrings to a path, so a URL on any host satisfies it, for example `https://attacker.example/?x=/photo/view_full_size/&fbid=1`.

When a navigation matches, Frost does not open the image in a cookieless viewer. It calls its image loader with the facebook.com cookie jar attached (`launchImage(..., cookie = fbCookie.webCookie)`), and the loader issues an HTTP GET to that same page-supplied URL with the cookies set as a `Cookie:` request header (`facebook/requests/Images.kt`, `facebook/FbRequest.kt`). The URL formatter preserves the host it was handed rather than forcing it back to facebook.com. A crafted link whose host is the attacker's, carrying those two substrings, therefore makes the app send the user's facebook.com cookies to the attacker's own server.

How bad that is comes straight back to the question from Mistake 2: can the attacker actually receive the secret, and is the secret enough. Here the attacker does control a real server at the destination host, so they receive whatever is in the `Cookie` header, and the contents of that header are the whole determinant. The string comes from `CookieManager.getInstance().getCookie("https://www.facebook.com")` (`facebook/FbCookie.kt`). If it includes the `HttpOnly` session cookie, the leak is a full session takeover; if the platform's `getCookie` returns only the non-`HttpOnly` cookies, the attacker learns the account id but not a usable session. That single platform-behaviour question is the line between account takeover and information leak, and it is exactly the thing to settle before attaching a severity to it.

The structural lesson is the general one. An authenticated WebView with no exact-host navigation gate lets one attacker-supplied link become a credentialed request to an attacker host, and the cleverness of the "is this one of our image URLs" heuristic does not change that. A per-navigation host allowlist, with everything off-origin pushed to the external browser, closes the whole class.

## When the attacker's content is meant to be there: mail apps

The examples so far assume attacker content arrives by accident, through a navigation the app failed to gate. Some apps invite it in by design. An email client renders HTML that a stranger wrote and sent you, and it often renders it inside the same WebView that holds the app's own session and native bridge. The attacker does not need to redirect anything. They just send you a message.

That raises the stakes on a single question: can the HTML in that message run script in a context where it can reach the app's bridge or credentials? Two open-source mail apps answer it in instructive, and opposite, ways.

FairEmail layers its defences. The message body renders in a WebView with JavaScript and cookies turned off (`WebViewEx`), links open in the system browser rather than in place, and there is no `addJavascriptInterface` bridge anywhere in the app for script to reach even if it ran. Each layer on its own would mostly do the job; together they leave no single control whose failure hands an attacker the account.

Tuta takes the opposite structural bet. Its mail body is sanitised with DOMPurify and then rendered inline, cloned into an open shadow root in the app's own document (`MailViewer`), which is the same realm as the native `NativeInterface` bridge the web client uses to reach the user's keys. A shadow root is an encapsulation feature, not a security boundary: script that runs inside it runs in the app realm. Nothing attacker-written executes today, because DOMPurify strips scripts, event handlers and `javascript:` URLs before the fragment is ever attached, and the configuration is a careful one. The point is not that Tuta is exploitable, because as configured it is not. The point is that the sanitiser is the only thing standing between a hostile email and the bridge. Mutation-XSS bypasses of HTML sanitisers do surface from time to time, and the day one lands against this configuration, there is no second wall behind it.

Neither design is wrong, and Tuta's sanitiser is well set up. But the contrast is the lesson of this whole article in one frame. The safe posture does not rely on any single control being perfect forever. It assumes the origin check, or the sanitiser, or the navigation gate will eventually fail, and arranges things so that one failure is not the whole account.

## A checklist

If you own an Android app with an authenticated WebView:

- Prefer `postWebMessage` or `postMessage` with a **specific** `targetOrigin` over a token-returning `@JavascriptInterface`. Never use `"*"`.
- If you must bridge, attach it only while the loaded origin is **exactly** the trusted one, and re-check on every navigation.
- Gate cookie or `Authorization` injection by **exact host**, not by `endsWith`, `contains`, or an unanchored pattern.
- Override `shouldOverrideUrlLoading`: keep the authenticated WebView on the trusted origin, send everything else to the external browser.
- Treat the WebView's current origin as something to verify from the app's own navigation state, not from anything the page tells you.
- Where attacker content is unavoidable, such as rendered email, assume it will one day run, and keep it out of any realm that can reach the session or a native bridge.

None of this is new, and the good news is that most well-maintained apps already do it. The pattern is cheap to get right and expensive to get wrong, and the cost of wrong is the user's account.
