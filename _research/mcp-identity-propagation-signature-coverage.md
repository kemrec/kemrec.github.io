---
title: "An Identity Signature Is Only As Good As the Claims It Covers"
date: 2026-11-16
target: "MCP gateways / identity propagation"
summary: "When an MCP gateway forwards a user's identity to an upstream server and signs it so the upstream can trust it, the signature is only meaningful if it covers the fields the upstream authorizes on and is bound to a time and an audience. A field guide to the safe shape, the two ways the signature ends up protecting the wrong thing, and the honest test for whether a coverage gap is a real forgery primitive or just a widened trust boundary. Built entirely from reading public open-source code."
---

## Why this is hard

A Model Context Protocol gateway sits between a client and a set of upstream MCP servers. One of the things a gateway is asked to do is carry the end user's identity to those upstreams, so that an upstream tool can make its own authorization decision: this call is coming from Alice, Alice is not an admin, so deny the admin tool. The gateway does that by attaching a set of headers to the outbound request, something like `X-Forwarded-User-Id`, `X-Forwarded-User-Admin`, `X-Forwarded-User-Roles`, `X-Forwarded-User-Groups`.

Plain headers are trivial to forge, so the better designs add a signature. The gateway computes an HMAC over the forwarded identity and ships it alongside, in a header such as `X-Forwarded-User-Claims-Signature`, and the upstream recomputes the same HMAC with a shared secret to decide whether to believe what it was handed. The documentation for this kind of feature usually says, in so many words, that the signature is how the upstream "verifies" the identity.

That is the whole promise, and it reduces to two questions. An implementation is only safe if it answers both:

1. **What** does the signature actually cover, relative to what the upstream **authorizes on**?
2. **Who** can present a header set carrying a valid signature to that upstream?

Get the first wrong and the signature authenticates the wrong bytes. Get the second wrong and it does not matter what you signed. Everything below is drawn from public, open-source gateway code anyone can read, and none of it is a report of an unfixed, confirmed exploit.

## The safe shape: sign everything you authorize on, bind it to a time and an audience

A signature is a promise with a precise meaning: *these exact bytes came from me, and they are fresh, and they are for you.* If you want an upstream to make an authorization decision on a forwarded identity, the bytes you sign have to be the bytes that decision reads, and the promise has to be scoped so it cannot be reused later or somewhere else.

Concretely, a forwarded-identity signature that holds up has four properties:

- **Full coverage.** The signed message is a canonical serialization of every claim the upstream might authorize on, not just the user's name. If `Admin`, `Roles`, `Groups`, `Teams` and any delegation chain travel in the request, they are inside the signed payload. The identity and the privileges are signed together, as one object, because together they are the thing being trusted.
- **Freshness.** The payload carries an issued-at timestamp and a short expiry, and ideally a nonce or counter. Without this, a single valid header set is good forever.
- **Audience.** The payload names the upstream it was minted for, or at least the gateway that minted it. Without this, a tag made for one upstream is equally valid at every other upstream that shares the secret.
- **A stated verification contract.** The upstream is told exactly which fields and which bindings to check, so verification is not left to each integrator's guess.

The cleanest way to get all four at once is to stop hand-rolling an HMAC over a string and instead mint a short-lived signed token, a JWT with `aud`, `iat` and `exp` and the claims in the body. The JWT libraries already enforce expiry and audience, and the claims are the signed payload by construction, so the "did I sign the privileges" question cannot be answered wrong by accident. If a bare HMAC is kept, the same discipline has to be applied by hand: serialize the whole claim set, append a timestamp and an audience, and HMAC that.

## Mistake 1: signing the identity but not the privileges

The most common way this goes wrong is a signature computed over who the user is, while the fields that decide what the user may do ride next to it unsigned.

In the open, you can see the shape directly. IBM's MCP Context Forge gateway (the `mcpgateway` project) builds its forwarded headers in `mcpgateway/utils/identity_propagation.py`. When claim signing is enabled, the signed payload is constructed like this:

```python
# build_identity_headers(), abridged
headers[f"{prefix}-Admin"]  = str(user_context.is_admin).lower()
headers[f"{prefix}-Roles"]  = ",".join(user_context.roles)
# ... groups, teams, delegation chain ...
if cfg["sign_claims"]:
    sig_payload = f"{user_context.user_id}:{user_context.email or ''}"
    headers[f"{prefix}-Claims-Signature"] = _sign_claims(sig_payload)
```

The payload handed to the HMAC is `user_id:email`. The `Admin`, `Roles`, `Groups`, `Teams` and delegation headers are set a few lines above and are not part of it. So the signature says, truthfully, "this is Alice." It says nothing at all about the `Admin: false` sitting beside it, which is the field an upstream actually reads to gate the admin tool.

An upstream that does exactly what the feature invites it to do, recompute the HMAC over the identity and then trust the forwarded `Admin` and `Roles`, is verifying one thing and authorizing on another. The signature passes while `Admin` is whatever the header currently says. The lesson is a single sentence: **sign what you authorize on, not just who the user is.** A signature over a strict subset of the security-relevant fields authenticates the wrong object.

## Mistake 2: a signature with no freshness and no audience is a bearer token

The second property that separates a real identity tag from a decorative one is scope in time and place. If the signed payload is just `user_id:email`, then for a given user the HMAC is a constant. It does not change between requests, it does not expire, and it carries nothing that ties it to a particular upstream.

A constant, non-expiring, audience-less tag is a bearer token wearing a signature's clothes. Whoever holds one valid copy can present it again later, because nothing in it says when it was minted, and can present it to any upstream configured with the same secret, because nothing in it says which upstream it was for. The "shared secret across a trust domain" deployment that these features document as a normal mode is precisely the setting where one tag is accepted in many places.

The fix is the freshness and audience properties from the safe shape: an `iat` and a short `exp` so a captured tag dies quickly, a nonce so it cannot be replayed even inside its window, and an audience so it cannot be walked from the upstream it was meant for to a more sensitive one next door.

## Is it a leak, or just a widened trust boundary?

This is the part that an honest write-up has to include, because the coverage gap above is real but its exploitability is conditional, and the condition is the interesting part.

Consider the "single trust domain, shared secret" model, where the gateway and the upstreams all hold the same signing key. A party inside that domain already has the secret. It does not need the coverage gap to forge anything: it can compute a valid signature for any `user_id:email` it likes, with any `Admin` value, from first principles. Against a secret-holder, an unsigned-privileges tag adds no new power, because that party was already trusted to mint tags. Pointed at that model alone, the gap is a widened shape, worth fixing as hardening, not a new capability.

The gap becomes a genuine forgery and replay primitive only when someone who does **not** hold the secret can do two things:

- **Obtain one valid signed header set.** Because the tag never expires, a single capture is enough. These headers are exactly the kind of thing that ends up in audit logs, request mirrors, and proxy traces, which the same feature often markets them for, so a static tag has a long and quiet life once written down.
- **Present it to a verifying upstream.** The attacker needs a path to send a request carrying those headers directly to an upstream that recomputes the signature and authorizes on the claims. If the upstream is only ever reachable through the gateway, that path may not exist. If the upstream independently trusts these headers from the network, it does.

So the test, before anyone calls a signature-coverage gap a vulnerability, is concrete: *can a party without the secret both capture a valid tag and reach an upstream that verifies it and acts on the forwarded claims?* If yes, then because the privileges are unsigned, that party does not just replay Alice, it replays Alice with `Admin: true` and `Roles: admin` appended, and the recomputed `user_id:email` HMAC still matches. That is identity spoofing and privilege escalation at the upstream, from a party that was never trusted. If no, if the only entities that can put headers in front of a verifying upstream are the secret-holders who could already forge, then the gap is a trust boundary drawn wider than it should be, and the right posture is to tighten it as defense in depth without overselling the impact.

The lesson cuts both ways, the same way it does for a suffix-matched allowlist or an over-broad WebView bridge. A defender should close the gap regardless, because designs change and the party who can reach the upstream tomorrow is not always the one who can reach it today. An assessor should ask the reachability question honestly before reaching for the word "critical."

## The checklist

If you are building or reviewing identity propagation in an MCP gateway, the signature is doing its job only if all of these hold:

- The signed payload is a canonical serialization of **every** claim an upstream authorizes on, privileges included, not just the user identifier.
- The payload carries an issued-at and a short expiry, and a nonce or counter, so a captured tag cannot be replayed.
- The payload names its audience, the specific upstream or gateway, so a tag cannot be walked to another upstream that shares the secret.
- Upstreams are given an explicit verification contract: which fields to check, which bindings to enforce, and to reject anything stale or misaddressed.
- Prefer a short-lived signed token (a JWT with `aud`, `iat`, `exp`) over a bare HMAC, so coverage, freshness and audience are enforced by the token format rather than by remembering to append them.
- Treat the headers as sensitive at rest. A static tag in a log file is a credential in a log file.

A signature is a promise about a specific set of bytes. The failure in all of the shapes above is the same: the bytes it promises about are not the bytes the other side believes. Make the signed object the whole trusted object, bind it to now and to you, and the promise finally means what the documentation already claims it does.
