---
title: "django-ses: Forged SES Delivery Events via Unverified SNS Topic Origin"
date: 2026-10-12
target: "django-ses/django-ses"
severity: High
identifier: "GHSA-2vww-32j3-5v92"
advisory_url: "https://github.com/django-ses/django-ses/security/advisories/GHSA-2vww-32j3-5v92"
summary: "django-ses's SES event webhook verified the SNS signature on incoming notifications but never checked which topic sent them — any AWS account can subscribe the deployment's webhook URL to a topic of its own, have django-ses auto-confirm the subscription, and then publish forged bounce and complaint events that the application processes as genuine. With the blacklist integration enabled, the attacker chooses which addresses stop receiving mail; with default settings, every event handler receives attacker-controlled input while believing it came from AWS. Fixed in 4.8.1 via an opt-in trusted-topic allowlist and an https-only SubscribeURL constraint."
---

## Summary

django-ses ships an SES event webhook (`SESEventWebhookView`) that receives
SNS notifications for bounces, complaints, deliveries, opens and clicks. The
view verifies the SNS signature on each notification — and with
`AWS_SES_VERIFY_EVENT_SIGNATURES = True` (the default) that verification is
real: an invalid signature is rejected with a 400.

The problem is what a valid signature proves. It proves a message came from
*an* AWS SNS topic. It does not prove the message came from *your* topic.
`TopicArn` appears in the package only inside log statements and in the list
of fields covered by the signature — it is never compared against an expected
value, and there is no setting that would let an operator configure one.

Any AWS account can therefore create a topic of its own, subscribe the
deployment's webhook URL to it, and start publishing. The subscription
confirmation is accepted automatically — `handle_subscription_confirmation()`
fetches the notification's `SubscribeURL` and the subscription goes live with
no operator involvement — and from then on every notification the attacker
publishes is signed by AWS, verifies correctly, and is dispatched as a
genuine delivery event. No credential belonging to the deployment is needed
at any point.

With `AWS_SES_ADD_BOUNCE_TO_BLACKLIST = True`, a single forged
permanent-bounce event adds any address the attacker names to
`BlacklistedEmail`, and `filter_blacklisted_recipients()` then strips that
address from every outgoing message. The attacker decides which users stop
receiving password resets, MFA codes and invoices. Fixed in 4.8.1
(2026-10-12).

## Background

django-ses is the long-standing Django email backend for Amazon SES. Beyond
sending, it provides webhook views that receive SNS notifications from SES
and reflect them into the application: bounces and complaints can be added to
a `BlacklistedEmail` table, and applications commonly register signal
handlers (`bounce_received`, `complaint_received`, `delivery_received`,
`open_received`, `click_received`) to keep their own delivery state in sync.

The README's standard setup mounts `SESEventWebhookView` at a public URL and
configures the SNS topic to deliver to it. Because the endpoint is public,
the package verifies the SNS message signature before acting on a
notification: the signing certificate is fetched from an
`sns.<region>.amazonaws.com` URL that must match an anchored regex and a
trusted-domain list, and the signature itself is checked over the canonical
message fields. That machinery does what it claims to do.

What the machinery does not establish is *which topic* sent the message.
Nothing between the signature check and the event dispatch inspects the
sender's identity.

## The vulnerability

The view's `post()` is, in full, two steps:

```python
if settings.VERIFY_EVENT_SIGNATURES and not self.verify_event_message(notification):
    return HttpResponseBadRequest("Signature verification failed.")

if notification.get("Type") == "SubscriptionConfirmation":
    self.handle_subscription_confirmation(notification)
```

Signature verification, then act on the notification — with no check on
`TopicArn` in between. The same is true of the deprecated `handle_bounce`
path, and of `confirm_sns_subscription()` in `utils.py`:

```python
subscribe_url = notification.get("SubscribeURL")
urlopen(subscribe_url).read()
```

so a subscription request from any topic is confirmed by simply fetching the
URL the notification names.

The full attack, from an attacker's own AWS account:

1. Create an SNS topic in that account.
2. Subscribe the deployment's webhook URL to it.
3. AWS sends a `SubscriptionConfirmation` signed with a genuine
   `sns.<region>.amazonaws.com` certificate. django-ses verifies it —
   correctly, the signature really is valid — then fetches `SubscribeURL`,
   and the subscription is live.
4. Publish anything to the topic. AWS signs it, django-ses verifies it,
   parses the attacker-controlled `Message` field and dispatches it as a
   delivery event.

`TopicArn` never participates. A check of the published releases (1.0.0,
2.0.0, 3.0.0, 3.5.0, 4.0.0, 4.4.0, 4.8.0) shows that no version ever compared
it against an expected value, none ever had a topic-related setting in
`conf.py`, and automatic subscription confirmation is present throughout —
in `views.py` in 1.0.0, moved to `utils.py` from 2.0.0 on. Every published
version is affected.

Two things worth stating precisely, because both bound the finding:

- **The signature check itself is not broken.** The anchored certificate-URL
  regex and the label-wise suffix match against
  `AWS_SNS_EVENT_CERT_TRUSTED_DOMAINS` both hold up; the report that led to
  this advisory explicitly does not claim otherwise. The claim is narrower:
  a signature alone does not establish origin.
- **`SubscribeURL` goes to `urlopen()` unconstrained.** That accepts
  `file://` and anything else urllib supports, so a confirmed subscription
  would be a fetch primitive — but it sits behind signature verification, so
  an outsider cannot reach it today. It is closed as a hardening measure in
  the same fix, not because it was independently exploitable.

## Verifying it

The behaviour was reproduced against a stock lab: django-ses 4.8.0, Django
6.1.1, `SESEventWebhookView` mounted exactly as the README shows,
`AWS_SES_VERIFY_EVENT_SIGNATURES = True` (the default, and the control under
test), `AWS_SES_ADD_BOUNCE_TO_BLACKLIST = True`:

```
victim address blacklisted before: False
TopicArn presented              : arn:aws:sns:us-east-1:999999999999:attacker-controlled-topic
signature verification result   : True
webhook HTTP status             : 200
victim address blacklisted after: True
recipients surviving the filter : []
```

One substitution has to be stated plainly: AWS's SNS signing key is not
available to a lab, so the lab signs with its own key and seeds the package's
certificate cache under a URL that satisfies the package's own domain rules.
The signature verification code runs completely unmodified and returns
`True`. The real attack needs no substitution at all, because AWS signs the
attacker's own topic's messages with a genuine certificate and the
verification path never looks at which topic sent them. The lab isolates the
missing control rather than bypassing the one that is present.

The fix itself was then verified end-to-end before it was merged, on a live
`runserver` against the fork PR head (`8324e04`): a 13-scenario E2E matrix
(21 checks) covering attacker-topic and trusted-topic notifications across
both webhook paths, `SubscriptionConfirmation` and `UnsubscribeConfirmation`
handling, and hostile `SubscribeURL` shapes (`file://`, `http://`, lookalike
suffixes, userinfo tricks) with an instrumented `urlopen` sink — plus a
30-case predicate battery over the two new helpers, all failing closed, and
the vendor test suite (`Ran 96 tests ... OK`).

## Impact

With `AWS_SES_ADD_BOUNCE_TO_BLACKLIST = True`, a forged permanent-bounce
event adds an attacker-chosen address to `BlacklistedEmail`.
`filter_blacklisted_recipients()` then strips it from every outgoing message
and the send fails with "Refusing to send email. All recipients were filtered
by the blacklist". The attacker decides which users stop receiving password
resets, MFA codes and invoices. `AWS_SES_ADD_COMPLAINT_TO_BLACKLIST` reaches
the same state through complaints.

With default settings the blacklist is off and the impact is narrower, but
not nothing: every `bounce_received`, `complaint_received`,
`delivery_received`, `open_received` and `click_received` handler in the
application receives attacker-controlled `mail_obj` and raw message while
believing it came from AWS.

No credential belonging to the deployment is needed at any point, and the
webhook is public by design — it is the endpoint SES is supposed to reach.
The advisory rates it `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = **7.5
High** (CWE-290, CWE-346): remote, no privileges, no user interaction, and
the damage is to integrity — the application's record of what AWS actually
did.

## The fix

Fixed on 2026-10-12 and released as **4.8.1**. The fix implements both
recommendations from the report:

1. **A trusted-topic allowlist.** A new setting,
   `AWS_SNS_EVENT_TRUSTED_TOPIC_ARNS`, checked in `post()` and
   `handle_bounce()` immediately after signature verification (untrusted
   topics get a 400 "Untrusted topic.") and again inside
   `confirm_sns_subscription()`, so an untrusted topic cannot attach in the
   first place. The default is an empty list, which preserves the historical
   behaviour of accepting any topic — the setting must be configured to
   actually block, and the `conf.py` comment says so plainly: *"Leaving this
   empty preserves the historical behaviour of accepting any topic, which is
   not safe for a publicly reachable webhook."*
2. **`SubscribeURL` constrained to SNS.** `is_trusted_sns_subscribe_url()`
   requires `https` on an `sns.<region>.amazonaws.com` (or `.cn`) host before
   the confirmation fetch happens, removing the `file://` fetch primitive
   from behind the signature gate.

The default was the real decision, and it belongs to the maintainers. An
empty default keeps every deployment working and leaves them as exposed as
they are today; reject-unless-configured is safe and breaks every deployment
on upgrade. The maintainers chose the empty default with documentation. If
you run django-ses with a public webhook, set the setting.

## Timeline

- **2026-09-11** — Reported via GitHub's private vulnerability reporting
  (with a same-day correction simplifying the report).
- **2026-09-12** — Patch attached in the advisory thread.
- **2026-10-09** — Maintainer opens the fix PR on the advisory fork and asks
  for verification.
- **2026-10-10** — Fix verified end-to-end on the fork PR head (`8324e04`):
  13-scenario E2E matrix (21 checks), 30-case predicate battery, vendor suite
  green.
- **2026-10-12** — Merged (`a98f37d3`), released as 4.8.1, and the advisory
  published: `GHSA-2vww-32j3-5v92`, High (CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` = 7.5, CWE-290/CWE-346), no CVE
  assigned.

## Disclosure

Full advisory: [GHSA-2vww-32j3-5v92](https://github.com/django-ses/django-ses/security/advisories/GHSA-2vww-32j3-5v92)
(published 2026-10-12; High; no CVE assigned). The fix is in
[v4.8.1](https://github.com/django-ses/django-ses/releases/tag/v4.8.1)
(commit `a98f37d3`). This writeup describes behaviour verified against
django-ses 4.8.0 in a local lab and the fix as merged for 4.8.1.
