---
title: "django-gcp's Cloud Tasks and Events Endpoints Have No Authentication By Default"
date: 2026-09-20
target: "octue/django-gcp"
severity: High
identifier: "GHSA-m3g2-c3jw-pvxf"
advisory_url: "https://github.com/octue/django-gcp/security/advisories/GHSA-m3g2-c3jw-pvxf"
summary: "django-gcp wires three routes for Cloud Tasks and PubSub events with no authentication at all, so anyone who can reach the URL can run application tasks and inject events with arbitrary arguments."
---

## Summary

django-gcp gives a Django app three routes for Google Cloud Tasks and
PubSub-driven events. All three are meant to be called only by Google
Cloud itself — but nothing in the package checks that. Any anonymous
request that can reach the URL can run whatever task the application
registered, with whatever arguments it likes, or inject an arbitrary event
into the app's event-handling code.

## Background

`django_gcp/urls.py` wires up:

```python
urlpatterns = [
    path(r"events/<event_kind>/<event_reference>", GoogleCloudEventsView.as_view(), name="gcp-events"),
    path(r"subscriber-tasks/<task_name>", GoogleCloudSubscriberTaskView.as_view(), name="gcp-subscriber-tasks"),
    path(r"tasks/<task_name>", GoogleCloudTaskView.as_view(), name="gcp-tasks"),
]
```

All three views are plain Django `View` subclasses, decorated
`csrf_exempt` (necessary, since Google Cloud won't send a CSRF token) —
but nothing else stands in for the authentication that decision removed.

`GoogleCloudTaskView.post()` selects a task class by the `task_name` URL
segment and turns the request body straight into that task's keyword
arguments:

```python
task_class = self.tasks[task_name]
task = task_class()
task_kwargs = task._body_to_kwargs(request_body=request.body)  # json.loads(body)
result = task.execute(**task_kwargs)
```

`GoogleCloudEventsView.post()` fires an `event_received` signal carrying
the URL's `event_kind` and `event_reference`, the JSON body, and the query
string — again, with nothing checking who sent the request.

The documentation does warn that these routes should sit behind platform
IAM — an internal-ingress-only Cloud Run service, or an authenticating
proxy in front of it — but that's an operator responsibility, not
something the package enforces. Nothing about the routes themselves
signals that they're unprotected by default.

Notably, the package already ships the exact mechanism this needed:
`django_gcp/workflows/oidc.py` provides `verify_workflow_oidc_token` and
`workflow_oidc_required`, which check a token's signature, verify the
audience matches the request URI, and check the signing service account
against an allow-list. That guard exists — it's just scoped to a
different feature (workflows) and never applied to tasks or events.

## Impact

Anyone who can reach the URL can invoke any registered task with
arguments of their choosing. Task handlers are backend jobs — refunds,
provisioning, deletion, third-party sync, sending mail — and are commonly
written with no authorization checks of their own, precisely because
they're only supposed to be reachable from Cloud Tasks:

```
POST /gcp/tasks/RefundCustomerTask
{"account_id": "victim-account-1", "amount": "50000.00"}

-> 200 {"result": "refunded 50000.00 to victim-account-1"}
```

An unrecognized task name returns the full registry of available tasks in
the error response, so an attacker doesn't need to guess:

```
POST /gcp/tasks/does-not-exist
-> 404 {"error": "Task does-not-exist not found", "available_tasks": ["RefundCustomerTask"]}
```

The events endpoint is equally open — an anonymous request can inject
whatever `event_kind`/`event_reference`/body/query-string it likes into
whatever the application has connected to `event_received`, which
commonly drives GCS-notification-triggered file processing.

There's no deserialization RCE here — the body is parsed with `json.loads`,
not anything that executes arbitrary code on its own — so the actual
ceiling depends on what a given deployment's tasks and event handlers do
with their input. For most applications, that's still a meaningful chunk
of backend functionality reachable by anyone on the internet.

## Fix

Fixed in **0.27.0** — upgrade following the notes at the
[0.27.0 release](https://github.com/octue/django-gcp/releases/tag/0.27.0).
If you can't upgrade immediately, put these three routes behind
authenticating infrastructure (internal-ingress Cloud Run, or a proxy that
verifies the request actually came from Google) rather than exposing them
directly.

## Timeline

- **2026-09-11** — Reported via GitHub's private security-advisory
  reporting.
- **2026-09-20** — Advisory published as `GHSA-m3g2-c3jw-pvxf`, High (CVSS
  3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L` = 8.6).
- Fixed in **0.27.0**.

## Disclosure

Full advisory: [GHSA-m3g2-c3jw-pvxf](https://github.com/octue/django-gcp/security/advisories/GHSA-m3g2-c3jw-pvxf).
