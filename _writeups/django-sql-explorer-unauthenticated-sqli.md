---
title: "Unauthenticated SQL Injection in django-sql-explorer's AI Assistant Endpoint"
date: 2026-09-25
target: "explorerhq/sql-explorer (django-sql-explorer)"
severity: Critical
identifier: "GHSA-cj2v-7pv9-p63r"
advisory_url: "https://github.com/explorerhq/sql-explorer/security/advisories/GHSA-cj2v-7pv9-p63r"
summary: "django-sql-explorer's AI Assistant endpoints had no permission check and interpolated attacker-supplied table names directly into SQL, giving unauthenticated users arbitrary SQL execution."
---

## Summary

django-sql-explorer is a Django app that lets authorized users run and
save SQL queries against configured database connections through a web
UI. A newer feature, the AI Assistant, adds a chat-style helper that
samples table contents to answer questions about the schema. Its two
endpoints shipped with no permission check at all — reachable by anyone
who could reach the application, logged in or not — and one of them built
its sampling query by dropping a client-supplied table name straight into
a SQL string. Put those two together and an unauthenticated request could
run arbitrary SQL against any database connection Explorer had configured,
including the Django application's own database if it was registered as
one.

## Background

Every other view in the same module that touches table metadata —
`TableDescriptionUpdateView`, `TableDescriptionCheckView`, and their
siblings — is gated behind `PermissionRequiredMixin`, checking either
`view_permission` or `change_permission` depending on what it does. The
Assistant views, `AssistantHelpView` and `AssistantHistoryApiView`, are
just plain Django `View` subclasses, with nothing checking who's calling
them.

They're also registered unconditionally: even an installation that never
configured `EXPLORER_AI_API_KEY` (i.e., never intended to turn the
Assistant feature on) still exposes these routes.

## The vulnerability

`POST <explorer-root>/assistant/` accepts a `selected_tables` field
listing which tables the assistant should sample. The sampling code takes
each name from that field and interpolates it directly:

```python
cursor.execute(f"SELECT * FROM {table_name} LIMIT 3")
```

No permission check happens before this runs, and no validation or
quoting happens to `table_name` before it lands in the query string. Since
`selected_tables` is entirely attacker-controlled request body, and
nothing checks the caller is even logged in, this is unauthenticated,
unauthenticated-user-controlled SQL — not just a limited "which tables can
I list" issue.

`POST <explorer-root>/assistant/history/` has the same missing permission
check, giving unauthenticated access to Assistant history regardless of
the SQL injection.

## Impact

Depending on the database backend and the privileges of the connection's
configured user, an unauthenticated attacker can read, modify, or delete
data through any connection Explorer has registered — including the
Django project's own primary database in installations that expose it
through Explorer, which is a supported and common configuration.

## Fix

Fixed in **5.3.1**. The Assistant endpoints now require
`EXPLORER_PERMISSION_CHANGE`, and table sampling only considers tables
actually present in the connection's introspected schema (respecting the
`EXPLORER_SCHEMA_INCLUDE_TABLE_PREFIXES` / `EXPLORER_SCHEMA_EXCLUDE_TABLE_PREFIXES`
settings), with the table name quoted as an identifier rather than
interpolated raw.

```
pip install --upgrade 'django-sql-explorer>=5.3.1'
```

If you can't upgrade immediately, block requests to the `assistant/` and
`assistant/history/` paths under your Explorer URL prefix at your reverse
proxy — leaving `EXPLORER_AI_API_KEY` unset does **not** mitigate this,
since the endpoints are registered regardless.

## Timeline

- **2026-09-10** — Reported to the maintainer.
- **2026-09-25** — Maintainer replied, fixed and released **5.3.1** the
  same day.
- **2026-09-25** — Advisory published as `GHSA-cj2v-7pv9-p63r`, Critical
  (CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8).

## Disclosure

Full advisory: [GHSA-cj2v-7pv9-p63r](https://github.com/explorerhq/sql-explorer/security/advisories/GHSA-cj2v-7pv9-p63r).
