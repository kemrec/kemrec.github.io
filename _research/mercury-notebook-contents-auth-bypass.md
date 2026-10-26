---
title: "Mercury: notebook source readable without credentials on token- or password-protected servers"
date: 2026-10-26
target: "mljar/mercury"
severity: High
fixed: "3.2.12"
fix: "authentication restored on MercuryContentsHandler"
fix_url: "https://github.com/mljar/mercury/releases/tag/v3.2.12"
advisory_url: "https://github.com/mljar/mercury/security/advisories/GHSA-w823-3v59-v22p"
summary: "Mercury standalone adds its own contents handler for .ipynb paths and overrides get() and put() without the authentication decorators Jupyter's base class carries. On a server started with --token or --pass, an anonymous GET /api/contents/<name>.ipynb returns the full notebook JSON, including cell source and the hidden checkpoint copy. Verified on 3.2.3 through 3.2.11; fixed in 3.2.12."
---

## Summary

Mercury can be started with authentication, either a static token (`--token`, `MERCURY_TOKEN`) or a password (`--pass`, `MERCURY_PASSWORD`). In that mode the web app, the REST API, the login redirect and the notebook listing all refuse anonymous clients. One route that Mercury adds itself does not: `GET /api/contents/<path>.ipynb` answers with the complete notebook document, no credentials required.

The document contains every code cell, the markdown, and the notebook metadata. On the servers I tested it also returned the `.ipynb_checkpoints` copy, which Mercury enables by forcing `ContentsManager.allow_hidden`.

Mercury is a dashboard layer over Jupyter: a notebook is both the report and the code that builds it. Cell source is where deployments keep database passwords, API keys and internal hostnames. That is the material the password exists to protect, and the vendor documentation says so: "Before opening the notebook user needs to provide the password".

## Background

Mercury runs in two shapes. As a JupyterLab extension it inherits JupyterLab's routing and authentication. In standalone mode (`mercury` entry point, `is_mercury_app()` true) it builds its own Tornado application and prepends its own route rules ahead of Jupyter's blocklist:

```python
security_rules.append(Rule(PathMatches(full_pattern), handler))
app.default_router.rules = security_rules + block_rules + app.default_router.rules
```

One of those rules maps notebook paths to a Mercury handler:

```python
(r"/api/contents/(.*\.ipynb)", MercuryContentsHandler),
```

In Jupyter, authentication on the contents API is not a middleware decision. It is a decorator on each handler method: `ContentsHandler.get` and `ContentsHandler.put` carry `@web.authenticated`, and read access goes through `@authorized`. A subclass that overrides the method without repeating the decorator loses the check, because Python decorators are not inherited with the method body.

## The handler that skipped the check

`mercury_app/custom_contents_handler.py` in 3.2.11:

```python
class MercuryContentsHandler(ContentsHandler):
    async def get(self, path=""):
        model = await ensure_async(
            self.contents_manager.get(path, content=True, type=None, format=None)
        )
        ...
        self.finish(model)
```

No `@web.authenticated`. No `@authorized`. The `put` method in the same class has the same shape. The sibling class in the same file shows what the author intended:

```python
class MercuryCheckpointsHandler(CheckpointsHandler):
    @web.authenticated
    @authorized
    async def get(self, path, checkpoint_id):
        ...
```

That handler answers 403 to an anonymous client. The contents handler answers 200 with the notebook.

## Proof of concept

Server:

```
mercury --token=SECRETTKN --working-dir /srv/apps --port 8951
```

Client, no cookies, no headers:

```
GET /                                      -> 302 /login?next=%2F
GET /api/status                            -> 403
GET /api/kernelspecs                       -> 403
GET /mercury/api/notebooks                 -> 302 /login
GET /api/contents/secrets.ipynb            -> 200
GET /api/contents/team/secrets.ipynb       -> 200
GET /api/contents/.ipynb_checkpoints/secrets-checkpoint.ipynb -> 200
```

The 200 bodies carry the cells verbatim. In the lab notebook that meant a literal `DB_PASSWORD = "Pr0d-S3cret-9911"` in a cell. Password mode behaves the same as token mode.

Controls from the same run:

- `GET /api/contents/../../etc/passwd.ipynb` returns 404, so the path stays inside the contents root.
- `GET /api/contents/<nb>.ipynb/checkpoints` returns 403, the decorated handler.
- `PATCH`, `POST` and `DELETE` on the same path return 403; `PUT` returns the model without persisting the submitted body.

Version sweep, standalone mode, anonymous requests:

| Version | `/api/status` | `/api/contents/<nb>.ipynb` |
|---|---|---|
| 3.2.3 | 403 | 200 |
| 3.2.4 | 403 | 200 |
| 3.2.6 | 403 | 200 |
| 3.2.11 | 403 | 200 |

Master `a01ba07` still had the undecorated handler when the report was filed.

One correction worth recording: an earlier draft of my report claimed saved cell outputs were exposed too. They are not. Mercury masks outputs in the model it serves (`sanitize_notebook_for_mercury_runtime` clears `outputs`), so the exposure is source and markdown. The filed report rests on source only.

## Impact

Any host that can reach the port reads the source of every notebook under the contents root, including nested directories and the hidden checkpoint directory, on a server the operator believes is protected by a token or a password.

CVSS 3.1: 7.5 High, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`, CWE-306. If a deployment treats notebook source as non-sensitive the score drops, but the vendor ships authentication specifically for this content, which is what fixes the weighting.

## Fix

Mercury 3.2.12 restores `@web.authenticated` and `@authorized` on both methods. The advisory also names the interim mitigation for protected deployments: set `ServerApp.allow_unauthenticated_access=False`, which closes this path independently of the handler fix.

For anyone running an affected version: upgrade to 3.2.13 or later, restart the server, and rebuild runtime images, because the fix lives in the serving layer, not in the notebooks.

## Credit and advisory

I filed this on 2026-10-20 as GHSA-64p3-m5fp-mcmj. The maintainers received several reports of the same handler defect and consolidated them into GHSA-w823-3v59-v22p, published 2026-10-26, with the reporters' credits retained on the combined advisory. The fixed release is 3.2.12, and the advisory records the same root cause described here: a contents handler that omitted the authentication and authorization checks on GET and PUT.
