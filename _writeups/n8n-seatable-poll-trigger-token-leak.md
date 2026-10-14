---
title: "n8n: SeaTable Poll-Trigger Error Data Leaks the Plaintext API Token"
date: 2026-10-14
target: "n8n-io/n8n (SeaTable node, v1 and v2)"
severity: Medium
identifier: "GHSA-crfj-5wv6-8v86"
advisory_url: "https://github.com/n8n-io/n8n/security/advisories/GHSA-crfj-5wv6-8v86"
summary: "The SeaTable node's access-token helper called the raw HTTP helper with the API token in an Authorization header and no error wrapping. When the poll trigger's token request failed, the raw error, headers included, was persisted verbatim into the error execution. Any user who can read the workflow's executions, but not the credential, could recover the token. Fixed in 1.123.85, 2.43.5 and 2.44.1."
---

## Summary

SeaTable poll triggers request a base access token with the credential's API
token in an `Authorization` header. That request is made through the raw
`this.helpers.request` / `this.helpers.httpRequest` primitives with no
try/catch. When the request fails, the raw HTTP error travels through the
poll scheduler's error path, which persists it verbatim. The error object
carries the original request config, headers included, so the plaintext
token lands in the error execution record.

Execution read access is a much lower bar than credential read access. Any
user who can view the workflow's executions can pull the record through the
standard executions API and use the token directly against the linked
SeaTable base.

Fixed in n8n 1.123.85, 2.43.5 and 2.44.1 (GHSA-crfj-5wv6-8v86).

## Background

n8n had already fixed one instance of this class. GHSA-vrv8-j27g-g7cr
covered Strapi, SeaTable and Mailcheck nodes leaking decrypted credential
secrets into persisted execution error data. That fix added
`normalizeUnhandledAxiosError()` in `packages/core/src/execution-engine/workflow-execute.ts`,
which wraps an unhandled raw `AxiosError` into a `NodeApiError` before it is
persisted. It covers the regular node-execution catch path only.

The SeaTable poll trigger's failure path is entirely separate, and it never
touches that wrapper.

## The vulnerability

`getBaseAccessToken()` mints the SeaTable API session token and runs at the
start of every SeaTable API request, including from the poll trigger's
`poll()`:

```typescript
// packages/nodes-base/nodes/SeaTable/v1/GenericFunctions.ts
export async function getBaseAccessToken(this, ctx) {
	if (ctx?.base?.access_token !== undefined) return;
	const options: IRequestOptions = {
		headers: { Authorization: `Token ${ctx?.credentials?.token}` },
		uri: `${resolveBaseUri(ctx)}/api/v2.1/dtable/app-access-token/`,
		json: true,
	};
	ctx.base = await this.helpers.request(options);   // no try/catch
}
```

The v2 helper is the same shape with `this.helpers.httpRequest`. Both are
the raw, unwrapped primitives; neither ever wraps a failure into a
`NodeApiError`. The node's own `seaTableApiRequest()`, used for regular data
operations, wraps the identical call correctly. `getBaseAccessToken()` alone
is missing the wrapper, in both node versions.

The failure path:

1. The poll task handler catches the thrown error and calls
   `pollFunctions.__emitError(ensureError(error))`.
2. `ensureError()` only checks `instanceof Error` and passes the
   `AxiosError` straight through, unchanged.
3. `recordTriggerFailure()` creates an error execution, and
   `createErrorExecutionData()` stores the error verbatim into
   `resultData.error` and the node's run data, with no redaction.

The persisted error carries the request config, and the request config
carries the `Authorization` header.

## Proof of concept

Reproduced with the exact axios version n8n pins (1.18.0), against a local
server returning 401, replicating the helper's request shape:

```
error.config.headers.Authorization: "Token sec-real-seatable-api-token-DO-NOT-LEAK-abc123"
```

The rejected promise is a real `AxiosError` (`isAxiosError: true`,
`instanceof Error: true`) whose `.config.headers` retains the full header.
That is exactly what `ensureError()` passes through and what the error
execution factory persists.

## Impact

Any SeaTable poll-trigger workflow whose token later becomes invalid (natural
expiry, revocation, or an attacker briefly overwriting the credential and
reverting it) produces an error execution containing the plaintext token. A
user with execution read access recovers it via the executions API and can
read or modify whatever the linked SeaTable base contains, for as long as
the token stays valid.

## The fix

Wrap the helper call in `getBaseAccessToken()` in try/catch and rethrow via
`NodeApiError`, exactly like the node's own `seaTableApiRequest()` already
does, in both v1 and v2. n8n 1.123.85, 2.43.5 and 2.44.1 carry that change.

## References

- [GHSA-crfj-5wv6-8v86](https://github.com/n8n-io/n8n/security/advisories/GHSA-crfj-5wv6-8v86)
- [GHSA-vrv8-j27g-g7cr](https://github.com/n8n-io/n8n/security/advisories/GHSA-vrv8-j27g-g7cr): the earlier fix for the same class in the regular execution path
