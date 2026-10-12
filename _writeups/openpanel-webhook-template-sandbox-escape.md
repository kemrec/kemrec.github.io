---
title: "OpenPanel: Webhook Template Sandbox Escape via an Aliased Function Constructor"
date: 2026-10-11
target: "Openpanel-dev/openpanel"
severity: Critical
identifier: "GHSA-mc99-9jf5-22cq"
advisory_url: "https://github.com/Openpanel-dev/openpanel/security/advisories/GHSA-mc99-9jf5-22cq"
summary: "OpenPanel's webhook JavaScript-template validator checked call targets and assignment targets but never plain reads — `const F = payload.constructor.constructor` copied the real Function constructor into a local and called it, executing arbitrary code in the worker process that holds the platform's database, ClickHouse, Redis and integration credentials. Fixed upstream in PR #510 (2026-09-22)."
---

## Summary

OpenPanel lets a project member attach a JavaScript template to a webhook
integration (`mode: 'javascript'` + `javascriptTemplate`). The template is
checked by an AST allowlist (`validate()` in
`packages/js-runtime/src/validate.ts`) and then compiled with `new Function()`
in the **worker process** (`packages/js-runtime/src/execute.ts`) — the same
process that holds the database, ClickHouse, Redis and every third-party
integration credential the deployment has.

The validator only ever inspected two kinds of nodes: call targets and
assignment/update targets. A plain **read** of a forbidden property was
neither, so a template could copy `payload.constructor.constructor` — the real
`Function` constructor — into a local, and call the local. The call is no
longer a member expression, so the "only allowlisted methods" check never
runs, and the returned function is evaluated in global scope with the worker's
privileges:

```js
(payload) => { const F = payload.constructor.constructor; return F('return 1')(); }
```

`validate()` returns `{ valid: true }` for this and five more spellings of the
same idea — including payload-independent ones like
`[].filter.constructor` — and `execute()` compiles whatever the validator
accepts. Arbitrary JavaScript, hence arbitrary commands, in the process that
holds all the platform's secrets.

## Background

OpenPanel is a self-hosted analytics platform. Webhook integrations support a
JavaScript "transform" mode: a project member writes an arrow function that
receives the event payload and returns the body to POST to the webhook URL.
Those templates are stored in the database and executed by `apps/worker` when
a notification rule attached to the integration fires.

Because the template is arbitrary JavaScript, the project runs it through a
hand-written validator first. `validate()` parses the source with `@babel/parser`
and walks the AST, refusing the constructs it knows about — and the codebase
documents the assumption that makes the whole design work:

```ts
// packages/js-runtime/src/validate.ts:353-355
// Block writes that reach the prototype chain: payload.__proto__.x = 1,
// payload['constructor'].prototype.y = 2. Reading these is already
// handled by the call and 'new' checks above.
```

"Handled by the call checks" only holds when the read and the call are the
*same AST node*. They are not, in any of the forms below.

## The vulnerability

The checks live in two places, and both are keyed on the *shape* of a node
rather than on the value being reached:

1. **Call targets** (`validate.ts:276-331`). The block only runs when
   `callee.type` is `MemberExpression` / `OptionalMemberExpression`. Any other
   callee shape — an identifier bound to a local, a sequence expression
   (`(0, x)(…)`), a call of a call (`x('…')()`) — is not inspected at all.
   When it *is* a member expression, the only thing that can reject
   `.constructor` is the `ALLOWED_INSTANCE_METHODS` list, and only for the
   final property of the callee.
2. **Assignment/update targets** (`validate.ts:356-366`). This walks the chain
   and rejects `__proto__` / `constructor` / `prototype` — but only on the
   left-hand side of an assignment or update.

A read (`const F = payload.constructor.constructor;`) is neither, so no rule
applies to it. Reading `.constructor` off a plain object yields `Object`; off
`Object` it yields `Function`. The previous validator fix — the one for
computed member access on a call target (CVE-2026-93985, commit `e6339b3`) —
added the computed-key rejection, a `new`-target shape check, and prototype
*writes*, but no rule for a plain member read, so this path was untouched by
it. And `execute()`'s runtime re-validation cannot catch it either: it runs
the *same* `validate()`, which accepts the template.

Six independent spellings of the escape were accepted by the validator:

```js
// 1. aliased read of .constructor
(payload) => { const F = payload.constructor.constructor; return F('return 1')(); }

// 2. sequence-expression callee (callee is not a member expression)
(payload) => (0, payload.constructor.constructor)('return 1')()

// 3. read off an allowlisted instance method
(payload) => { const F = payload.hasOwnProperty.constructor; return F('return 1')(); }

// 4. read off an allowlisted global's method
(payload) => { const F = JSON.parse.constructor; return F('return 1')(); }

// 5. read via destructuring (ObjectPattern keys are skipped)
(payload) => { const { constructor: O } = payload; const F = O.constructor; return F('return 1')(); }

// 6. read off an array literal — needs no payload cooperation at all
(payload) => { const F = [].filter.constructor; return F('return process.version')(); }
```

The forms the validator is *supposed* to refuse stayed refused in the same
run — computed call targets (the form CVE-2026-93985 fixed), direct member
calls on `.constructor`, `new` on a non-identifier callee, dynamic `import()`
and `__proto__` writes — so the escape is a gap in the rule set, not a defect
in the checks that did run.

## Verifying it

The templates above were run through the real `validate()` and `execute()`
bundled verbatim from the repository at the tested revision (`61a92453`,
2026-09-18): the five documented-refused forms are refused (negative
control), all six aliased-constructor forms are accepted, and `execute()` on
the accepted template runs a real shell command in the host process and reads
the worker's environment from inside the template — with an empty payload
object, for the array-literal spelling. The same `execute()` is what
`apps/worker` calls for a stored template, so the process that runs it in
production is the one holding the deployment's credentials.

## Impact

The precondition is a project member with `write` — the lowest role that can
configure an integration — on any project of a self-hosted instance. From
there: arbitrary code execution in the worker process. That process holds the
platform database (all tenants' projects, events, users, and the encrypted
integration credentials it decrypts itself), ClickHouse, Redis, the
object-store credentials, and outbound network access from inside the
deployment. Because this is code execution in a shared process rather than a
data-scoping bug, the impact applies to the whole deployment, not just the
attacker's project — which is why the advisory's vector carries `S:C`:
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` = **9.9 Critical**.

## The fix

Fixed upstream on 2026-09-22 in PR #510 (commit `42fc8623b5`). The fix does
two things, and the second is the more interesting one:

1. **The validator became a default-deny allowlist of AST node types.**
   Anything not on the list is refused — tagged templates, sequence
   expressions, `switch`, labels, `var`, `++`, `delete`, computed keys,
   object methods. Reads of `constructor` / `__proto__` / `prototype` /
   `caller` / `callee` are refused everywhere, including destructuring
   patterns; dynamic computed keys (`obj[expr]`) are refused so a forbidden
   name cannot be assembled at runtime; callees are limited to plain
   identifiers, member expressions and inline arrows; assignments must be
   rooted at local variables. What remains is deliberately small — object and
   array literals, literal-key property access, template strings, ternaries,
   arithmetic and the allowlisted built-ins — and the project put every
   template currently saved in production into the test suite as fixtures.
2. **`execute()` now runs the template in a fresh V8 context** via
   `node:vm`'s `runInNewContext`, with `eval` and `new Function` disabled in
   that context, a 250 ms timeout and a 1 MB output cap. The payload crosses
   in as JSON and the result crosses out as JSON, so a template never holds a
   reference to a host-realm object:

```ts
const script = `'use strict'; JSON.stringify((${code})(JSON.parse(payloadJson)));`;
const resultJson = runInNewContext(
  script,
  { payloadJson: JSON.stringify(payload) },
  {
    timeout: EXECUTION_TIMEOUT_MS,          // 250
    contextCodeGeneration: { strings: false, wasm: false },
    microtaskMode: 'afterEvaluate',
  },
);
```

The commit describes the second layer honestly: it is defense in depth behind
the validator, not a boundary on its own — the point is that a future
validator miss lands in an empty realm instead of the worker process. An AST
allowlist over attacker-supplied source is a losing game in general; a real
isolation boundary (a separate isolate or process) is what makes the first
layer's occasional miss survivable.

## Timeline

- **2026-01-23** — JavaScript webhook templates introduced (commit `286f8e16`).
- **2026-09-04** — previous validator fix for computed member access on a
  call target (CVE-2026-93985, commit `e6339b3`); the read path stays open.
- **2026-09-20** — Reported via GitHub's private vulnerability reporting.
- **2026-09-22** — Fixed upstream: PR #510, commit `42fc8623b5`.
- **2026-10-11** — Advisory published as `GHSA-mc99-9jf5-22cq`, Critical
  (CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` = 9.9, CWE-94). OpenPanel
  publishes no versioned releases (GHCR images with a rolling tag), so the
  fix is in every image build after `42fc8623b5`.

## Disclosure

Full advisory: [GHSA-mc99-9jf5-22cq](https://github.com/Openpanel-dev/openpanel/security/advisories/GHSA-mc99-9jf5-22cq)
(published 2026-10-11; Critical; no CVE assigned). The fix is [PR #510](https://github.com/openpanel-dev/openpanel/pull/510)
(commit `42fc8623b5`). This writeup describes behavior verified against the
repository at the tested revision (`61a92453`) and the fix as merged in PR #510.
