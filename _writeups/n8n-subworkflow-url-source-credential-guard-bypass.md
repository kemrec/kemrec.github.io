---
title: "n8n: Execute Sub-workflow URL Sources Bypass the Shared-Workflow Credential Guard"
date: 2026-10-14
target: "n8n-io/n8n (Execute Sub-workflow node)"
severity: Medium
identifier: "GHSA-8crx-5h96-q72q"
advisory_url: "https://github.com/n8n-io/n8n/security/advisories/GHSA-8crx-5h96-q72q"
summary: "n8n's save-time credential guard for shared workflows inspects what a node contains. An Execute Sub-workflow node that loads its content from a URL or a local file contains nothing to inspect, so it passes untouched, and the fetched document's credential references resolve in the shared workflow's project at run time. Fixed in 1.123.85, 2.43.5 and 2.44.1 by refusing uninspectable sources for editors without full credential access."
---

## Summary

When a workflow is shared for editing, n8n runs a save-time guard: an editor
without access to the workflow's credentials must not be able to make the
workflow use credentials they cannot use. The guard works by walking each
submitted node for credential references. It walks the node's own
`credentials`, an inline `workflowJson` string, and an inline agent config.

An Execute Sub-workflow node configured with `source: url` or
`source: localFile` has none of those. Its content arrives from an
attacker-controlled URL or file at execution time, so at save time there is
nothing to walk. The guard reports zero references for the node, the save is
accepted, and at run time the fetched document executes like any
code-sourced sub-workflow: its credential references resolve in the parent
workflow's project context, and the decrypted values flow to whoever
authored the fetched document.

Fixed in n8n 1.123.85, 2.43.5 and 2.44.1 (GHSA-8crx-5h96-q72q).

## Background

n8n lets a workflow be shared with other users for editing. The share does
not include credentials, so the platform has to stop an editor from wiring
up credentials they cannot use. That check lives in the enterprise workflow
service and has been hardened three times before this report:

- GHSA-cj9h-qx8g-pq2g: the guard originally missed some node shapes.
- GHSA-r6g9-5cpp-ppwr: renamed nodes and mismatched references slipped past.
- GHSA-x25p-9mr6-cwgp: an expression-valued credential slot changed which
  credentials get checked.

Each fix extended the walk. The walk still starts from what the submitted
node *contains*: the node's `credentials` object, and for the three
workflow-selector node types (`executeWorkflow`, the Workflow Tool, and the
Workflow Retriever), an inline `workflowJson` string. The `source` parameter
of the Execute Sub-workflow node was never consulted.

## The vulnerability

The Execute Sub-workflow node can load its sub-workflow from four sources.
Two are inspectable at save time: `database` (a stored workflow) and
`parameter` (inline JSON in the node). Two are not:

```typescript
// packages/nodes-base/nodes/ExecuteWorkflow/.../GenericFunctions.ts
} else if (source === 'url') {
    // fetch the document at execution time
} else if (source === 'localFile') {
    // read the document at execution time
}
```

The runtime dispatches purely on the parameter value. There is no version
gate. The node UI stopped offering `url` and `localFile` for newer type
versions, but the runtime honors the value regardless, and workflow writes
do not schema-restrict node parameters, so a crafted save reaches it.

The guard never sees the document. Its per-node predicate returns
`{ ids: [], hasUnresolved: false }` for a `source: url` node, exactly as it
would for a node with no credentials at all. The same foreign credential
reference is flagged the moment it sits in `node.credentials` or in an
inline `workflowJson`, which shows the walk itself works and only the
runtime-fetched forms are invisible.

At execution the fetched document runs like any code-sourced sub-workflow.
Its credential references resolve in the parent workflow's project, which is
the cross-access the earlier fixes exist to prevent.

## Live verification

Verified on the stock `n8nio/n8n:2.42.1` image (digest
`sha256:e7634e62f766044dc770460db8defdcd84034eb6d767dd6a1101d49fe98f814f`),
no modifications. Two halves:

**(1) The shipped guard reports zero references for url/localFile nodes.**
The compiled `dist/workflows/workflow.service.ee.js` was imported inside the
container and the exact per-node predicate the save-time guard uses
(`getNodesWithInaccessibleCreds`) was called on four crafted workflows, with
the editor's accessible credentials limited to one:

```
W1 url-source (attack)         | flagged: [] | refs: {"ids":[],"hasUnresolved":false}
W2 localFile-source            | flagged: [] | refs: {"ids":[],"hasUnresolved":false}
W3 inline workflowJson (ctl)   | flagged: [ 'InlineSub' ] | refs: {"ids":["FOREIGN-CRED-INLINE"],"hasUnresolved":false}
W4 plain foreign cred (ctl)    | flagged: [ 'Plain' ] | refs: {"ids":["FOREIGN-CRED-2"],"hasUnresolved":false}
```

**(2) The channel executes and resolves.** A member's workflow (Webhook,
then Execute Sub-workflow with `source: url`) fetched the served document
(`User-Agent: n8n`), executed it, and the credential reference inside the
fetched document resolved in the parent context. The listener recorded the
outbound request carrying the credential header:

```
--- GET /collect-a from 127.0.0.1
    X-Lab-Secret: SECRET-R6G9-M2
    User-Agent: n8n
```

With the fetched document also supplying an `id` and
`"settings": {"callerPolicy": "any"}`, the full chain completed on stock
2.42.1: the sub-execution ran under the parent workflow's id and the owner
project's credential was decrypted and used for the outbound request. The
id and policy handling is a separate, earlier report (GHSA-866p-xg8v-g2q7);
the new element here is the delivery channel and the guard blind spot.

## Impact

An editor of a shared workflow, with no access to its credentials, can have
those credentials resolved and used by a document they serve. The decrypted
values reach attacker-controlled infrastructure through a node the fetched
document contains. The bar is an ordinary member account with editor access
to a shared workflow, which is the premise the guard family's advisories
already use.

## The fix

n8n 1.123.85, 2.43.5 and 2.44.1 add the missing axis to the guard. Saves by
a user who can use every credential behave as before. For everyone else:

- Nodes whose sub-workflow source cannot be inspected (`url`, `localFile`,
  or any value outside the known set) are refused with
  `UninspectableSubworkflowSourceError`.
- The restore path for read-only nodes compares the submitted node against
  the stored one through a normalized definition (the same fields the editor
  can freely edit are excluded), and rejects the save instead of silently
  discarding changes when a blocked-source node was edited.
- The create path runs the same check, so the channel cannot be opened at
  creation time either.

## References

- [GHSA-8crx-5h96-q72q](https://github.com/n8n-io/n8n/security/advisories/GHSA-8crx-5h96-q72q)
- [GHSA-cj9h-qx8g-pq2g](https://github.com/n8n-io/n8n/security/advisories/GHSA-cj9h-qx8g-pq2g), [GHSA-r6g9-5cpp-ppwr](https://github.com/n8n-io/n8n/security/advisories/GHSA-r6g9-5cpp-ppwr), [GHSA-x25p-9mr6-cwgp](https://github.com/n8n-io/n8n/security/advisories/GHSA-x25p-9mr6-cwgp): earlier fixes on the same guard
- [GHSA-866p-xg8v-g2q7](https://github.com/n8n-io/n8n/security/advisories/GHSA-866p-xg8v-g2q7): the id and policy handling for code-sourced sub-workflows
