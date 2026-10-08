---
title: "agent-framework: The Sensitivity Guard Covered Every Parameter but the Conversation ID"
date: 2026-10-07
target: "microsoft/agent-framework"
severity: Medium
identifier: "PR #9071"
advisory_url: "https://github.com/microsoft/agent-framework/pull/9071"
summary: "The declarative-workflow runtime tags environment-scoped values as Sensitive and blocks them from every external-call parameter it evaluates — except conversationId, which every conversation-aware executor forwarded unvalidated, putting the protected value on the wire to the agent service. Microsoft assessed it as defense-in-depth and did not service it as a vulnerability; engineering fixed the coverage gap anyway (PR #9071)."
---

## Summary

`Microsoft.Agents.AI.Workflows.Declarative` implements a protected-value
control for declarative agent workflows: values assigned from the
`Environment` scope carry `SensitivityLevel.Sensitive`, and every executor
that evaluates an expression destined for an external call checks the
evaluated result's `Sensitivity` before transmitting. The check covers the
parameters of those calls one by one — agent name and version, structured
inputs, input messages, function names and arguments, MCP server URLs/labels/
tool names/arguments/headers, HTTP methods/URLs/headers/bodies — except
`conversationId`, which every conversation-aware executor evaluates through
the same expression engine and forwards unchecked.

The value is not merely a local identifier. The shipped Foundry provider puts
it on the wire: as `ChatOptions.ConversationId` inside the streaming agent
request, and as the target conversation of
`CreateProjectConversationItemsAsync` message writes. A workflow author who
references an `Env`-scoped value in a `conversationId` expression therefore
causes that value to be transmitted to the configured agent service — the
exact transmission the guard on every neighboring parameter exists to
prevent. The omission applied equally to the `connectionName` parameter of
the MCP and HTTP actions.

The coverage gap was reported to Microsoft on 2026-09-30 and fixed upstream
as PR #9071 ("Reject sensitive declarative identifiers"), which routes
`conversationId`, `connectionName` and the conversation-retrieval
identifiers through a single checked accessor in the executor base class.

## Background

Declarative workflows let an application describe an agent orchestration in
YAML and run it through `Microsoft.Agents.AI.Workflows.Declarative`. Workflow
expressions evaluate in a scoped engine: values from the workflow's own state
are ordinary, while values provided by the host under the `Environment` scope
— connection strings, keys, host configuration — are tagged
`SensitivityLevel.Sensitive`.

The guard built on those tags is deliberate: an executor that would hand an
evaluated value to an external system throws rather than transmit when the
value is sensitive. The guard had been extended over several rounds during
September 2026 as sibling omissions were closed in the HTTP request
executor, the MCP tool executor, and the invocation executors — in each
round, the fix added checks to the parameters that particular investigation
had identified. The mechanism is a per-parameter hand enumeration, and that
is where coverage gaps live.

## The gap

Each executor evaluates `conversationId` through the same `Evaluator.GetValue`
call that computes `Sensitivity`, and simply never looks at it:

```csharp
private string? GetConversationId()
{
    if (this.Model.ConversationId is null)
    {
        return null;
    }

    // Evaluated through the same engine as every guarded parameter below…
    string conversationId = this.Evaluator.GetValue(this.Model.ConversationId).Value;

    // …but .Sensitivity is never inspected before the value is returned.
    return conversationId;
}
```

Compare the sibling parameter in the same file, which captures the
`EvaluationResult` and refuses sensitive values:

```csharp
// agent name — guarded
EvaluationResult<string> result = this.Evaluator.GetValue(this.Model.AgentName);
if (result.Sensitivity == SensitivityLevel.Sensitive)
{
    throw new DeclarativeActionException("Cannot send sensitive agent name ...");
}
```

The same unguarded `GetConversationId()` pattern existed in six executors —
`InvokeAzureAgent`, `InvokeFunctionTool`, `InvokeMcpTool`, `HttpRequest`,
`AddConversationMessage`, `CopyConversationMessages` — plus `GetConnectionName()`
in the MCP and HTTP executors. The consumed value flows straight into the
provider boundary (`agentProvider.InvokeAgentAsync(..., conversationId, ...)`
and `agentProvider.CreateMessageAsync(conversationId, ...)`), which, with the
shipped Foundry provider, is on the wire.

## Verifying it

The differential was straightforward because the control next door is exact:
a sensitive `Env` value placed in `agentName` throws
("Cannot send sensitive agent name") before the provider is invoked; the same
value placed in `conversationId` reaches the provider unchanged — verified
with the provider boundary mocked, asserting on the value the executor passes
it. A battery of 23 expression shapes that reference the protected value
(records, tables, lambdas, interpolations, field access) were all blocked in
function arguments, confirming the expression walker itself was thorough —
the gap was in which parameters were routed through it, not in the analysis.

After the fix, the same two probes flip: the former leak cases now throw
`Cannot use a sensitive value for conversation ID in InvokeAzureAgent` /
`... in InvokeFunctionTool`, and the controls (including the vendor's own
sensitive-value test suite) pass unchanged. The same differential was re-run
against the published `1.24.0` package before this writeup went up — same
results.

## Impact

Scope, stated plainly: the value is transmitted to the application's own
configured agent service — not to an author-chosen host, and no cross-tenant
reads are claimed. The precondition is a deployment that treats workflow
authorship as a lower-trust role than environment/secret configuration —
which is the separation the sensitivity control exists to implement. Under
that model, a workflow author can cause host-scoped values to be sent to the
agent service as conversation identifiers, outside the boundary the guard
family enforces on every adjacent parameter, leaking them into service-side
request handling, logs and telemetry. CVSS 3.1 on that reading is
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5.

Microsoft reviewed the report and assessed that the workflow author and the
party configuring environment values are the same trust principal, and that
the value is only sent to the operator-configured agent service — so no
security boundary established for the feature is crossed, and the case was
not serviced as a vulnerability. The engineering team nonetheless adopted a
fix days later; read this post as a coverage study of a defense-in-depth
control, not as a serviced CVE.

## The fix

PR #9071 adds a single checked accessor to the executor base class:

```csharp
protected T GetNonSensitiveValue<T>(EvaluationResult<T> result, string location)
{
    if (result.Sensitivity == SensitivityLevel.Sensitive)
    {
        throw new DeclarativeActionException(
            $"Cannot use a sensitive value for {location} in {this.Model.GetType().Name} [{this.Id}].");
    }

    return result.Value;
}
```

and routes **every reported site** through it — all six `conversationId`
sites and both `connectionName` sites — plus four additional sites the fix
author identified in the conversation-retrieval executors (`conversationId`,
`messageId`, message expression, cursor), with unit tests per executor
(~630 lines of tests). The base-class helper means future executors get the
check by construction instead of by enumeration.

## Timeline

- 2026-09-23 → 2026-09-29 — sibling coverage gaps in the same guard family
  closed in earlier rounds (HTTP request `#8797`, MCP tool `#8832`, and the
  invocation-parameter wave).
- 2026-09-30 — reported to Microsoft with a differential test harness.
- 2026-10-06 — Microsoft: not serviced as a vulnerability (same trust
  principal; operator-configured destination). Same day, engineering merged
  PR #9071 fixing the coverage gap.
- 2026-10-07 — fix released in `Microsoft.Agents.AI.Workflows.Declarative`
  1.24.0 (NuGet); re-verified against the released package.

## Disclosure

No advisory or CVE was issued for this report. The public record is the
upstream fix: [PR #9071](https://github.com/microsoft/agent-framework/pull/9071)
(commit `0774607d8d`). This writeup describes behavior verified against the
repository at both the pre-fix (`1a03705a`) and fixed (`0774607d`) revisions,
and re-verified against the published `1.24.0` package.
