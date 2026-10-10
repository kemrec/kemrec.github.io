---
title: "agent-framework: The Sensitivity Guard Was Missing From the MCP Tool Executor"
date: 2026-10-07
target: "microsoft/agent-framework"
severity: High
identifier: "GHSA-9f26-7mqc-9vc4"
advisory_url: "https://github.com/microsoft/agent-framework/security/advisories/GHSA-9f26-7mqc-9vc4"
summary: "The declarative-workflow runtime tags environment-scoped values as Sensitive and blocks them from every external call it evaluates — but the MCP tool executor read its server URL, tool name, arguments and transport headers through the same expression engine without ever checking, so a workflow could forward a host secret to an MCP server of its choosing. Fixed upstream the day after the report (PR #8832); released in 1.24.0."
---

## Summary

`Microsoft.Agents.AI.Workflows.Declarative` implements a protected-value
control for declarative agent workflows: values assigned from the
`Environment` scope carry `SensitivityLevel.Sensitive`, and every executor
that evaluates an expression destined for an external call checks the
evaluated result's `Sensitivity` before transmitting. By late September 2026
that check covered seven executors, and the HTTP request executor had just
been added as an eighth.

The MCP tool executor — the action that invokes tools on a remote MCP
server — was not in the set. `InvokeMcpToolExecutor` evaluates its server
URL, server label, tool name, arguments and transport headers through the
same engine that computes the sensitivity tag, and uses only the value. A
workflow whose MCP argument or transport header referenced an `Env`-scoped
value therefore forwarded that value — no exception, no redaction — to the
MCP server the workflow itself named: the exact transmission the neighboring
checks exist to prevent, headed off-host.

The gap was reported to Microsoft on 2026-09-28 and fixed upstream the next
day as PR #8832 ("Reject protected values in declarative MCP invocations"),
which routes all five read sites through a checked accessor. The fix shipped
in `Microsoft.Agents.AI.Workflows.Declarative` 1.24.0; the advisory is
[GHSA-9f26-7mqc-9vc4](https://github.com/microsoft/agent-framework/security/advisories/GHSA-9f26-7mqc-9vc4).

## Background

Declarative workflows let an application describe an agent orchestration in
YAML and run it through `Microsoft.Agents.AI.Workflows.Declarative`. Workflow
expressions evaluate in a scoped engine: values from the workflow's own state
are ordinary, while values provided by the host under the `Environment` scope
— connection strings, keys, host configuration — are tagged
`SensitivityLevel.Sensitive`.

The guard built on those tags is deliberate: an executor that would hand an
evaluated value to an external system throws rather than transmit when the
value is sensitive. The guard was extended round by round during September
2026, and in each round the fix added checks to the parameters that the
particular investigation had identified — the HTTP request executor received
its gate on 2026-09-28. The mechanism is a per-site hand enumeration, and
that is where coverage gaps live. This report's gap was found while auditing
the coverage of that day's HTTP request gate.

## The gap

Every expression input of `InvokeMcpToolExecutor` goes through the same
`Evaluator.GetValue` call that computes `Sensitivity`; the executor kept the
value and discarded the tag. `grep -n "Sensitiv" InvokeMcpToolExecutor.cs`
returned zero hits — no check anywhere in the file:

```csharp
// GetArguments(): the evaluated value is stored…
result[argument.Key] = this.Evaluator.GetValue(argument.Value).Value.ToObject();

// GetHeaders(): …and the evaluated header string is returned…
string value = this.Evaluator.GetValue(header.Value).Value;

// …with .Sensitivity never inspected on either path.
```

The evaluated values go straight to `mcpToolHandler.InvokeToolAsync(...)`,
and the shipped `DefaultMcpToolHandler` puts them on the network: the
evaluated headers become the MCP transport's `AdditionalHeaders` and the
evaluated `serverUrl` is called over Streamable HTTP. The destination — the
MCP server — is named by the workflow definition itself.

Compare the executor that had received its gate the same day the audit
started: `HttpRequestExecutor.GetRequestValue()` throws `Cannot use a
protected value in HTTP request {location}.` for every request field it
evaluates. The MCP tool invocation — also an outbound path, and one to a
workflow-selected destination — had no such check at all.

## Verifying it

The differential was straightforward because the control next door is
exact: a sensitive `Env` value placed in a guarded parameter throws before
the handler is invoked; the same value in an MCP argument or transport
header was forwarded. With the MCP handler boundary mocked, a small test
file added to the repository's own test project (product source unmodified)
showed the mocked handler receiving the protected value in both the argument
(`query`) and the transport header (`X-Custom`), while the identical
construction against `HttpRequestExecutor` threw and never invoked its
handler — proving both directions on the repo's own harness.

After the fix, an 18-shape expression battery run through the real executor
— direct references, concatenation, string interpolation, record and table
literals, index access, lambdas, field access, `With` bindings — blocks
every leak-capable shape (16/16 executable), while the pre-fix arm forwards
them with the secret inside: the guard is the exact delta. The same
differential was re-run against the published `1.24.0` package before this
writeup went up — the former leak case now throws `Cannot use a protected
value in MCP tool invocation argument 'query'.`, and the vendor's own
sensitive-value tests pass.

## Impact

Scope, stated plainly: the value is transmitted to an MCP server the
workflow itself selects — an author-chosen destination, over the network.
No cross-tenant reads are claimed. The precondition is a deployment that
treats workflow authorship as a lower-trust role than environment/secret
configuration — the separation this control exists to implement. CVSS 3.1 on
that reading is `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 7.5.

Microsoft's servicing review assessed that a declarative workflow definition
is treated as trusted input — the author is considered to be operating
inside the application's trust boundary — and that the sensitivity handling
on this tool-invocation path is a defense-in-depth measure rather than a
security guarantee, so the case was not serviced as a vulnerability. The
engineering fix and the advisory landed through the project's own process
regardless; read this post as a coverage study of the guard family, not as a
serviced CVE.

## The fix

PR #8832 adds a single checked accessor and routes all five read sites
through it:

```csharp
private T GetInvocationValue<T>(EvaluationResult<T> result, string location)
{
    if (result.Sensitivity == SensitivityLevel.Sensitive)
    {
        throw this.Exception($"Cannot use a protected value in MCP tool invocation {location}.");
    }

    return result.Value;
}
```

applied to the server URL, server label, tool name, every argument
(`argument '{key}'`) and every transport header (`header '{key}'`) — in both
direct and approval-based execution, with regression tests over all five
locations across the two execution modes.

## Timeline

- 2026-09-23 — protected-value guard introduced across the original seven
  executors (commit `0bbb7245d4`).
- 2026-09-28 — HTTP request executor gate lands (PR #8797, commit
  `0d6d2bb6b0`); auditing its coverage exposed the MCP tool executor,
  reported to Microsoft the same day.
- 2026-09-29 — fixed upstream: PR #8832 (commit `ba320332d4`).
- 2026-10-07 — advisory GHSA-9f26-7mqc-9vc4 published (High; no CVE); fix
  released in `Microsoft.Agents.AI.Workflows.Declarative` 1.24.0 and
  re-verified against the published package.

## Disclosure

The finding is public as [GHSA-9f26-7mqc-9vc4](https://github.com/microsoft/agent-framework/security/advisories/GHSA-9f26-7mqc-9vc4)
(published 2026-10-07; High; no CVE), the fix as [PR #8832](https://github.com/microsoft/agent-framework/pull/8832)
(commit `ba320332d4`). This writeup describes behavior verified against the
repository at the pre-fix (`f47c3782`) and fixed (`ba320332d4`) revisions,
and re-verified against the published `1.24.0` package.
