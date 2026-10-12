---
title: "ToolHive: Host-Gateway Blocklist Keyed on the Wrong Docker Network"
date: 2026-10-12
target: "stacklok/toolhive"
severity: Medium
identifier: "GHSA-hfmx-2rf9-m35g"
advisory_url: "https://github.com/stacklok/toolhive/security/advisories/GHSA-hfmx-2rf9-m35g"
summary: "ToolHive's HTTP(S) egress proxies blocked exactly one host-gateway address — the gateway of Docker's default `bridge` network — while isolated MCP workloads live on their own per-server and shared bridge networks, whose gateways Docker assigns independently. The isolation policy denied an address the workload did not need and left open the one it does use to reach host services. Fixed in v0.52.0 by snapshotting every Docker bridge gateway at deployment time; published as a joint advisory crediting this report and one other."
---

## Summary

ToolHive runs MCP servers as containers with network isolation on by default. The
isolation has two halves: the workload sits on a Docker bridge network, and its
HTTP(S) traffic is forced through an egress proxy (Squid or Envoy) that denies
requests to the host gateway. The second half is what stops an isolated server
from reaching services running on the host itself.

The gateway deny list, however, was keyed on the wrong network. It inspected
only the Docker network literally named `bridge` and blocked its gateway —
`172.17.0.1`, or whatever that network happens to use. An isolated MCP workload
is not on that network. It is attached to a per-server network
(`toolhive-<name>-internal`) plus a shared `toolhive-external` one, and Docker
assigns each user-defined bridge its own gateway: `172.18.0.1`, `172.19.0.1`,
`172.24.0.1`, and so on. Those addresses appeared in neither the Squid rules nor
the Envoy rules.

So the isolation denied an address the workload had no use for, and left open
the address it does use to reach host-local services. Under the default
permission profile (`insecure_allow_all`), the egress proxy then permits the
request. A malicious or compromised MCP workload could reach a service exposed
on the host through its own network's gateway — a host service, a database
admin panel, another container's published port — crossing the boundary the
proxy policy exists to enforce.

Fixed on 2026-10-12 in [ToolHive v0.52.0](https://github.com/stacklok/toolhive/releases/tag/v0.52.0).

## Background

ToolHive (from Stacklok) runs MCP servers in containers with a security posture
it calls isolation: the workload is placed on a dedicated Docker bridge network,
and all of its HTTP(S) egress is routed through a proxy container that applies
the configured outbound policy. This matters because MCP servers are typically
run from third-party images, and the isolation is the thing standing between a
malicious server image and everything reachable from the host's network stack.

An earlier advisory, [GHSA-qg2g-g9w3-m5h8](https://github.com/advisories/GHSA-qg2g-g9w3-m5h8)
(CVE-2026-58197, 8.8), covered containerized MCP servers reaching host services
via `host.docker.internal`. Its fix, shipped in v0.30.1, added the host-gateway
deny list: the two Docker hostnames (`host.docker.internal`,
`gateway.docker.internal`) and a single resolved IP. That fix's intent is the
invariant under test here — *an isolated workload must not reach the host
through the gateway address of its bridge network*.

## The vulnerability

ToolHive represented the protected gateway as a single value, `GatewayIP`,
resolved once at workload creation:

```go
// pkg/container/docker/client.go
GatewayIP: c.getDockerBridgeGatewayIP(ctx)

// getDockerBridgeGatewayIP — inspects the *default bridge* network only,
// with a hardcoded fallback
nr, err := c.client.NetworkInspect(ctx, "bridge", mobyclient.NetworkInspectOptions{})
// ...falls back to 172.17.0.1
```

That one value became the sole IP deny target in both proxy implementations —
a `dst 172.17.0.1` line in Squid, a `:authority` regex in Envoy — alongside the
two hostnames.

But the workload is attached elsewhere:

```go
// pkg/container/docker/client.go
networkName := fmt.Sprintf("toolhive-%s-internal", name)
externalEndpointsConfig := map[string]*network.EndpointSettings{ networkName: {} }
if networking.IsBridgeMode(permissionConfig.NetworkMode) {
    externalEndpointsConfig["toolhive-external"] = &network.EndpointSettings{}
```

User-defined bridges get their own host-side gateways, assigned in order as
networks are created. The container's route to the host goes through *its*
network's gateway — an address that was never in the deny set. The generated
policy, produced by ToolHive's own rule generators, showed exactly one IP:

```
generated Squid gateway rules (gatewayIP=172.17.0.1):
  acl docker_gateway_hosts dstdomain host.docker.internal gateway.docker.internal
  acl docker_gateway_ip dst 172.17.0.1
  NOT COVERED: 172.18.0.1
  NOT COVERED: 172.19.0.1
  NOT COVERED: host.containers.internal

generated Envoy :authority deny patterns:
  (?i)172\.17\.0\.1\.?(:[0-9]+)?
  NOT COVERED: 172.18.0.1 / 172.19.0.1 / host.containers.internal
```

A second, runtime-specific instance lived in the fallback: ToolHive's
supported non-Docker runtimes (Podman/Colima) are driven through the
Docker-compatible socket, but under Podman there is no network named `bridge`
— so the inspection fails, the hardcoded `172.17.0.1` is used, and Podman's
documented host-gateway addresses (`10.88.0.1`, `10.0.2.2`) and its host alias
`host.containers.internal` are all absent. That instance was code-level (no
Podman on the test host) and was withdrawn from the report when the maintainers
asked for topology-faithful proof; it is noted here because the same
single-value design causes it.

## Verifying it

Two layers, both against real code.

**The generated policy** was read from the real rule generators with an
in-package test at the tested revision (`ea994394`, latest release v0.50.0):
both Squid and Envoy deny exactly one IP plus the two Docker hostnames, as
shown above.

**The live path** was reproduced with real Docker (28.5.2, rootful, native
Linux Docker Engine). A network created the same way ToolHive creates one
(`toolhive-poc-internal`, subnet `172.19.0.0/16`, gateway `172.19.0.1`), a
host-local service (`python3 -m http.server` bound to `0.0.0.0`), and a
container attached to that network:

```
ToolHive-style per-server network : subnet=172.19.0.0/16 gateway=172.19.0.1
network ToolHive resolves        : subnet=172.17.0.0/16 gateway=172.17.0.1   <-- the one it blocks

container default gateway        : 172.19.0.1
172.17.0.1 (BLOCKED ip)          -> HTTP 200 (952 bytes)
172.19.0.1 (own-network gateway) -> HTTP 200 (952 bytes)   <-- host service reached
```

The workload's own gateway reaches the host service; the address the policy
blocks is simply a different network's gateway.

A follow-up re-verification went further, at the maintainers' request: a real
`thv run` workload (v0.50.0, both default and `--isolate-network` modes),
recording its actual `toolhive-pocrepro-internal` network (`internal=true`,
gateway `172.24.0.1`), clearing the proxy environment variables the runtime
injects, and issuing a raw stdlib-socket request. The host service at
`172.24.0.1` answered `HTTP/1.0 200 OK` in both modes, while `172.17.0.1` and
other networks' gateways were unreachable — confirming the direct path on
native Linux Docker Engine. That raw-traffic path is **not** part of this
advisory: the published remediation is specific to requests routed through the
egress proxies, and the direct-path question remains under separate
investigation upstream.

## Impact

The confirmed result is unauthorized network reachability: a malicious or
compromised MCP workload can connect through the egress proxy to a service
exposed on the host or on another bridge network, and read its response.
Further impact depends entirely on what is listening there — a service bound
only to Linux loopback is not made reachable this way, but a database panel,
an internal API, or another container's published port on a wildcard bind is.
This is not a container escape and does not by itself compromise the host.

The advisory rates it `CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L` = **6.3
Medium** (CWE-284, CWE-693). The scope change (`S:C`) reflects traffic
crossing from the isolated workload into the host's security authority; the
environmental severity is higher wherever a sensitive unauthenticated service
happens to be exposed.

## The fix

Fixed in [v0.52.0](https://github.com/stacklok/toolhive/releases/tag/v0.52.0)
(commit `a87b6fd5`, merged 2026-10-12). The remediation replaces the
single-value design with a deployment-time snapshot:

1. Lists the daemon's networks and selects **every** network using the
   `bridge` driver — including bridges not attached to the proxy.
2. Inspects each by immutable network ID, canonicalizes, deduplicates and
   sorts every valid IPv4 and IPv6 IPAM gateway.
3. Removes the hardcoded `172.17.0.1` fallback and **fails isolated startup
   closed** when gateway discovery cannot establish a complete policy.
4. Uses the identical gateway set in both Squid and Envoy, for the deny rules
   and for the explicit `--allow-docker-gateway` opt-in.
5. Upgrades Envoy to v1.39.1 and adds exact gateway `/32` and `/128` ranges to
   the dynamic-forward-proxy resolved-address filter, so a permitted hostname
   that resolves (or re-resolves after a DNS TTL) to a gateway is rejected on
   the resolved address rather than only on the lexical authority.

The fix's shape is the one the report suggested — derive the deny set from the
networks that actually exist rather than from one hardcoded network name — with
a stronger failure mode (fail closed) than the report asked for. One
operational caveat, documented in the advisory: gateway discovery is a
deployment-time snapshot, so workloads must be redeployed after Docker bridge
topology changes.

The same advisory also consolidates a second, independently reported gap in the
Envoy path (authority-only matching against DNS rebinding), reported by
another researcher; this writeup covers the gateway-discovery issue that led
to my report.

## Timeline

- **2026-09-20** — Reported via GitHub's private vulnerability reporting
  (`GHSA-v7q7-97w6-v6mc`).
- **2026-09-22** — Maintainers confirm the egress-proxy portion and consolidate
  it with a second report into a joint private advisory; request a
  topology-faithful direct-path reproduction, which follows on native Linux
  Docker Engine.
- **2026-10-12** — Fix merged (`a87b6fd5`), released in v0.52.0, and the
  advisory published as `GHSA-hfmx-2rf9-m35g`, Medium (CVSS 3.1
  `AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L` = 6.3, CWE-284/CWE-693), no CVE
  assigned.

## Disclosure

Full advisory: [GHSA-hfmx-2rf9-m35g](https://github.com/stacklok/toolhive/security/advisories/GHSA-hfmx-2rf9-m35g)
(published 2026-10-12; Medium; no CVE assigned; credits this report and one
other). The fix is in
[v0.52.0](https://github.com/stacklok/toolhive/releases/tag/v0.52.0)
(commit `a87b6fd5`). This writeup describes behavior verified against ToolHive
`main` at `ea994394` (v0.50.0) and the remediation as merged for v0.52.0.
