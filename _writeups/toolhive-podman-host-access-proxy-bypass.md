---
title: "ToolHive: Podman's Host-Access Endpoints Slip Past the Egress Proxy"
date: 2026-10-19
target: "stacklok/toolhive"
severity: Medium
identifier: "GHSA-2x65-h9w3-h7hc"
advisory_url: "https://github.com/stacklok/toolhive/security/advisories/GHSA-2x65-h9w3-h7hc"
summary: "With network isolation on and --allow-docker-gateway off, ToolHive's egress proxies still permitted rootless Podman workloads to reach host.containers.internal and the runtime-provided host-access address. The protected set was built from Docker assumptions, so the Podman alias and its address were never in it. Fixed in v0.55.2 by reading the DNS sidecar's hosts file at deployment time."
---

## Summary

ToolHive runs MCP servers as containers and, by default, forces their outbound
traffic through an egress proxy. The proxy denies a list of destinations that
are supposed to be off limits to a workload. One of them is the host itself:
the address a container can use to reach services bound on the machine running
the container.

That protected set was written for Docker. It knew the Docker host aliases and
the bridge gateway addresses ToolHive discovered from the runtime API. Rootless
Podman provides host access through a different alias,
`host.containers.internal`, and through an address that is not a bridge IPAM
gateway. Neither was in the set. With isolation enabled and
`--allow-docker-gateway` disabled, a workload could still send requests through
the proxy to a host service.

The issue was confirmed on Linux with rootless Podman 5.8.7 and Netavark, on
both supported proxy backends. It is fixed in v0.55.2 and published as
[GHSA-2x65-h9w3-h7hc](https://github.com/stacklok/toolhive/security/advisories/GHSA-2x65-h9w3-h7hc)
(CVSS 6.3, Medium).

## Background

An earlier advisory, [GHSA-hfmx-2rf9-m35g](https://github.com/stacklok/toolhive/security/advisories/GHSA-hfmx-2rf9-m35g),
covered the Docker side of this policy: the gateway deny list was keyed on the
default `bridge` network while workloads live on their own per-server and
shared bridge networks. The fix there snapshotted every Docker bridge gateway
at deployment time.

The lesson from that report was narrower than it looked. The policy was correct
for the gateway addresses Docker hands out, and still wrong for any host access
path that does not go through those addresses. Rootless Podman is exactly that
case.

## The gap

ToolHive's proxy configuration is generated from a protected address set. The
Squid rules deny the host aliases by name and the collected addresses as
literal destinations. The Envoy rules match the same names on the authority
header and remove the protected addresses from resolved DNS results. The flag
`--allow-docker-gateway` is the explicit opt-in that opens this set to the
workload.

Under rootless Podman, the runtime reaches the host through
`host.containers.internal`, and through an address the runtime provides for
host access. That address is not necessarily the bridge gateway and it is not
returned as part of Docker's IPAM configuration, so the deployment time
snapshot never contained it. The Envoy resolved-address filter had the bridge
gateways but not the Podman host-access address either.

The result was a proxy policy bypass, not traffic that ignores
`HTTP_PROXY`/`HTTPS_PROXY`. The request went through the egress proxy and the
proxy allowed it, because the destination was not on a list that was supposed
to include it.

## Verifying it

Testing used separate Squid and Envoy workloads started with network isolation
enabled, the `network` permission profile, and without
`--allow-docker-gateway`. The probe was attached only to the workload's actual
internal network, so it had no route around the proxy, and the proxy-bypass
variables were cleared before each request. The target was a host HTTP canary
under test control that returned an unpredictable marker, so a successful
request could be told apart from a cached or synthetic response.

```
Destination                                      Squid       Envoy
host.containers.internal                         ALLOWED     ALLOWED
Runtime host-access IP (observed 169.254.1.2)    ALLOWED     ALLOWED
host.docker.internal                             BLOCKED     BLOCKED
Workload bridge gateway (observed 10.89.27.1)    BLOCKED     BLOCKED
Allowed container-local control                  ALLOWED     ALLOWED
```

All four permitted host requests returned the canary marker and the canary
logged them independently. The deny policy was active. Its destination set was
incomplete.

The observed `169.254.1.2` belongs to that test environment. It is not a
universal Podman fallback and the advisory says so.

## Impact

A malicious or compromised MCP workload can open a proxied connection to a
service on the host that the isolation policy is meant to protect. What that
buys the workload depends on the service and how it authenticates. The
confirmed impact is unauthorized reachability and exposure of the response
body. This is not a container escape and does not by itself establish host
compromise.

Preconditions are specific: Linux with rootless Podman and Netavark, network
isolation in bridge mode, traffic routed through the ToolHive egress proxy,
`--allow-docker-gateway` disabled, an outbound profile that permits the
destination, and a host service reachable through Podman's host-access path.
The user-interaction component in the CVSS vector models a victim launching a
malicious image.

## The fix

v0.55.2 stops deriving the host side from a fixed list. When the runtime is
Podman, ToolHive reads the runtime-generated `/etc/hosts` of its DNS sidecar at
deployment time and adds every address mapped to `host.containers.internal`,
`host.docker.internal`, or `gateway.docker.internal` to the protected set,
alongside all daemon bridge gateways. No address is assumed.

Squid denies the aliases by name and the discovered addresses as literal
destinations. Envoy matches the aliases and the addresses on the authority
header and removes the addresses from dynamic-forward-proxy DNS results. The
protection applies even when the outbound profile is permissive.
`--allow-docker-gateway` remains the explicit opt-in and opens the same set on
both backends.

Deployment now fails before the proxy or the MCP container starts if the host
alias is missing, or if the hosts data is malformed, oversized, or unreadable,
including when `--allow-docker-gateway` is set. The protected set is a snapshot
taken at deployment, so changing Podman's host mappings or networking mode
requires redeploying the workload.

## Remaining scope

Confirmation is limited to Linux, rootless Podman 5.8.7, and Netavark. Rootful
Podman, CNI, the slirp4netns and pasta variants, and Podman Machine on macOS or
Windows were not verified. Traffic that bypasses the HTTP(S) proxy entirely is
a separate advisory, and the Docker bridge gateway defect is the earlier one
linked above.

## Timeline

The Podman host-access path was reported privately after the Docker gateway
finding. It was published on 2026-10-19 as GHSA-2x65-h9w3-h7hc, with the fix in
v0.55.2 covering both Squid and Envoy.
