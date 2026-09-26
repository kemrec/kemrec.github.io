---
title: "Predis's write() Re-Parses Its Buffer on \\r\\n, Enabling Redis Command Injection"
date: 2026-09-17
target: "predis/predis"
severity: Critical
identifier: "GHSA-v32q-pmmw-cf38"
advisory_url: "https://github.com/predis/predis/security/advisories/GHSA-v32q-pmmw-cf38"
summary: "A public, documented Predis method re-derives RESP command boundaries by splitting on literal \\r\\n bytes instead of respecting length-prefixed arguments, letting attacker-controlled data smuggle an entirely separate command onto a cluster or replication node."
---

## Summary

Redis's wire protocol, RESP, is length-prefixed: an argument states its own
byte length up front, so the server reads exactly that many bytes
regardless of what they contain. `Predis\Connection\AbstractAggregateConnection::write()`
— a public method on the interface every Predis connection implements,
reachable through the ordinary, documented `Client::getConnection()` call
— ignores that and re-derives command boundaries by splitting the buffer
on literal `\r\n` bytes instead. Any value or key that happens to contain
`\r\n` can carve a completely separate, attacker-chosen command out of what
should have been a single argument, and have it dispatched to whichever
node the connection resolves it to.

## Background

`write(string $buffer): void` is declared on `Connection\ConnectionInterface`
— not an internal helper, but genuinely public API — and does this:

```php
public function write(string $buffer): void
{
    $rawCommands = [];
    $explodedBuffer = explode("\r\n", trim($buffer));

    while (!empty($explodedBuffer)) {
        $argsLen = (int) explode('*', $explodedBuffer[0])[1];
        $cmdLen = ($argsLen * 2) + 1;
        $rawCommands[] = array_splice($explodedBuffer, 0, $cmdLen);
    }

    foreach ($rawCommands as $command) {
        $command = implode("\r\n", $command) . "\r\n";
        $commandObj = Command::deserializeCommand($command);
        $this->getConnectionByCommand($commandObj)->write($command);
    }
}
```

This function takes an already-correctly-serialized RESP buffer and
re-parses it a second time, on the client side, using a byte-delimiter
strategy that disagrees with how the protocol it's re-parsing actually
works.

## The vulnerability

A bulk-string argument like `PAD4\r\n*1\r\n$7\r\nFLUSHDB` is, to the real
Redis server, a single value of whatever length was declared for it — the
embedded `\r\n` sequences inside it are just bytes, not protocol
boundaries, because RESP tells the server how many bytes to read rather
than where to stop reading.

`AbstractAggregateConnection::write()`'s own re-parser doesn't know that.
Splitting that same string on `\r\n` produces five lines; the parser reads
`*1` from the second line and concludes a new "command" starts there,
consisting of one argument — and reconstructs `*1\r\n$7\r\nFLUSHDB\r\n`, a
complete, syntactically valid `FLUSHDB` command, as if the calling
application had sent it on its own. `getConnectionByCommand()` then routes
this fabricated command to whichever node Predis's fake routing key
happens to hash to for a keyless command like `FLUSHDB`, and that node
executes it.

Because `write()` sits on the public `ConnectionInterface` and is
reachable via the documented `Client::getConnection()` method, this
doesn't require any special calling pattern — any code writing a raw
buffer to a cluster or replication connection, built from data that
includes attacker-influenced keys or values, is exposed.

## Proof of concept

Two plain Redis instances standing in as cluster shards, addressed through
Predis's client-side cluster sharding:

```php
$client = new Predis\Client(
    ['tcp://127.0.0.1:6391', 'tcp://127.0.0.1:6392'],
    ['cluster' => 'predis']
);

$connection = $client->getConnection(); // documented public API, no pipeline() involved

$key = "slug:PAD4\r\n*1\r\n\$7\r\nFLUSHDB";
$buf = (new Predis\Command\RawCommand('GET', [$key]))->serializeCommand();
$connection->write($buf);
```

A single `GET` call — nothing that looks like a write, let alone a
`FLUSHDB` — reliably empties one of the two shards after a handful of
attempts (routing to a specific shard depends on which slot the fake
routing key hashes to, so success is probabilistic with few shards and
approaches certainty as shard count grows):

```
Before: shard1 dbsize=47, shard2 dbsize=53
  attempt 4: shard1 dbsize=47, shard2 dbsize=0
```

## Impact

Any application using a Predis cluster or replication client that ever
writes a raw buffer built from attacker-influenced key or value data
through this method is exposed to unauthenticated command injection on a
node it never intended to send anything to: cluster-wide `FLUSHDB`,
targeted `DEL`/`SET`, key theft via `GET`, or a `CLUSTER FLUSHSLOTS`-driven
outage. Since the method is a property of the connection object itself,
this isn't tied to any one specific calling pattern in application code.

## Fix

Fixed in **v3.6.1**, which replaces the `\r\n`-splitting re-parser with
logic that walks the buffer by each argument's own declared byte length,
matching how RESP actually works — an embedded `\r\n` inside a value can
no longer be reinterpreted as a fresh command boundary.

## Timeline

The path to a fix wasn't a straight line. The initial report was closed
without engagement the same day it was filed; a public follow-up laying
out exactly what a related, earlier fix had and hadn't covered got the
maintainer to re-open it, and a contributor shipped the real fix days
later.

- **2026-09-14** — Reported via GitHub's private security-advisory
  reporting.
- **2026-09-14** — Closed by the maintainer without comment, a few hours
  later.
- **2026-09-14** — Public follow-up opened, explaining the specific
  reachable path in more detail.
- **2026-09-15** — Maintainer re-engaged, advisory reopened and formally
  accepted; a fix shipped shortly after in a pull request rewriting the
  vulnerable method to use length-prefixed parsing.
- **2026-09-17** — Fix released in **v3.6.1**; advisory published as
  `GHSA-v32q-pmmw-cf38`, Critical (CVSS 3.1
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8).

## Disclosure

Full advisory: [GHSA-v32q-pmmw-cf38](https://github.com/predis/predis/security/advisories/GHSA-v32q-pmmw-cf38).
