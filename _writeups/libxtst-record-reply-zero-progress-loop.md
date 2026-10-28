---
title: "libXtst: a RECORD reply that never advances the parser"
date: 2026-10-27
target: "libXtst (X.Org)"
severity: Medium
identifier: "CVE-2026-109088"
advisory_url: "https://www.cve.org/CVERecord?id=CVE-2026-109088"
summary: "A malformed RECORD EnableContext reply with a zero-size FromClient element or an unknown category byte leaves parse_reply_call_callback() with nothing to advance the cursor, so an X client that enables a RECORD context spins forever. Fixed in libXtst 1.2.6."
---

## Summary

libXtst parses the reply to `XRecordEnableContext()` one element at a time and
moves a cursor forward after each element. The loop assumes every element makes
progress. Two server-controlled reply shapes break that assumption: a
`FromClient` element whose length decodes to zero, and an element with a
category byte outside the handled range. In both cases the cursor stays where
it is and the parser calls the application callback again, forever.

The client does not need to do anything wrong. It connects to an X server,
enables a RECORD context, and the server answers with a malformed reply. The
synchronous API never returns. The asynchronous API livelocks inside Xlib reply
processing.

Fixed in libXtst 1.2.6.

## Background

The RECORD extension lets a client observe protocol traffic on an X server.
`XRecordEnableContext()` sends an `EnableContext` request and then reads the
reply, which is a sequence of elements: client requests, replies, start and end
markers, and client-died notifications.

`parse_reply_call_callback()` in `src/XRecord.c` walks those elements. Each
iteration reads one element, hands it to the application callback, and advances
`current_index` by the element's decoded size:

```c
	(*callback)(closure, data);
	current_index += datum_bytes;
    } while (current_index<rep->length<<2);
```

`datum_bytes` comes from the reply bytes. The parser checks bounds and rejects
oversized elements, but it does not require the value to be greater than zero.

## The vulnerability

Two reply shapes produce `datum_bytes == 0` while bytes remain in the buffer.

The first is a `FromClient` element with a zero length field. A 16-bit length of
zero selects the BIG-REQUESTS form, where the real size is read from the next
32-bit word. If that word is also zero, the element size is zero:

```c
    if (reply->buf[current_index+2] == 0
	&& reply->buf[current_index+3] == 0)
    {	/* BIG-REQUESTS */
	if (current_index + 8 > rep->length << 2)
	    goto out;
	EXTRACT_CARD32(rep->clientSwapped,
		       reply->buf+current_index+4, datum_bytes);
    } else {
	EXTRACT_CARD16(rep->clientSwapped,
		       reply->buf+current_index+2, datum_bytes);
    }
    if (datum_bytes < 0 || datum_bytes > INT_MAX >> 2)
	goto out;
    datum_bytes <<= 2;
    break;
```

The second is an element whose category byte is not one of the six handled
values. The `switch (rep->category)` has no `default`, so `datum_bytes` keeps
its previous value of zero and control falls through to the callback.

In both cases the callback receives `data == NULL` and `data_len == 0`, the
cursor does not move, and the loop runs again.

This is not a new class in this file. CVE-2016-7952 was the same endless loop,
and the fix for it (commit `9556ad67`, released in 1.2.3) added the progress
check to three other categories: `StartOfData`, `EndOfData`, and `ClientDied`
without a client sequence are rejected when `current_index < rep->length << 2`.
A zero-size element is only legal at the end of the buffer. That treatment was
never applied to zero-length `FromClient` elements, and nothing rejects unknown
category bytes.

The newer out-of-bounds fix for CVE-2026-94286 (MR !10, commit `16023c86`) adds
an element-size versus remaining-buffer check. It does not change either loop.

## Proof of concept

The harness compiles the real `src/XRecord.c` from two snapshots and feeds
`parse_reply_call_callback()` a crafted reply, built the way `XRecordEnableContext()`
receives one: a 32-byte reply header through `_XReply()` and reply data through
`_XRead()`. A callback counts invocations and a `SIGALRM` stops the run after ten
seconds.

| scenario | master (1.2.5, `a1086d8f`) | with MR !10 (`16023c86`) |
|---|---|---|
| one well-formed 4-byte client request | 1 callback, `Continue` | 1 callback, `Continue` |
| oversized element (CVE-2026-94286) | callback gets 1024 bytes over an 8-byte buffer, ASan heap-buffer-overflow | rejected with an error, ASan clean |
| zero-length FromClient element | 949,192,452 callbacks in 10 s | 958,714,169 callbacks in 10 s |
| undefined category byte (99) | 1,273,655,343 callbacks in 10 s | 1,300,754,068 callbacks in 10 s |

The oversized row shows the harness reaches the real parsing path: it reproduces
the known out-of-bounds read and shows the pending fix stopping it. The two loop
rows are this finding, and both survive the pending fix.

The whole reply is under server control. No server privileges and no client
authentication are involved.

## Impact

A malicious or compromised X server can hang any client that records a context.
`XRecordEnableContext()` never returns. The async path spins inside Xlib's reply
processing, so the client's event handling stops, and only killing the process
ends it.

The loop runs at roughly 10^8 to 10^9 callbacks per second at 100% CPU. Each
iteration allocates or recycles an `XRecordInterceptData` record, and a callback
that does not free zero-length records grows memory without bound.

CVE-2026-109088 is rated 6.5 Medium (CWE-835) with `UI:R`: a user has to start a
client that enables RECORD, or the client does so as part of its normal work.
Session recorders, automation tools, and test harnesses that attach to a display
are the practical targets.

## Fix

Reject any element that makes no forward progress:

```c
	if (datum_bytes == 0 && current_index < rep->length << 2)
	    goto out;	/* element made no progress: malformed reply */
```

Valid streams are unaffected. The only legitimate zero-size elements already
appear at the end of the buffer, where `current_index == (rep->length << 2)`.
A `default: goto out;` in the category switch covers the unknown-category vector
as defense in depth; the single progress check above covers both.

Applied to both snapshots, the check makes both loop vectors return `Error` with
zero callbacks, while the calibration element still parses.

## Timeline

- 2026-09-29: reported to the X.Org security team
- 2026-10-01: maintainer replied with a proposed fix, agreement sent the same day
- 2026-10-13: CVE-2026-109088 assigned
- 2026-10-15: MR !11 merged (`ac60f5f4`)
- 2026-10-16: tag `libxtst-1.2.6`
- 2026-10-27: CVE record published

## Disclosure

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-109088
- Upstream fix: https://gitlab.freedesktop.org/xorg/lib/libxtst/-/merge_requests/11
