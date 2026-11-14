---
title: "Microsoft Outlook: An Out-of-Bounds Write in the Icon-Property Parser"
date: 2026-11-14
target: "Microsoft Outlook"
severity: High
fixed: "Office LTSC 2021 16.0.14334.20974, M365 Apps / LTSC 2024 16.0.17932.21056"
fix: "October 2026 Patch Tuesday"
fix_url: "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct"
identifier: ""
advisory_url: "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct"
summary: "An icon blob stored in a MAPI binary property was parsed with no length argument at all. A 32-bit offset taken straight from the blob located a bitmap header, and the parser then wrote into it, so a crafted property produced an out-of-bounds write at an attacker-chosen distance from the allocation. Reconstructed from the October 2026 Outlook patch; fixed by adding a length parameter and a range check."
---

## Summary

This is a root-cause writeup of one memory-corruption bug that Microsoft fixed in the October 2026 Outlook security update. It lives in `OLMAPI32.DLL`, the MAPI runtime that classic Outlook uses to read message and object properties. The vulnerable function parses an icon blob that arrives as a binary MAPI property. It took no buffer length, trusted a 32-bit offset embedded in the blob, and used that offset to locate a bitmap header it then wrote to. A crafted property value therefore produced an out-of-bounds read and an out-of-bounds write at an offset the attacker chose.

This is n-day work. The fix shipped in October 2026, so nothing here is a live zero-day. The point is to document the root cause, which the vendor advisory does not, and to be honest about the two things I could not pin down: the exact CVE number, and whether the parser is reachable from the reading pane without a click. Both are discussed below rather than glossed over.

## Background

Outlook stores a lot of per-object state as MAPI properties. Each property has a tag whose low 16 bits are a type and whose high 16 bits are an identifier. Two of them carry icon artwork for an object: `PR_ICON` (`0x0FFD0102`) and `PR_MINI_ICON` (`0x0FFC0102`). The `0102` suffix is `PT_BINARY`, so the value is an opaque byte blob whose contents the property store never interprets. Whatever produced the object decides the bytes, and on an inbound object those bytes are outside Outlook's trust boundary.

The blob itself is a classic Windows icon structure: a small directory that counts image entries, then one or more device-independent bitmaps. A `BITMAPINFOHEADER` inside each entry carries the width, height and bit depth. Icon parsers routinely rewrite the height field, because a classic DIB icon stores the color bitmap and its AND mask stacked in one image, so the stored height is twice the real height and the code halves it. That rewrite is where this bug lands.

## The bug

The property getter `FUN_180408b40` fetches the icon property and hands the raw blob to a parser. Reconstructed from the pre-patch build, the parser looked roughly like this:

```c
/* pre-patch, reconstructed. Note the signature: a blob pointer and an
   output pointer, and no length anywhere. */
HRESULT ParseIconProperty(const BYTE *blob, HICON *out)
{
    if (IsBadReadPtr(blob, 1))          /* validates exactly one byte */
        return E_FAIL;

    DWORD count = *(const DWORD *)(blob + 0x0C);   /* entry count, unbounded */

    for (DWORD i = 0; i < count; i++) {
        const ICONDIRENTRY *e = entry_at(blob, i);     /* walked with no bound */
        DWORD off = *(const DWORD *)((const BYTE *)e + 6);  /* 32-bit, as-is */

        BITMAPINFOHEADER *bmi = (BITMAPINFOHEADER *)(blob + off + 2);

        bmi->biHeight = bmi->biHeight / 2;   /* OUT-OF-BOUNDS WRITE */
        LONG  w   = bmi->biWidth;            /* out-of-bounds read   */
        WORD  bpp = bmi->biBitCount;

        CreateDIBitmap(/* ... */, bmi, /* ... */);
        GetBitmapBits(/* ... */);
    }
    /* ... */
}
```

The trust decision that failed is the first line. `IsBadReadPtr(blob, 1)` confirms that a single byte at the start of the blob is readable, and nothing else. There is no blob length in scope, so the parser has no way to know where the buffer ends even if it wanted to check.

From there, two attacker-controlled values drive the reads and writes. `count` at offset `0x0C` is taken as the number of directory entries and bounds the loop with no sanity limit. `off` is a raw 32-bit offset pulled out of each entry and added to the blob base to locate the bitmap header. Neither is validated against the real size of the property value.

The write is `bmi->biHeight = bmi->biHeight / 2`. Because `bmi` is `blob + off + 2` with `off` fully attacker-chosen, the four bytes of `biHeight` can be placed well past the end of the allocation. That is a four-byte out-of-bounds write whose target distance from the buffer the attacker controls, which is a strong primitive, not a mere crash. The subsequent reads of `biWidth` and `biBitCount`, and the handoff to `CreateDIBitmap`, add out-of-bounds reads on top.

## The fix

The October 2026 build rewrites the function (it moves to `FUN_1803fd6c8`) and makes two structural changes.

First, the parser now takes a length. The signature gains an unsigned size argument, and every caller was updated to plumb the real property size through (the getter picks up a new field at offset `+0x1B0` to carry it). A parser that knows its buffer length can finally reason about bounds.

Second, a new range-check helper (`FUN_1801b1ae8`, absent from the pre-patch binary) validates that the structure actually fits before anything is dereferenced. The added check has the shape `base + count * 4 + extra <= length`, computed against the length that is now in scope, and the code bails out instead of parsing when it fails.

```c
/* post-patch, reconstructed */
HRESULT ParseIconProperty(const BYTE *blob, DWORD cbBlob, HICON *out)
{
    DWORD count = read_count(blob, cbBlob);
    DWORD off   = read_entry_offset(blob, cbBlob, i);

    if (!IconRangeCheck(off, sizeof(BITMAPINFOHEADER), cbBlob))   /* new helper */
        return E_FAIL;

    BITMAPINFOHEADER *bmi = (BITMAPINFOHEADER *)(blob + off + 2);
    /* ... same work, now proven in-bounds ... */
}
```

The fix looks complete for the inbound path. I checked the obvious sibling, a stream-based icon marshaler in the same binary (`FUN_18058b9a0`) that builds an icon from dimensions and bit buffers read off an `IStream`. It was not touched by this update and it does carry a dimensions-versus-buffer mismatch, but the property getter does not route the inbound blob to it. It is reached only through serializer vtable slots fed by an internal persistence round-trip, not by the raw attacker property, so it is not a second unpatched copy of this bug on the attack surface.

## CVE attribution

The vendor advisory for every Outlook memory bug in this release says the same sentence, "heap-based buffer overflow in Microsoft Office Outlook," with no component, function or property named. That makes a confident one-to-one mapping from this function to a single CVE number impossible from public data, so I am not going to invent one. What the public record does support is a bounded candidate set, reached by elimination.

The October 2026 Outlook cluster contains eleven CVEs. This bug is an out-of-bounds write on a heap blob, reconstructed from the Windows classic binary `OLMAPI32.DLL`, present and fixed in the Office LTSC 2021 train. That rules out:

- the two stack-overflow RCEs (CVE-2026-88156, CVE-2026-97012) and the double-free (CVE-2026-97749), which are different bug classes;
- the information-disclosure out-of-bounds read (CVE-2026-70281), which is not an RCE;
- the two heap RCEs that Microsoft also lists for Office for Mac (CVE-2026-70291, CVE-2026-108448), because `OLMAPI32.DLL` has no equivalent in the Mac build, so a Mac-affecting CVE is almost certainly the shared cross-platform parser rather than this code;
- CVE-2026-70256, whose affected-product list omits LTSC 2021, the train this bug was diffed on.

What remains is the set of Windows-only heap-overflow Outlook RCEs: CVE-2026-70242 and CVE-2026-97016 (both 9.8, no user interaction), and CVE-2026-70257 and CVE-2026-70282 (both 8.8, user interaction required). Those four are the honest candidate set. They cannot be separated further from outside Microsoft, because 70242 and 97016 are identical in every published field, and the two severity tiers differ only by whether the trigger needs a click, which brings us to the next caveat.

## Reachability

I did not prove how this parser is reached, and I will not pretend otherwise. The data source is a binary property on a MAPI object, which could be a message, a folder or a form. If Outlook renders a message's icon while listing or previewing it, the path is reachable from inbound mail, possibly without a click. If the property is only consumed for a folder or form icon in a more deliberate context, the trigger needs user action. The decompiled getter does not settle this on its own, and I built no live trigger to test it. So the severity here is stated as the floor of the candidate set, High, and the bug may well be one of the 9.8 preview-pane entries instead. Treat the exact tier as unproven.

## Impact

The primitive is a four-byte out-of-bounds write at an attacker-controlled offset, with attacker-controlled reads alongside it, driven entirely by the contents of an inbound binary property. In a process that parses untrusted objects, that is a memory-corruption bug in the remote-code-execution class, which is exactly how Microsoft rates the cluster it belongs to. The precondition is that Outlook parses an object whose icon property an attacker set, with the reachability caveat above governing whether that needs a click.

## The method

The bug was recovered by diffing the pre-update and post-update `OLMAPI32.DLL` from two Office Click-to-Run builds and reading the changed function in both. The general technique, and the specific problem that the most interesting fixes in this cluster add no new strings or imported calls and so hide from a naive diff, is written up separately in [Patch-Diffing a Large Closed-Source Binary Cluster](/research/outlook-patch-diffing-closed-source-binaries/).

## Timeline

- 2026-10-13: Microsoft ships the October 2026 Office updates that fix the cluster this bug belongs to.
- 2026-11-14: this root-cause writeup.

## Disclosure

This is n-day research. The fix is public and shipped before this was written, and no report was filed by me for this bug. Credit for the original report of whichever CVE this is belongs to its reporter in Microsoft's acknowledgments, which for the two unnamed Windows-only heap candidates (CVE-2026-70242 and CVE-2026-97016) is listed as Anonymous. This post only adds the root-cause detail the advisory withholds. All analysis was done against publicly distributed Office binaries.
