---
title: "Microsoft Outlook: A Heap Overflow Flattening Multivalued Binary Properties"
date: 2026-11-14
target: "Microsoft Outlook"
severity: High
fixed: "Office LTSC 2021 16.0.14334.20974, M365 Apps / LTSC 2024 16.0.17932.21056"
fix: "October 2026 Patch Tuesday"
fix_url: "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct"
identifier: ""
advisory_url: "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct"
summary: "A routine that flattens a MAPI property array sized the output for a multivalued binary property using an eight-byte element stride borrowed from the multivalued string cases, then copied sixteen-byte structures into it. The allocation was short by eight bytes per element, so the copy overflowed the heap buffer. Reconstructed from the October 2026 Outlook patch; fixed by giving the binary type its own size branch and a second validation pass."
---

## Summary

This is a root-cause writeup of a heap out-of-bounds write that Microsoft fixed in the October 2026 Outlook security update. It lives in `OUTLOOK.EXE` itself, in a routine that flattens a MAPI property value into a contiguous buffer. For a multivalued binary property the routine computed the buffer size with the wrong element stride: it reused the eight-byte stride meant for the multivalued string cases, then copied sixteen-byte binary descriptors into the undersized buffer. The result is an allocation that is short by eight bytes for every element, overflowed by a copy loop that writes the full structures.

This is n-day work. The fix shipped in October 2026. What follows is the root cause, plus the same two honest caveats as the rest of this series: the CVE number cannot be uniquely assigned from public data, and the reachability tier is unproven.

## Background

A MAPI property value is an `SPropValue`, a tagged union. The tag's type field says how to read the union. Multivalued types carry a count and a pointer to an array. The relevant ones here are the multivalued strings, `PT_MV_STRING8` (`0x101E`) and `PT_MV_UNICODE` (`0x101F`), and the multivalued binary type `PT_MV_BINARY` (`0x1102`).

The element sizes differ. The multivalued string cases work with an array of eight-byte pointers. The multivalued binary case is an array of `SBinary`, which is `{ ULONG cb; BYTE *lpb; }`. On a 64-bit build that structure is sixteen bytes once alignment pads the four-byte length out to the eight-byte pointer. Flattening copies these elements into one output buffer, so the size calculation has to use the right per-element stride for the type it is flattening. This bug is what happens when it does not.

## The bug

Reconstructed from the pre-patch build, the size calculation put the binary type in the same branch as the string types, using an eight-byte stride, while the copy wrote full `SBinary` elements:

```c
/* pre-patch, reconstructed */
SCODE FlattenPropValue(const SPropValue *pv, void **out)
{
    ULONG n = pv->Value.MVbin.cValues;
    SIZE_T cb;

    switch (PROP_TYPE(pv->ulPropTag)) {
    case PT_MV_STRING8:   /* 0x101E */
    case PT_MV_UNICODE:   /* 0x101F */
    case PT_MV_BINARY:    /* 0x1102, wrong bucket */
        cb = (SIZE_T)n * 8;            /* eight-byte element stride */
        break;
    /* ... other types ... */
    }

    SBinary *dst = (SBinary *)MAPIAllocateBuffer(cb);   /* under-allocated */

    for (ULONG i = 0; i < n; i++)
        dst[i] = pv->Value.MVbin.lpbin[i];   /* writes sizeof(SBinary) == 16 each */

    *out = dst;
    return S_OK;
}
```

The allocation reserves `n * 8` bytes. The copy writes `n` elements of `sizeof(SBinary)`, which is sixteen bytes each, so it writes `n * 16` bytes into a buffer that holds `n * 8`. Every element overflows by eight bytes, and the total overflow is `n * 8` bytes past the end of the allocation, with `n` taken from the property's own count field. This is the textbook shape of CWE-131, an incorrect buffer-size calculation, leading to CWE-787, an out-of-bounds write on the heap.

The reason the stride was wrong is visible in the pre-patch switch: `0x1102` shared a `case` arm with `0x101E` and `0x101F`. The string types really do move eight-byte-strided data, so the constant was correct for them and simply never adjusted when the binary type was folded into the same arm.

## The fix

The October 2026 build rewrites the function (it moves to `FUN_1408a2850`) and corrects the calculation in two steps.

First, `PT_MV_BINARY` gets its own size branch with the correct element stride, so the allocation is sized for sixteen-byte `SBinary` elements rather than eight-byte ones.

Second, the code adds a second validation pass before it calls `MAPIAllocateBuffer`, which cross-checks the computed size against the element count and type before committing to the allocation, so a future stride mistake cannot silently under-allocate again.

```c
/* post-patch, reconstructed */
    switch (PROP_TYPE(pv->ulPropTag)) {
    case PT_MV_STRING8:   /* 0x101E */
    case PT_MV_UNICODE:   /* 0x101F */
        cb = (SIZE_T)n * 8;
        break;
    case PT_MV_BINARY:    /* 0x1102, now its own branch */
        cb = (SIZE_T)n * sizeof(SBinary);     /* sixteen-byte stride */
        break;
    }
    /* second pass re-derives and checks cb against n and the type
       before MAPIAllocateBuffer */
```

The fix looks complete. I checked the eleven functions in `OUTLOOK.EXE` that reference both `0x1102` and the string tags for a second copy of the mistake. Six are static property-table initializers with no flatten logic. Two are stream codecs (one serialize, one deserialize) that already use the correct sixteen-byte stride. The remaining three are not flatten routines. There is no twin in the binary.

## CVE attribution

As with the other bugs in this cluster, Microsoft's advisory text is a single generic sentence per CVE with no component named, so a unique CVE assignment is not possible from public data. The honest result is a bounded candidate set.

This is a heap out-of-bounds write, reconstructed from the Windows binary `OUTLOOK.EXE`, present and fixed in the Office LTSC 2021 train. The same elimination used across this series excludes the stack overflows (CVE-2026-88156, CVE-2026-97012), the double-free (CVE-2026-97749), the information-disclosure read (CVE-2026-70281), the two Mac-affecting heap entries (CVE-2026-70291, CVE-2026-108448), and CVE-2026-70256, which does not list LTSC 2021. The candidate set is the Windows-only heap-overflow Outlook RCEs: CVE-2026-70242 and CVE-2026-97016 (9.8, no interaction) and CVE-2026-70257 and CVE-2026-70282 (8.8, interaction required).

## Reachability

Property flattening runs when Outlook serializes or marshals a message's properties, which happens on a lot of ordinary paths, so this one feels closer to reading-pane reach than the icon or OfficeArt bugs. I did not prove that, though. I did not establish which inbound flow sets a `PT_MV_BINARY` property with an attacker-chosen count and reaches this routine without a click, and I built no live trigger. So the reachability tier stays unproven, the severity is stated at the candidate-set floor of High, and the bug may be one of the 9.8 no-interaction entries instead.

## Impact

The primitive is a heap out-of-bounds write whose overflow length is a direct multiple of a count field in an attacker-influenced property. In the process that handles untrusted messages, that is a memory-corruption bug in the remote-code-execution class, matching how Microsoft rates the cluster. The precondition is that Outlook flattens a multivalued binary property an attacker controls, with the reachability caveat above governing whether that needs a click.

## The method

This was recovered by an instruction-level diff of the pre-update and post-update `OUTLOOK.EXE`, a forty-two-megabyte binary where the real fix is a handful of changed instructions. How that fix was surfaced without drowning in the noise of a monthly rebuild is the subject of the companion post, [Patch-Diffing a Large Closed-Source Binary Cluster](/research/outlook-patch-diffing-closed-source-binaries/).

## Timeline

- 2026-10-13: Microsoft ships the October 2026 Office updates that fix this cluster.
- 2026-11-14: this root-cause writeup.

## Disclosure

This is n-day research. The fix is public and shipped before this was written, and I filed no report for this bug. Credit for the original report of whichever CVE this is belongs to its reporter in Microsoft's acknowledgments. This post only adds the root-cause detail the advisory withholds, and all analysis was done against publicly distributed Office binaries.
