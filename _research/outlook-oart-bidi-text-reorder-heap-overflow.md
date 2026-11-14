---
title: "Microsoft Outlook: A Heap Overflow in OfficeArt Bidirectional Text Reordering"
date: 2026-11-14
target: "Microsoft Outlook"
severity: High
fixed: "Office LTSC 2021 16.0.14334.20974, M365 Apps / LTSC 2024 16.0.17932.21056"
fix: "October 2026 Patch Tuesday"
fix_url: "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct"
identifier: ""
advisory_url: "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct"
summary: "An OfficeArt text-run reordering routine sized its output buffer from one length and then drove the write loop with a different length that could grow while the loop ran. When the loop length ran past the allocation, the routine wrote past the end of the heap buffer. Reconstructed from the October 2026 Outlook patch; fixed by freezing the bound and pinning the write index to the allocation."
---

## Summary

This is a root-cause writeup of a heap out-of-bounds write that Microsoft fixed in the October 2026 Outlook security update. It sits in `OART.DLL`, the OfficeArt component that lays out and renders drawing and text-shape content across Office, including shapes that Outlook renders. The vulnerable function reorders a run of complex-script or bidirectional text. It allocated its output buffer using one length and then wrote into that buffer using a second, separately computed length that could increase while the write loop ran. When the second length exceeded the allocation, the routine wrote past the end of the buffer.

This is n-day work. The fix is public and shipped in October 2026. The value here is the root cause, and an honest account of the two open questions this bug shares with the rest of the cluster: which CVE it is, and whether the path is reachable without a click. Both are addressed below.

## Background

Bidirectional and complex-script text cannot be drawn in storage order. Arabic and Hebrew run right to left, scripts like Devanagari reorder and combine glyphs, and zero-width joiners and non-joiners (`U+200D` and `U+200C`) change how neighbors fuse. Before a run can be shaped, the engine reorders the characters into visual order. OfficeArt does this with a Uniscribe-style itemize-and-shape step, and the function at issue builds a reordered copy of the run into a freshly allocated buffer.

The pattern that fails is a common one in this kind of code: the buffer is sized from a quick scan of the input, and the copy is then driven by the shaping logic, which counts characters differently. If those two counts can diverge, the write runs off the end.

## The bug

Reconstructed from the pre-patch build, the routine sized the destination from a scan to the run terminator, then filled it with a loop whose bound was a different variable:

```c
/* pre-patch, reconstructed */
HRESULT ReorderTextRun(const WCHAR *text /* attacker-influenced */, /* ... */)
{
    int n = ScanToTerminator(text);               /* length snapshot A */
    WCHAR *dst = (WCHAR *)Alloc((n + 1) * sizeof(WCHAR));

    int i     = 0;
    int limit = run_length_from_itemize(/* ... */);   /* length B, != A */

    do {
        dst[i++] = reorder_next(text, /* ... */);     /* write index tracks B */
        limit    = advance_over_joiners(/* ... */);   /* B can GROW in the loop */
    } while (counter < limit);                        /* loop bound is B, buffer is A */

    /* ... */
}
```

The allocation is `(n + 1)` elements, where `n` comes from `ScanToTerminator`. The write loop is governed by `limit`, which is computed by the itemize and joiner-handling logic and is a different quantity than `n`. The subtle part is that `limit` is updated inside the loop body: the joiner handling can advance it as it consumes `U+200D` and `U+200C` sequences, so the number of iterations is not fixed when the loop starts. When `limit` ends up larger than `n + 1`, `dst[i++]` writes past the allocation. That is a heap out-of-bounds write, with the overflow length driven by the difference between how the terminator scan and the shaper count the same run.

The classification is CWE-787, an out-of-bounds write, on a heap buffer (CWE-122). The data is document text, so the trigger is a crafted run of bidirectional or complex-script characters in content that Outlook hands to OfficeArt.

## The fix

The October 2026 build rewrites the function (it moves to `FUN_1807d4b24`) and makes the two counts agree in three steps.

First, the bound is frozen before the loop. The code snapshots the scan length into a local (`local_70`) and loops `while (index < local_70)`, so the number of writes is fixed by the allocation length at loop entry and cannot drift as the shaper advances.

Second, the write index is pinned to the allocation. An added `if (limit <= index) break;` stops the loop at the smaller of the two counts rather than trusting the shaper count.

Third, there is a post-condition safety net. After the loop the code compares what it allocated against what it wrote, and if the written count ever exceeds the allocation it frees the buffer and bails (`if (alloc_count < written_count) { free(dst); return E_FAIL; }`) instead of returning a corrupted result.

```c
/* post-patch, reconstructed */
HRESULT ReorderTextRun(const WCHAR *text, /* ... */)
{
    int n = ScanToTerminator(text);
    WCHAR *dst = (WCHAR *)Alloc((n + 1) * sizeof(WCHAR));

    int bound = n;                         /* frozen snapshot */
    for (int i = 0; i < bound; i++) {
        if (limit <= i) break;             /* write index pinned to allocation */
        dst[i] = reorder_next(text, /* ... */);
    }

    if (alloc_count < written_count) {     /* post-condition safety net */
        Free(dst);
        return E_FAIL;
    }
    /* ... */
}
```

The fix looks complete. I looked for an unpatched sibling using the same shape, a buffer sized by one length-snapshot and a write loop bounded by a different, loop-mutated length, across the other OfficeArt text and joiner handlers. The functions that reference the same `U+200D` and `U+200C` constants in this binary are classifiers, dispatchers and read-only scanners. None of them builds an output buffer with the snapshot-versus-loop-bound mismatch, so there is no second copy of this bug in that neighborhood.

## CVE attribution

Microsoft describes every memory RCE in this Outlook release with one generic sentence and names no component, so a single CVE number cannot be assigned to this function from public data. The honest result is a bounded candidate set.

This is a heap out-of-bounds write, reconstructed from the Windows classic binary `OART.DLL`, present and fixed in the Office LTSC 2021 train. By the same elimination used across this series, that excludes the stack overflows (CVE-2026-88156, CVE-2026-97012), the double-free (CVE-2026-97749), the information-disclosure read (CVE-2026-70281), the two Mac-affecting heap entries (CVE-2026-70291, CVE-2026-108448), and CVE-2026-70256, which does not list LTSC 2021. The remaining candidates are the Windows-only heap-overflow Outlook RCEs: CVE-2026-70242 and CVE-2026-97016 (9.8, no interaction) and CVE-2026-70257 and CVE-2026-70282 (8.8, interaction required). The data cannot narrow it further.

## Reachability

I did not prove the trigger path, so I will not claim it is zero-click. OfficeArt renders drawing and text-shape content, and Outlook reaches it when it renders such content: an OfficeArt drawing in a rich-text or HTML body, or a shape in an attached Office document. Whether the reading pane renders OfficeArt text shapes automatically, before any click, I could not confirm from the decompiled code alone, and I built no live trigger. That matters, because it is the exact difference between the 9.8 no-interaction candidates and the 8.8 user-interaction candidates above. The severity here is therefore stated as the floor of the candidate set, High, with the top of the range left open.

## Impact

The primitive is a heap out-of-bounds write whose overflow length is driven by crafted bidirectional or complex-script text. In a process that renders untrusted content, that is a memory-corruption bug in the remote-code-execution class, consistent with how Microsoft rates the cluster. The precondition is that Outlook hands attacker-influenced text to the OfficeArt reorderer, with the reachability caveat above deciding whether that needs a click.

## The method

This was recovered by an instruction-level diff of the pre-update and post-update `OART.DLL` and reading the changed function in both builds. The reason a fix like this one, which mostly adds comparisons and a loop-bound change and introduces no new string or imported call, is nearly invisible to a naive binary diff is covered in the companion post, [Patch-Diffing a Large Closed-Source Binary Cluster](/research/outlook-patch-diffing-closed-source-binaries/).

## Timeline

- 2026-10-13: Microsoft ships the October 2026 Office updates that fix this cluster.
- 2026-11-14: this root-cause writeup.

## Disclosure

This is n-day research. The fix is public and shipped before this was written, and I filed no report for this bug. Credit for the original report of whichever CVE this is belongs to its reporter in Microsoft's acknowledgments. This post only adds the root-cause detail the advisory leaves out, and all analysis was done against publicly distributed Office binaries.
