---
title: "oras-go: The Path Check That Never Looked at the Last Component"
date: 2026-10-19
target: "oras-project/oras-go"
severity: High
identifier: "GHSA-2hhj-vj64-hx3j"
advisory_url: "https://github.com/oras-project/oras-go/security/advisories/GHSA-2hhj-vj64-hx3j"
summary: "file.Store resolves symlinks on the deepest existing ancestor of a write target and appends the final component without resolving it. A terminal symlink planted by an unpacked layer passed the containment check, and the next blob push wrote through it to any path the pulling process could reach. Fixed in v2.6.4."
---

## Summary

`oras.land/oras-go/v2/content/file.Store` is the supported way to materialize a
pulled artifact on disk. `oras pull` uses it, and so does any Go program that
calls `oras.Copy` with a file store as the destination. When a layer carries the
unpack annotation, the store extracts that layer's tarball into the working
directory. Ordinary blobs are written as files under titles relative to the same
directory.

The write path has a containment check. It resolves symlinks on the deepest
ancestor that already exists and appends the remaining path components as
literal text. If the last component is itself a symlink, the check never looks
at where that symlink points.

An attacker can plant such a symlink with an unpacked layer and then write
through it with the next blob. Under default settings the bytes land outside the
store root, at any path the pulling process can write.

Reported privately on 2026-09-20, fixed in oras-go v2.6.4, published as
[GHSA-2hhj-vj64-hx3j](https://github.com/oras-project/oras-go/security/advisories/GHSA-2hhj-vj64-hx3j)
(CVSS 8.8, CWE-22 and CWE-59).

## Background

ORAS moves OCI artifacts. The `file` package implements a local content store:
it can hold blobs, and with `AnnotationUnpack: "true"` on a layer descriptor it
extracts the layer tarball instead. The extraction root is
`<workingDir>/<title>`, where the title comes from the descriptor annotation.

The store has two write paths:

- `(*Store).push` resolves the destination from the title and dispatches to
  `pushDir` for unpacked layers and `pushFile` for plain blobs.
- `resolveWritePath` runs a lexical `filepath.Rel` check against the working
  directory, then calls `checkSymlinkEscape` to catch symlinks that would carry
  the write outside the root.

Two earlier advisories shaped this code. GHSA-8xwf-rjm4-xvhv introduced
`checkSymlinkEscape` for the blob path. GHSA-m37j-52j7-pjw7 hardened the unpack
path after a tar-slip report: `writeFile` now unlinks a planted symlink before
writing, and extraction validates each entry's own path. Both fixes are in
v2.6.2.

The assumption left behind was that the unpack path may create a link that
escapes, because nothing writes through it. That assumption is what the next
section breaks.

## The vulnerability

The blob write in `content/file/file.go` (v2.6.2, lines 472 to 479):

```go
if err := ensureDir(filepath.Dir(target)); err != nil {
    return ocispec.Descriptor{}, err
}
fp, err := os.Create(target)   // line 477: follows a terminal symlink
```

There is no `Lstat` of the target and no `O_NOFOLLOW`. `os.Create` follows a
symlink at the final component. The comparable helper in `content/file/utils.go`,
`writeFile`, was hardened with exactly that `Lstat` and remove step by the
earlier fix. `pushFile` was not touched.

The containment check does run, but it cannot see the problem. Call chain:

1. `resolveWritePath` (file.go:609 to 641) does the lexical `Rel` check, then
   calls `checkSymlinkEscape(base, target)` at line 632.
2. `checkSymlinkEscape` (file.go:700 to 724) compares
   `filepath.EvalSymlinks(base)` with `realPathForWrite(target)`.
3. `realPathForWrite` (file.go:726 to 748) walks up to the deepest ancestor
   that exists, resolves that part, and appends the rest verbatim. Its own doc
   comment says: "Non-existent path components are appended verbatim, matching
   the semantics of a file about to be created."

A destination that exists and is a symlink is therefore treated the same as a
regular file that does not exist yet. `Rel(realBase, realTarget)` stays
in-bounds, and the check passes.

The symlink itself comes from the unpack path. `extractTarDirectory`
(utils.go:159 to 241, link case at 207 to 224) validates each link with
`ensureLinkPath` and `resolveRelToBase`. Those functions clean the target
lexically with `filepath.Join`, which collapses `..` textually, and `Lstat`
only the ancestors of the cleaned path. The final component is never resolved,
and the per-entry `checkSymlinkEscape` added by the previous fix checks the
link's own path, not its target.

That gives a two-step primitive:

1. Unpack a layer whose tarball contains a symlink chain. The chain's lexical
   target stays inside the extraction root; its kernel-resolved target is an
   absolute path outside it.
2. Push a plain blob titled `<title>/escape`. `pushFile` calls
   `os.Create(<workingDir>/<title>/escape)`, follows the planted link, and
   writes the blob to the outside path.

Neither step needs a local precondition on the victim side. The plant arrives
inside the artifact.

## Proof of concept

The core of the harness, run against v2.6.2 and against `main` at the time of
the report:

```go
store, _ := file.New(workDir) // defaults: AllowPathTraversalOnWrite=false

// 1) plant: one unpack layer with a symlink chain in its tarball
desc := ocispec.Descriptor{
    MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
    Digest:    digest.FromBytes(gz),
    Size:      int64(len(gz)),
    Annotations: map[string]string{
        ocispec.AnnotationTitle: "out",
        file.AnnotationUnpack:   "true",
    },
}
store.Push(ctx, desc, bytes.NewReader(gz))

// 2) write: a plain blob whose title points at the planted link
payload := []byte("PWNED\n")
desc2 := ocispec.Descriptor{
    MediaType: "application/octet-stream",
    Digest:    digest.FromBytes(payload),
    Size:      int64(len(payload)),
    Annotations: map[string]string{
        ocispec.AnnotationTitle: "out/escape",
    },
}
store.Push(ctx, desc2, bytes.NewReader(payload))
```

Output on v2.6.2:

```
[*] planted symlink  : /tmp/oras-victim-3802003788/out/escape
    -> "d0/d1/d2/d3/d4/d5/d6/up/../../../../../../../tmp/oras-outside-704254150/authorized_keys"
[*] kernel resolves it to: /tmp/oras-outside-704254150/authorized_keys
[+] BYPASS: /tmp/oras-outside-704254150/authorized_keys overwritten
```

The lexical target above starts with `d0/d1/...`, so `filepath.Join` keeps it
inside the extraction root. The kernel follows the chain through `up` and
lands on the absolute path.

The same primitive works through `oras.Copy`, which is what `oras pull` does. A
single artifact whose layers alternate plant and write entries overwrites six
outside targets in one pull when `Concurrency = 1` (6 of 6, three runs). With
the default `Concurrency = 3`, ordering between a plant and its write is racy,
but repeated pulls accumulate escapes.

Controls on the same harness:

- The previously published single-layer attack is blocked on v2.6.2.
  `writeFile` removes the planted symlink and writes inside the root.
- A plain push with a benign title lands inside the store.

## Impact

Arbitrary file create and overwrite as the process that materializes the
artifact. That covers `~/.ssh/authorized_keys`, shell startup files, Git hooks,
CI job definitions, and anything else on a writable path. The attacker controls
the registry or artifact source and needs no authentication to the victim. User
interaction is the victim pulling the artifact.

No non-default configuration is required. `AllowPathTraversalOnWrite=false` and
`SkipUnpack=false` are the defaults, and the two-push sequence works under them.

## The fix

The fix follows the pattern already used on the unpack path. `pushFile` and
`pushDir` now call `removeSymlink` before writing, and open files with
`createNoFollow`, which sets `O_NOFOLLOW` on Unix. `writeFile` uses the same
helper. Regression tests cover the two-push sequence.

I re-ran the harness against the released v2.6.4 module: the plant still
creates the link, the second push returns no error, and the outside file keeps
its original content. Both controls still behave. The fix is in the advisory
fork as v2 `15e969139f` and main `e69b02531e`, verified before merge.

Advisory metadata lists no patched version. v2.6.4 is the first release I
verified as fixed.

## Timeline

- 2026-09-20: report submitted through GitHub private vulnerability reporting.
- 2026-10-13: advisory accepted, credits to the reporter and an independent finder.
- 2026-10-14: v3.0.0-rc.2 released.
- 2026-10-16: v2.6.4 released.
- 2026-10-19: advisory published.
