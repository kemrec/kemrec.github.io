---
title: "A 72-Byte Serialized Stream Forced Gigabyte Allocations in Guava"
date: 2026-09-29
target: "google/guava"
severity: High
identifier: "CVE-2026-102554"
advisory_url: "https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94"
summary: "CompactHashMap, CompactHashSet, and MapMakerInternalMap read an attacker-controlled size field during Java deserialization and eagerly allocate arrays sized to the full, unvalidated value before the rest of the stream is consumed, a 72-byte payload forces multi-gigabyte allocation and an OutOfMemoryError. Fixed in Guava 33.7.2."
---

## Summary

`CompactHashMap`, `CompactHashSet`, and `MapMakerInternalMap` in Google's Guava library implement `readObject(ObjectInputStream)` by reading an attacker-controlled size field, `elementCount` for the `CompactHash*` collections, `initialCapacity`/`concurrencyLevel` for `MapMakerInternalMap`, straight off the wire. On the very first insertion, each implementation eagerly allocates backing arrays sized to that full, unvalidated declared value, without ever checking it against how much data the stream actually contains. A 72-byte serialized stream carrying a single tiny element can force several gigabytes of allocation and crash the JVM with `OutOfMemoryError`. This is CVE-2026-102554 / [GHSA-xxph-c9ww-hj94](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94), fixed in Guava 33.7.2.

## Background

This is the same amplification shape as the long-fixed CVE-2018-10237, which affected `AtomicDoubleArray` and `CompoundOrdering`: an attacker declares a large size up front, and the library allocates for that size before validating it against the stream's real content. Guava's own `HashBiMap.readObject()` already documents the correct defense in a comment on the line that avoids this exact trap: `init(16); // resist hostile attempts to allocate gratuitous heap`. `ArrayListMultimap`, `HashMultiset`, `LinkedHashMultiset`, `LinkedHashMultimap`, `ImmutableSetMultimap`, and `ImmutableListMultimap` all follow the same defensive pattern elsewhere in the codebase. `CompactHashMap`, `CompactHashSet`, and `MapMakerInternalMap` did not.

All three classes are top-level, `implements Serializable`, and Guava is present on the classpath of a large fraction of the JVM ecosystem, a native Java deserialization attacker can name any of them directly in a hand-crafted stream, with no dependency on which factory method the victim application actually used.

## The vulnerability

`CompactHashMap.readObject()` reads the declared count and only checks that it is non-negative:

```java
private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
  stream.defaultReadObject();
  int elementCount = stream.readInt();
  if (elementCount < 0) {
    throw new InvalidObjectException("Invalid size: " + elementCount);
  }
  init(elementCount);
  for (int i = 0; i < elementCount; i++) {
    K key = (K) stream.readObject();
    V value = (V) stream.readObject();
    put(key, value);
  }
}
```

`init()` just stores the value, clamped only to an upper bound of `CompactHashing.MAX_SIZE` (2^30-1, roughly 1.07 billion):

```java
void init(int expectedSize) {
  Preconditions.checkArgument(expectedSize >= 0, "Expected size must be >= 0");
  this.metadata = Ints.constrainToRange(expectedSize, 1, CompactHashing.MAX_SIZE);
}
```

The real allocation happens lazily, inside `allocArrays()`, which fires on the first `put()` call, after only one key/value pair has actually been read off the wire:

```java
int allocArrays() {
  int expectedSize = metadata;
  int buckets = CompactHashing.tableSize(expectedSize);
  this.table = CompactHashing.createTable(buckets);
  setHashTableMask(buckets - 1);
  this.entries = new int[expectedSize];
  this.keys = new Object[expectedSize];
  this.values = new Object[expectedSize];
  return expectedSize;
}
```

With `expectedSize` near `MAX_SIZE`, that single call allocates a hash table plus three `expectedSize`-length arrays, multiple gigabytes, after the stream has supplied exactly one small real element. `CompactHashSet` has the identical shape, and `CompactLinkedHashMap`/`CompactLinkedHashSet` inherit it from their parents.

`MapMakerInternalMap` has a related but separately-triggered version of the same bug. Its serialization proxy reads an unvalidated `size` and `concurrencyLevel` from the stream and passes them into a `MapMaker`, which allocates its full segment table, sized from those two attacker-controlled numbers, before any real entry is read back.

## Proof of concept

Against the current release at the time (`guava:33.7.1-jre`), a 72-byte malicious stream containing one real `"A"` string element, with only its 4-byte declared-count field patched from `1` to `0x3FFFFFFF` (`CompactHashing.MAX_SIZE`), produces:

```
### -Xmx8g (generous heap) ###
Declared elementCount: 1073741823 (~1.07 billion)
Real payload: 1 tiny string element ("A")
=== RESULT ===
Exception: java.lang.OutOfMemoryError: Java heap space
Time to allocate+fail: 4013 ms
Heap used after (at failure point): 4103 MB

### -Xmx128m (ordinary service heap) ###
=== RESULT ===
Exception: java.lang.OutOfMemoryError: Java heap space
Time to allocate+fail: 24 ms
```

A 72-byte input forces roughly 4.1 GB of real allocation before failing on an 8 GB heap, and crashes an ordinary 128 MB service heap in 24 milliseconds, over 50,000x amplification between input size and forced allocation. The `MapMakerInternalMap` variant behaves the same way: a 627-byte patched stream with a declared size of `Integer.MAX_VALUE` throws `OutOfMemoryError` in 30 milliseconds against a 128 MB heap, provided the map was constructed with an option (such as weak keys) that routes through Guava's own internal map implementation rather than the JDK's `ConcurrentHashMap` fast path.

## Impact

Any application that runs `ObjectInputStream.readObject()` on attacker-reachable data, with Guava anywhere on its classpath, can be crashed with a single payload of under a hundred bytes, regardless of what type the application itself expected to deserialize. This is a pure availability impact (CWE-770 / CWE-400). Under CVSS 3.1 the vector is `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`, 5.9 (Medium). The CNA and NVD also carry a CVSS 4.0 score for the same defect: `AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`, 8.2 (High). The two differ because 4.0 splits the precondition out of attack complexity (`AT:P`) and rates the remaining path as low complexity, while 3.1 folds the same precondition into `AC:H`. Nothing about the impact changes: availability only, no confidentiality or integrity effect. The 4.0 score is the one the CVE record and the OSV entry carry, so the severity badge on this page follows it.

## Fix

Guava 33.7.2 applies the same defense already present elsewhere in the codebase: the initial capacity used for the first allocation is capped to a small constant regardless of the stream's declared count, and the backing storage grows incrementally as elements are actually read, rather than being sized up front to the full attacker-declared value.

## Timeline

- **2026-09-22**: Reported to `google/guava` via GitHub private vulnerability reporting, covering `CompactHashMap`/`CompactHashSet` and, the same day, the related `MapMakerInternalMap` variant.
- **2026-09-29**: Fixed in **Guava 33.7.2**; advisory [GHSA-xxph-c9ww-hj94](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) published and **CVE-2026-102554** assigned.
- **2026-10-09**: CVE record published with the CNA's CVSS 4.0 metrics, 8.2 (High), alongside the original 3.1 score in the advisory.
- **2026-10-27**: OSV entry refreshed with the CVSS 4.0 vector and a HIGH rating; GitHub's advisory page still renders 5.9 Medium from 3.1 only. That divergence is why this page now carries High with both vectors spelled out.

## Disclosure

The advisory is public at [GHSA-xxph-c9ww-hj94](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) / [CVE-2026-102554](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94). Guava already had the right pattern for this class of bug documented in its own source, `HashBiMap`'s "resist hostile attempts to allocate gratuitous heap" comment predates this report by years. The gap was that three other Serializable collection types, added at different times by different authors, never inherited that same discipline.
