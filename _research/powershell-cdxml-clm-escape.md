---
title: "PowerShell: CDXML Import Bypasses Constrained Language Mode"
date: 2026-10-13
target: "PowerShell/PowerShell"
severity: High
fixed: "7.6.5+"
fix: "PR #27869"
fix_url: "https://github.com/PowerShell/PowerShell/pull/27869"
summary: "PowerShell generates the module script behind a CDXML import from attacker-controlled XML and marks it FullLanguage-trusted. On CoreCLR builds before 7.6.5, the XML schema validation that trust depended on was compiled out, so a crafted .cdxml escapes Constrained Language Mode: a session that can run Set-Content and Import-Module ends up executing arbitrary .NET code. Verified on 7.6.2; fixed in 7.6.5."
---

## Summary

Constrained Language Mode (CLM) is the enforcement layer behind WDAC and AppLocker script enforcement: a locked-down session can't call arbitrary .NET APIs, so it's safe to run code you don't fully trust. On PowerShell 7 builds before 7.6.5, importing a crafted `.cdxml` file from inside such a session escapes the boundary. The file needs two operations that CLM allows by design: write it with `Set-Content`, load it with `Import-Module`. Everything after that runs in FullLanguage.

This is an n-day, not a disclosure. The fix landed on the 7.6.5 release branch before I looked at this, and the main-branch merge ([PR #27869](https://github.com/PowerShell/PowerShell/pull/27869)) has been public since 2026-08-20. No CVE was assigned. I verified the behavior end to end on 7.6.2 and on 7.6.6, then went through the fix for completeness. The reason to write it up is the failure mode: a security decision that rested on a validation step that wasn't running in the build most people were on.

## Background

CDXML (Cmdlet Definition XML) is how CIM-based cmdlets get defined in XML instead of C#. `Import-Module` accepts `.cdxml` files directly, and Windows itself uses the format for its CIM-based management modules. The import path parses the XML, generates a PowerShell module script from it, and runs that script.

CLM is what makes "run this untrusted code" a solvable problem. WDAC or AppLocker puts the process into ConstrainedLanguage, and the engine then blocks method invocation on anything but core types. A script can keep working (cmdlets, pipelines, variables) while the interesting escape hatches stay closed. A CLM escape is therefore an escape from the security boundary itself. CVE-2019-1167 was the same class, in the same product.

## Where the trust comes from

The generated module script is marked trusted in `ModuleCmdletBase.cs`:

```csharp
ScriptBlock sb = ScriptBlock.Create(this.Context, cmdletizationProxyModuleWriter.ToString());

// CDXML doesn't allow script injection, so it is trusted.
sb.LanguageMode = PSLanguageMode.FullLanguage;
```

That comment is the security argument, and it's load-bearing: because the script block is FullLanguage, the code it contains runs with full privileges no matter what mode the importer is in.

"CDXML doesn't allow script injection" isn't structural, though. The generated script text is assembled from XML values, and what keeps those values from breaking out of their context is validation against `cmdlets-over-objects.xsd`, a schema whose patterns constrain fields like command names to plain identifiers. The source says so itself, right next to the one place where a value goes into the script without escaping:

```csharp
Dbg.Assert(
    Regex.IsMatch(commandMetadata.Name, @"[\p{Ll}\p{Lu}\p{Lt}\p{Lo}\p{Lm}]{1,100}-[\p{Ll}\p{Lu}\p{Lt}\p{Lo}\p{Lm}\p{Nd}]{1,100}"),
    "Command name doesn't need escaping - validated via xsd");
output.WriteLine(
    CmdletBeginBlockTemplate,
    /* 0 */ commandMetadata.Name,
    ...
```

`Dbg.Assert` compiles to nothing in release builds. So the schema is the only thing standing between the XML and the generated code. That's fine, as long as the schema actually runs.

## The bug

In 7.6.2, and in every CoreCLR build before 7.6.5, it didn't. The reader settings in `ScriptWriter` were set up under a preprocessor branch:

```csharp
#if CORECLR // The XML Schema file 'cmdlets-over-objects.xsd' is missing in Github, and it's likely the resource string
            // 'CmdletizationCoreResources.Xml_cmdletsOverObjectsXsd' needs to be reworked to work in .NET Core.
            ScriptWriter.s_xmlReaderSettings.DtdProcessing = DtdProcessing.Ignore;
#else
            ... ValidationType = ValidationType.Schema; Schemas.Add(...) ...
#endif
```

On Windows PowerShell (the `#else` side) the schema was attached and enforced. On PowerShell Core / PowerShell 7 (the `#if CORECLR` side) the setup was skipped, and the reader fell back to no validation at all. The comment in the source says the quiet part: the schema file was missing from the repository, and the resource lookup needed reworking for .NET Core. Rather than block the port, the validation was compiled out, and it stayed that way until 7.6.5.

With no schema, every value the patterns were supposed to police is attacker-controlled. One of those values is the command name: `Verb` + `-` + `Noun`, or `DefaultNoun`, written into the generated script through this template:

```
function {0}
{
```

A `DefaultNoun` like this:

```xml
<DefaultNoun>X {} ; [System.IO.File]::WriteAllText('C:\poc\marker.txt','proof') ; function Z</DefaultNoun>
```

turns the generated header into valid PowerShell:

```powershell
function Get-X {} ; [System.IO.File]::WriteAllText('C:\poc\marker.txt','proof') ; function Z { ... }
```

The payload closes the function header, runs a .NET method call, and opens a dummy function for the rest of the template to attach to. It executes at import time, and it executes in FullLanguage, because that's how the generated script block is marked.

## Proof of concept

The test is short: force the session to ConstrainedLanguage, confirm the boundary is real (a direct method call must fail), write the crafted file with `Set-Content`, import it, and check for a marker file.

On **7.6.2**:

```
mode: ConstrainedLanguage
CTRL: direct method call BLOCKED in CLM (expected): Cannot invoke method. Method invocation is
      supported only on core types in this language mode.
CLM Set-Content OK: True
IMPORT: OK
MARKER EXISTS -> payload executed
marker content: FULL-LANGUAGE-EXECUTION-PROOF
```

On **7.6.6**, the same script:

```
IMPORT ERR: Import-Module: Cannot process Cmdlet Definition XML ... The '...:DefaultNoun' element
is invalid - The value 'X {} ; [System.IO.File]::WriteAllText(...) ; function Z' is invalid
according to its datatype '...:Noun' - The Pattern constraint failed.
marker MISSING -> payload did not execute
```

That error is the schema doing its job: the `Noun` pattern rejects the payload before any script text is generated.

The runs above were on Linux builds. The CDXML import path is cross-platform, and ConstrainedLanguage is the same mode WDAC or AppLocker script enforcement sets on Windows; on a Windows CLM deployment the impact below applies unchanged.

## Impact

The preconditions are exactly what a CLM deployment is supposed to tolerate. In WDAC enforced mode, AppLocker script enforcement, or any host that runs untrusted scripts in a locked-down session, the attacker needs the session to write a file and import it. Both operations are ordinary and allowed. From there the injected code runs with FullLanguage privileges in the same process: arbitrary .NET, arbitrary API calls, no different from running outside the sandbox. The delivery route is a module import, so anything that feeds a `.cdxml` from a source the session doesn't fully control is a candidate.

The timeline matters here, though: this is closed on current stable. 7.6.5 and 7.6.6 both reject the payload. It only affects older 7.x builds, so if you deploy WDAC or AppLocker with script enforcement, make sure you're on 7.6.5 or later.

## The fix

The fix restores what the `#if CORECLR` branch had dropped, on every platform: `cmdlets-over-objects.xsd` is embedded in the assembly as a resource, and the reader settings always validate against it. In 7.6.5 and 7.6.6 the static constructor reads:

```csharp
using Stream xsdStream = typeof(ScriptWriter).Assembly.GetManifestResourceStream("cmdlets-over-objects.xsd");
XmlReader cmdletizationSchemaReader = XmlReader.Create(xsdStream, s_xmlReaderSettings);
```

with `ValidationType = ValidationType.Schema` set unconditionally. The change first landed on the release branch as "Add the xsd validation back for CIM cmdlets" (commit `2207e9e3e7`, merged 2026-08-10), shipped in 7.6.5 on 2026-08-14, and reached the main branch as [PR #27869](https://github.com/PowerShell/PowerShell/pull/27869) on 2026-08-20.

Two checks beyond "the PoC stopped working":

- The second consumer of the CDXML path, `AnalysisCache.AnalyzeCdxmlModule` (behind `Get-Module -List`), runs through the same validated `ScriptWriter` and only fills in module metadata; it doesn't generate or execute script text, so there's no parallel unvalidated path.
- The escaping layer, audited separately from the schema: a canary battery with quote-bearing values in every loosely typed field (class names, method names, parameter names, defaults, help URIs, adapter data) round-trips safely. String contexts double quotes via `EscapeSingleQuotedStringContent`, variable contexts use `EscapeVariableName`. The only raw write left is the command name, and that one is now schema-tight.

One observation about the fixed version, not a vulnerability in it: the command-name write is still protected by nothing but the schema. If the resource is ever lost again the way it was here, the injection comes back silently, and a release-build `Dbg.Assert` won't tell anyone. An escape at the write site, or a startup check that the schema actually loaded, would make this trust decision fail closed instead of fail open.

## Timeline

- 2026-08-10: fix merged into the release/v7.6.5 branch (`2207e9e3e7`).
- 2026-08-14: 7.6.5 released with the fix.
- 2026-08-20: same change merged to main as PR #27869 (`ad9c8fb93cd8`).
- 2026-09-08: 7.6.6 released.
- 2026-10-13: verified end to end on 7.6.2 (escape) and 7.6.6 (rejected); completeness checks done.

## Disclosure

This is n-day research, not a disclosure. The fix was already public when I looked at it, no report was filed, and no CVE exists. Everything above is based on public sources: the merged fix, released binaries (7.6.2 and 7.6.6), and the source that ships with them.
