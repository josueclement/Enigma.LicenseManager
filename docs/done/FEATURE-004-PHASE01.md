# FEATURE-004 · PHASE01 — Build-settings consolidation

**Completed on branch:** `feature/feature-004-phase01-build-props`

## Summary

Consolidated shared build settings into a solution-root `Directory.Build.props` and adopted a
repo-root `.editorconfig`, both mirroring the sibling repo `Enigma.Cryptography`. This removes
five duplicated MSBuild properties (`Authors`, `Copyright`, `LangVersion`, `Nullable`,
`TreatWarningsAsErrors`) from the five project files and newly enforces `TreatWarningsAsErrors`
and `EnforceCodeStyleInBuild` across the whole solution (previously only Tools and CLI treated
warnings as errors). The build is clean at **0 warnings** across all three target frameworks
(`netstandard2.0`, `net8.0`, `net10.0`) and the existing xUnit v2 suite still passes 76/76.

## Files/modules touched

**Created**
- `Directory.Build.props` — shared `Authors`, `Copyright`, `LangVersion 14`, `Nullable enable`,
  `TreatWarningsAsErrors true`, `EnforceCodeStyleInBuild true`. Build settings only — no version
  or package metadata (CPM invariant preserved).
- `.editorconfig` — ported verbatim from `Enigma.Cryptography/.editorconfig` (general C# style,
  nothing crypto-specific). Severities kept as-is, including `IDE0005` at `suggestion` (build-time
  IDE0005 would require `GenerateDocumentationFile` in the app/test projects).

**Modified**
- `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj` — removed `Nullable`, `LangVersion`,
  `Authors`, `Copyright`. Kept `OutputType`, `TargetFrameworks`, full package metadata,
  `Version 1.2.0`, `GeneratePackageOnBuild`, `GenerateDocumentationFile`. Now inherits
  `TreatWarningsAsErrors` from `Directory.Build.props` (new for this project).
- `src/Enigma.LicenseManager.Tools/…csproj` — removed `LangVersion`, `Nullable`,
  `TreatWarningsAsErrors`, `Authors`, `Copyright`. Kept `TargetFramework net8.0`,
  `ImplicitUsings disable`, `GenerateDocumentationFile`, `IsPackable false`.
- `src/Enigma.LicenseManager.Cli/…csproj` — removed `LangVersion`, `Nullable`,
  `TreatWarningsAsErrors`, `Authors`, `Copyright`. Kept `OutputType`, `TargetFramework net10.0`,
  `ImplicitUsings disable`, `RootNamespace`, `AssemblyName enigma-license`, `Version 1.0.0`,
  `IsPackable false`.
- `src/Enigma.LicenseManager.Desktop/…csproj` — removed `Nullable`, `LangVersion`, `Authors`,
  `Copyright`. Kept `OutputType WinExe`, `TargetFramework net10.0`,
  `AvaloniaUseCompiledBindingsByDefault`. Now inherits `TreatWarningsAsErrors` +
  `EnforceCodeStyleInBuild` (new for this project).
- `src/UnitTests/UnitTests.csproj` — removed `Nullable` and `LangVersion 13` (the hoisted `14`
  now applies — a harmless superset). Kept `TargetFramework net10.0`, `IsPackable false`. Now
  inherits `TreatWarningsAsErrors` + `EnforceCodeStyleInBuild` (new for this project).
- `src/Enigma.LicenseManager.Desktop/Program.cs` — added `internal` to `sealed class Program`
  (the only code fix required; see below).
- `docs/roadmap.md`, `docs/plan/FEATURE-004.md` — status updates (`IN PROGRESS` → `DONE` for
  PHASE01; the item stays `IN PROGRESS`).

## Deviations & follow-ups

- **One code fix triggered by the newly-hoisted rules:** enabling `EnforceCodeStyleInBuild` +
  `TreatWarningsAsErrors` on the Desktop project surfaced a single `IDE0040` error
  (`Program.cs:13` — accessibility modifier required). Fixed by making the implicit default
  explicit: `sealed class Program` → `internal sealed class Program`. No rule downgrade was
  needed — this was the plan's "fix code to comply" path, and it was the only violation across
  the entire solution.
- **No missing-XML-doc (CS1591) errors** appeared in the core library despite it having both
  `GenerateDocumentationFile=true` and (now) `TreatWarningsAsErrors=true` — its public surface
  is already fully documented.
- **Line endings (recommendation only, no action taken):** the working diff shows no CRLF/LF
  churn; touched-file deltas match the removed lines exactly. The repo still has no
  `.gitattributes`. As already noted in the FEATURE-004 plan's *Out of scope*, a separate commit
  adding `.gitattributes` (`* text=auto eol=lf`) followed by `git add --renormalize .` is
  recommended. The new `.editorconfig`'s `end_of_line = lf` is an editor hint only and performs
  no normalization. **This dev ran no `git renormalize`.**

## Build/test evidence

- `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s), 0 Error(s)**
  across `netstandard2.0`, `net8.0`, `net10.0`.
- `dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0, Passed: 76, Skipped: 0,
  Total: 76** (still xUnit v2 — v3 migration is PHASE03).
- `Enigma.LicenseManager.1.2.0.nupkg` content verified unchanged: `id`/`version 1.2.0`/`title`/
  `authors`/`copyright`/`description`/`tags`/`repository`/`license`/`readme` all present
  (`authors`/`copyright` now sourced from `Directory.Build.props`); `lib/net8.0` +
  `lib/netstandard2.0` DLLs & XML docs, README.md, LICENSE.md, and both dependency groups
  (DeviceId 6.11.0, Enigma.Cryptography 5.0.0, Newtonsoft.Json 13.0.4, Ulid 1.4.1) intact.
