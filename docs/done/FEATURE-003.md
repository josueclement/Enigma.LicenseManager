# FEATURE-003 — Upgrade Enigma.Cryptography to 5.0.0 + Central Package Management (DONE)

## Summary

Moved the whole solution to **Enigma.Cryptography 5.0.0** and introduced **Central Package
Management (CPM)**. All package versions are now pinned once in a root `Directory.Packages.props`;
every `<PackageReference>` in the five projects is version-less. This upgrade is a
recompile-and-verify (the consumed 5.0.0 surface is source-identical to 4.3.0 — none of the seven
documented breaking changes touch a call site here), and CPM also resolves the previous
cross-project version drift (core was 4.2.1, Tools/Desktop were 4.3.0). No C#, test, or PEM
test-data file was changed — the existing 4.x-generated ML-DSA/RSA key fixtures loaded under 5.0.0
are the cross-version regression guard, and they pass.

## Files / modules touched

**Created**
- `Directory.Packages.props` (repo root) — `ManagePackageVersionsCentrally=true` + 22
  `<PackageVersion>` entries; `Enigma.Cryptography` set to `5.0.0`.
- `docs/done/FEATURE-003.md` (this file).

**Modified**
- `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj` — stripped `Version` from `DeviceId`,
  `Enigma.Cryptography`, `Newtonsoft.Json`, `Ulid`; bumped the library's own
  `<Version>` **1.1.0 → 1.2.0**.
- `src/Enigma.LicenseManager.Tools/Enigma.LicenseManager.Tools.csproj` — stripped `Version` from
  `Enigma.Cryptography`, `Microsoft.Extensions.DependencyInjection.Abstractions`, `Ulid`.
- `src/Enigma.LicenseManager.Desktop/Enigma.LicenseManager.Desktop.csproj` — stripped `Version`
  from all refs; kept the `AvaloniaUI.DiagnosticsSupport` `IncludeAssets`/`PrivateAssets`
  conditional child block.
- `src/Enigma.LicenseManager.Cli/Enigma.LicenseManager.Cli.csproj` — stripped `Version` from
  `System.CommandLine`, `Microsoft.Extensions.Hosting`; the CLI's own `<Version>1.0.0</Version>`
  left unchanged.
- `src/UnitTests/UnitTests.csproj` — stripped `Version` from `coverlet.collector`,
  `Microsoft.Extensions.DependencyInjection`, `Microsoft.NET.Test.Sdk`, `xunit`,
  `xunit.runner.visualstudio`; kept the `PrivateAssets`/`IncludeAssets` metadata on
  `coverlet.collector` and `xunit.runner.visualstudio`.
- `docs/roadmap.md`, `docs/plan/FEATURE-003.md` — status → `DONE`.

**Deleted** — none.

## Deviations & follow-ups

- **No deviations from the plan.** Package tally came to exactly the 22 distinct packages the plan's
  `Directory.Packages.props` lists, at the same versions; the design was applied verbatim.
- The CLI and UnitTests projects have no *direct* `Enigma.Cryptography` reference (they consume it
  transitively via project references) — expected; nothing to convert there for that package.
- **Line endings (CRLF):** no line-ending churn observed in the touched files; no normalization
  performed (recommendation-only per the house workflow).

## Build / test evidence

- `dotnet restore Enigma.LicenseManager.slnx` — all 5 projects restored; `Enigma.Cryptography 5.0.0`
  resolved under CPM.
- `dotnet build Enigma.LicenseManager.slnx -warnaserror` — **Build succeeded, 0 Warning(s),
  0 Error(s)** across core `netstandard2.0`+`net8.0`, Tools `net8.0` (`TreatWarningsAsErrors`),
  Desktop/CLI/Tests `net10.0`. Core packed as `Enigma.LicenseManager.1.2.0.nupkg`. (AC 1)
- `dotnet test Enigma.LicenseManager.slnx` — **Passed: 76, Failed: 0, Skipped: 0** (RSA + ML-DSA
  sign/verify round-trips, encrypted-PEM load/save with password `test1234`, wrong-key negatives,
  CLI tests). The ML-DSA fixtures loading 4.x-generated keys under 5.0.0 confirm cross-version
  compatibility — no upstream BouncyCastle 2.6.2 incompatibility surfaced. (AC 2)
- `dotnet list Enigma.LicenseManager.slnx package` — every direct `Enigma.Cryptography` reference
  resolves to **5.0.0**; no 4.x remains. `grep` confirms **no `Version=` attribute** remains on any
  `<PackageReference>`. (AC 3)
- Packed nuspec (`Enigma.LicenseManager.1.2.0.nupkg`) — `<version>1.2.0</version>` with
  `<dependency id="Enigma.Cryptography" version="5.0.0" />` (i.e. `>= 5.0.0` floor) for both the
  `net8.0` and `.NETStandard2.0` dependency groups. (AC 4)
