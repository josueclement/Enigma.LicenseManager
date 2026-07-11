# FEATURE-003 — Upgrade Enigma.Cryptography to 5.0.0 + Central Package Management

**Status:** DONE · **Type:** FEATURE (single-phase) · **Planned now, built later.**

## Objective

Move every project to **Enigma.Cryptography 5.0.0** (published 2026-07-10) with **no regression**, and
introduce **Central Package Management (CPM)** so package versions are pinned once for the whole
solution — which also resolves the current cross-project drift.

## Context

`Enigma.Cryptography` is currently pinned at **inconsistent versions** — core library `4.2.1`, `Tools`
and `Desktop` at `4.3.0` — because there is no central version management. 5.0.0 is a new major
version.

Investigation (upstream `RELEASENOTES.md` at git tag `5.0.0` + full call-site mapping) established the
fact that shapes this work: **none of the seven documented 5.0.0 breaking changes touch a single call
site in this solution.** The consumed surface is source-identical between 4.3.0 and 5.0.0:

- `new PublicKeyServiceFactory().CreateRsaService()` → `.Sign` / `.Verify` / `.GenerateKeyPair(int)`
  (`LicenseBuilder.cs`, `LicenseService.cs`, `KeyGenerationService.cs`)
- `new MLDsaServiceFactory().CreateDsa87Service()` → `.Sign` / `.Verify` / `.GenerateKeyPair()`
  (same files)
- `PemUtils.SaveKey` / `SavePrivateKey(..., "AES-256-CBC")` / `LoadKey` / `LoadPrivateKey`
  (`KeyGenerationService.cs`, `LicenseGenerationService.cs`, `LicenseValidationService.cs`, tests)
- `GetUtf8Bytes()` string extension, `Enigma.Cryptography.Extensions` (`License.cs`)

5.0.0 still ships `netstandard2.0` + `net8.0` (adds `net10.0`) on **BouncyCastle.Cryptography 2.6.2+**,
so the transitive `Org.BouncyCastle.*` types (`AsymmetricKeyParameter`, `AsymmetricCipherKeyPair`,
`GeneralSecurityException`) remain. The upgrade is therefore a **recompile-and-verify**, not a code
migration. Enigma.Cryptography is the only package with a cross-project version conflict today
(Ulid ×3 and Microsoft.Extensions.Hosting ×2 are already consistent), so the CPM migration is
mechanical and low-risk.

## Scope & key decisions

### In scope
1. **Introduce CPM** — new `Directory.Packages.props` at the solution root with
   `ManagePackageVersionsCentrally=true` and one `<PackageVersion>` per package (22 distinct).
2. **Convert all 5 `.csproj`** to CPM: strip the `Version="…"` attribute from every
   `<PackageReference>`, leaving `Include` and any `IncludeAssets`/`PrivateAssets`/`ExcludeAssets`/
   `Condition` metadata untouched.
3. **Set `Enigma.Cryptography` = `5.0.0`** centrally (was 4.2.1 / 4.3.0).
4. **Bump the core library's own package version** `<Version>` `1.1.0 → 1.2.0` in
   `Enigma.LicenseManager.csproj` (the project's *own* NuGet version — stays in the csproj; **not** a
   `PackageReference` version).

### Out of scope
- No changes to any C# source, tests, or PEM test-data files. The existing `MLDSA*/RSA*` fixtures load
  4.x-generated keys under the 5.0.0 library — that *is* the cross-version regression guard.
- No CPM transitive pinning (`CentralPackageTransitivePinningEnabled`) — not needed; no direct
  BouncyCastle reference exists.
- No line-ending / CRLF normalization (recommendation-only per house workflow).

### Decisions & provenance
- Classify as **FEATURE-003, single-phase** (no `CHORE` type in the scheme). *(architect decision)*
- Core library own version **1.1.0 → 1.2.0**. *(recommendation accepted)*
- Regression proof = **existing suite** (build clean all TFMs + full test pass). *(recommendation accepted)*
- **Introduce CPM** rather than aligning versions inline. *(user's explicit choice against the focused-scope recommendation)*
- Keep the Desktop project's explicit Enigma.Cryptography reference (now version-less under CPM);
  CLI's own `<Version>1.0.0</Version>` unchanged. *(low-impact defaults)*

## Design

### `Directory.Packages.props` (new, at repo root)

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Avalonia" Version="12.0.5" />
    <PackageVersion Include="Avalonia.Desktop" Version="12.0.5" />
    <PackageVersion Include="Avalonia.Fonts.Inter" Version="12.0.5" />
    <PackageVersion Include="Avalonia.Themes.Fluent" Version="12.0.5" />
    <PackageVersion Include="AvaloniaUI.DiagnosticsSupport" Version="2.2.3" />
    <PackageVersion Include="Carbon.Avalonia.Desktop" Version="0.2.0" />
    <PackageVersion Include="CommunityToolkit.Mvvm" Version="8.4.2" />
    <PackageVersion Include="coverlet.collector" Version="8.0.0" />
    <PackageVersion Include="DeviceId" Version="6.11.0" />
    <PackageVersion Include="Enigma.Cryptography" Version="5.0.0" />   <!-- was 4.2.1 / 4.3.0 -->
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection" Version="10.0.9" />
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="8.0.2" />
    <PackageVersion Include="Microsoft.Extensions.Hosting" Version="10.0.9" />
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="18.3.0" />
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.4" />
    <PackageVersion Include="NLog" Version="6.1.3" />
    <PackageVersion Include="NLog.Extensions.Logging" Version="6.1.3" />
    <PackageVersion Include="PhosphorIconsAvalonia" Version="1.2.0" />
    <PackageVersion Include="System.CommandLine" Version="2.0.9" />
    <PackageVersion Include="Ulid" Version="1.4.1" />
    <PackageVersion Include="xunit" Version="2.9.3" />
    <PackageVersion Include="xunit.runner.visualstudio" Version="3.1.5" />
  </ItemGroup>
</Project>
```

### `<PackageReference>` conversion (all 5 csproj)

Drop only the `Version` attribute; keep everything else. Example:

```xml
<PackageReference Include="Enigma.Cryptography" Version="4.3.0" />   <!-- before -->
<PackageReference Include="Enigma.Cryptography" />                    <!-- after  -->
```

- `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj` — `DeviceId`, `Enigma.Cryptography`,
  `Newtonsoft.Json`, `Ulid`; **also** `<Version>1.1.0</Version>` → `1.2.0`.
- `src/Enigma.LicenseManager.Tools/…csproj` — `Enigma.Cryptography`,
  `Microsoft.Extensions.DependencyInjection.Abstractions`, `Ulid`.
- `src/Enigma.LicenseManager.Desktop/…csproj` — all refs; **keep** the `AvaloniaUI.DiagnosticsSupport`
  child `<IncludeAssets>/<PrivateAssets>` conditional block, only remove its `Version`.
- `src/Enigma.LicenseManager.Cli/…csproj` — `System.CommandLine`, `Microsoft.Extensions.Hosting`.
- `src/UnitTests/UnitTests.csproj` — `coverlet.collector`, `Microsoft.Extensions.DependencyInjection`,
  `Microsoft.NET.Test.Sdk`, `xunit`, `xunit.runner.visualstudio`; **keep** the asset/`PrivateAssets`
  metadata on `coverlet.collector` and `xunit.runner.visualstudio`.

### Notes / gotchas
- Only the core library's `<Version>` bumps to 1.2.0; the CLI's `<Version>1.0.0</Version>` is left alone.
- `GeneratePackageOnBuild` on the core library still works under CPM — the packed `.nupkg` dependency
  floor becomes `Enigma.Cryptography >= 5.0.0` (and Newtonsoft.Json / DeviceId / Ulid) automatically
  from the central `<PackageVersion>` entries.
- No `Directory.Build.props` / `nuget.config` exists to conflict with the new props file.

## Acceptance criteria

1. `dotnet build Enigma.LicenseManager.slnx` succeeds with **zero warnings** across all target
   frameworks (core `netstandard2.0`+`net8.0`; Tools `net8.0` with `TreatWarningsAsErrors`;
   Desktop/CLI/Tests `net10.0`).
2. `dotnet test Enigma.LicenseManager.slnx` — **entire suite green** (RSA + ML-DSA sign/verify
   round-trips, encrypted-PEM load/save with password `test1234`, wrong-key negatives, CLI tests).
   The ML-DSA fixture tests loading 4.x-generated keys under 5.0.0 confirm cross-version compatibility.
3. All `Enigma.Cryptography` references resolve to **5.0.0** (`dotnet list package`); no project still
   pins 4.x; no `Version` attribute remains on any `<PackageReference>`.
4. Core library packs as **1.2.0** with a dependency on `Enigma.Cryptography >= 5.0.0`.
5. Roadmap + this plan's status updated; `docs/done/FEATURE-003.md` written.

## Verification (end-to-end, at build time)

```bash
dotnet restore Enigma.LicenseManager.slnx
dotnet build   Enigma.LicenseManager.slnx -warnaserror   # 0 warnings, 0 errors
dotnet test    Enigma.LicenseManager.slnx                # all green
dotnet list Enigma.LicenseManager.slnx package           # Enigma.Cryptography 5.0.0 everywhere
```

Optional real-world smoke via the CLI (`enigma-license`): generate a key pair, create a license,
validate it — end-to-end against 5.0.0. **Risk note:** if the ML-DSA fixture tests fail (the one
theoretical risk from the transitive BouncyCastle 2.6.2 bump), that is a genuine upstream
incompatibility to surface and discuss — **not** to be papered over by silently regenerating the
committed test keys.
