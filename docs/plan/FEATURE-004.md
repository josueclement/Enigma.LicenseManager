# FEATURE-004 — Prepare the 1.2.0 release

**Status:** IN PROGRESS (planned via `/interview`; implement with `/build FEATURE-004`)
**Type:** FEATURE (multi-phase, 4 phases)

## Objective

Get Enigma.LicenseManager into a production-ready, shippable `1.2.0` state and align its repository
structure with the sibling repo `Enigma.Cryptography`. The `1.2.0` version and the `v1.2.0` RELEASENOTES
entry already exist (delivered in FEATURE-003), so this item is a **production-readiness pass**, not a
version bump: build-config consolidation, code-style parity, a non-Avalonia dependency refresh, an
xUnit v2→v3 test migration, and a documentation sweep + release checklist.

## Scope & key decisions

- **Code style — full parity + fix violations.** Port/adapt Enigma.Cryptography's `.editorconfig`, enable
  `EnforceCodeStyleInBuild`, hoist `Nullable`/`TreatWarningsAsErrors` solution-wide, and fix (or, for a
  genuinely noisy rule, downgrade) every surfaced violation to a zero-warning build.
- **Dependencies — update all except the Avalonia ecosystem.** Hold the 4 `Avalonia.*` packages **plus**
  `Carbon.Avalonia.Desktop`, `PhosphorIconsAvalonia`, `AvaloniaUI.DiagnosticsSupport` (version-coupled to
  Avalonia; Avalonia work is reserved for the *next* feature). Bump only the non-Avalonia packages.
- **Tests — migrate to xUnit v3** (matching the sibling), not a v2 bump.
- **Release mechanics — documented, not executed.** Deliver a reusable `docs/RELEASE.md` runbook; the
  customer runs the tag/merge/publish steps themselves.
- **CPM invariant preserved:** versions live only in `Directory.Packages.props`; `<PackageReference>` items
  carry no `Version`. `Directory.Build.props` holds shared *build* settings only — no version/package metadata.

## Out of scope (recommendations only)

- **Line endings / `.gitattributes`:** repo has none; per house policy this is never a task. *Recommendation:*
  add `.gitattributes` (`* text=auto eol=lf`) + `git add --renormalize .` in a separate commit. This item runs
  no `git renormalize`; the ported `.editorconfig`'s `end_of_line = lf` is an editor hint only.
- **Stale empty root dirs** (`ConsoleApp1/`, `Enigma.LicenseManager/`, `UnitTests/` with leftover `bin`/`obj`):
  gitignored clutter, safe to delete manually.
- **Avalonia 12.0.5 → 12.1.0** available (low-risk minor) but deliberately deferred to the next feature.

---

## PHASE01 — Build-settings consolidation

**Status:** DONE · Suggested branch: `feature/feature-004-phase01-build-props`

- Add root `Directory.Build.props` mirroring `../Enigma.Cryptography/Directory.Build.props`: `Authors`,
  `Copyright`, `LangVersion 14`, `Nullable enable`, `TreatWarningsAsErrors true`, `EnforceCodeStyleInBuild true`.
- Remove the now-duplicated props from all 5 csprojs (`Authors`, `Copyright`, `LangVersion`, `Nullable`,
  `TreatWarningsAsErrors`). Keep per-project: `TargetFramework(s)`, `OutputType`, `IsPackable`, library package
  metadata + `<Version>1.2.0</Version>`, `GenerateDocumentationFile` (core + Tools only), `ImplicitUsings disable`
  (Tools/CLI), `AssemblyName`/`RootNamespace` (CLI), `AvaloniaUseCompiledBindingsByDefault` (Desktop),
  CLI `<Version>1.0.0</Version>`.
- Port/adapt `.editorconfig` from Enigma.Cryptography to repo root (keep its severities, incl. IDE0005 at suggestion).
- **Risk:** hoisting warnings-as-errors + code-style enforcement newly applies to core, Desktop and Tests. Desktop
  (Avalonia XAML + compiled bindings + ViewModels) is the likeliest source of new errors — build everything, then
  fix code to comply or downgrade a noisy rule.
- **Files:** new `Directory.Build.props`, new `.editorconfig`; edit `Enigma.LicenseManager.csproj`,
  `Enigma.LicenseManager.Tools.csproj`, `Enigma.LicenseManager.Cli.csproj`, `Enigma.LicenseManager.Desktop.csproj`,
  `src/UnitTests/UnitTests.csproj`.
- **Acceptance:** `dotnet build Enigma.LicenseManager.slnx` = **0 warnings** across `netstandard2.0`/`net8.0`/`net10.0`;
  existing test suite (still xUnit v2) passes; `Enigma.LicenseManager.1.2.0.nupkg` content unchanged.

## PHASE02 — `Directory.Packages.props` overhaul

**Status:** DONE · Suggested branch: `feature/feature-004-phase02-packages`

- Reorganize the single flat `ItemGroup` into commented category groups, keeping the leading
  `ManagePackageVersionsCentrally` PropertyGroup:
  - **Core library:** DeviceId, Enigma.Cryptography, Newtonsoft.Json, Ulid
  - **Tools:** Microsoft.Extensions.DependencyInjection.Abstractions
  - **CLI:** System.CommandLine, Microsoft.Extensions.Hosting
  - **Desktop (Avalonia):** Avalonia, Avalonia.Desktop, Avalonia.Fonts.Inter, Avalonia.Themes.Fluent,
    AvaloniaUI.DiagnosticsSupport, Carbon.Avalonia.Desktop, CommunityToolkit.Mvvm, NLog, NLog.Extensions.Logging,
    PhosphorIconsAvalonia
  - **Tests:** Microsoft.NET.Test.Sdk, coverlet.collector, Microsoft.Extensions.DependencyInjection
- Bump non-Avalonia packages (hold the entire Avalonia ecosystem at current versions):
  - `coverlet.collector` 8.0.0 → **10.0.1** — two-major jump (no 9.x shipped); verify coverage still collects
  - `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.2 → **10.0.9** — aligns with `…DependencyInjection` 10.0.9
  - `Microsoft.NET.Test.Sdk` 18.3.0 → **18.7.0**
  - `NLog` 6.1.3 → **6.1.4** · `NLog.Extensions.Logging` 6.1.3 → **6.1.4**
  - Unchanged (already latest, or newer is prerelease-only): CommunityToolkit.Mvvm, DeviceId, Enigma.Cryptography,
    Microsoft.Extensions.DependencyInjection, Microsoft.Extensions.Hosting, Newtonsoft.Json, System.CommandLine, Ulid.
- **Files:** `Directory.Packages.props`.
- **Acceptance:** 0-warning build all TFMs; all tests pass; `netstandard2.0` core lib restores/builds; nupkg packs with
  correct dependency floors; coverage report still emitted.

## PHASE03 — xUnit v3 migration

**Status:** DONE · Suggested branch: `feature/feature-004-phase03-xunit-v3`

- Rewrite `src/UnitTests/UnitTests.csproj` to mirror `../Enigma.Cryptography/src/UnitTests/UnitTests.csproj`:
  `OutputType=Exe`, `TestingPlatformDotnetTestSupport=true`; references `Microsoft.NET.Test.Sdk` + `xunit.v3` +
  `coverlet.collector`; remove `xunit` and `xunit.runner.visualstudio`. Preserve the `Data\*.pem` copy items and
  the three project references; keep the `Microsoft.Extensions.DependencyInjection` reference if the tests use DI.
- Update `Directory.Packages.props` Tests group: add `xunit.v3` (latest stable; sibling uses 3.2.2), remove `xunit`
  and `xunit.runner.visualstudio`.
- Adjust test code for the v3 API where needed (namespace `Xunit` is unchanged; watch `IAsyncLifetime`/fixture
  signatures and a few `Assert` changes — esp. the shared `KeyFixture`).
- **Files:** `src/UnitTests/UnitTests.csproj`, `Directory.Packages.props`, possibly `Tests.cs` / `ToolsTests.cs` / `CliTests.cs`.
- **Acceptance:** `dotnet test Enigma.LicenseManager.slnx` runs on xUnit v3, all tests pass (parity with the 76 currently
  passing); 0-warning build.

## PHASE04 — Production-readiness docs & release checklist

**Status:** TODO · Suggested branch: `feature/feature-004-phase04-docs`

- **README.md:** add NuGet-version + MIT-license badges; verify RSA / ML-DSA / device-binding / `LicenseService`
  samples and the `enigma-license` CLI command + exit-code reference against the built 1.2.0, correcting drift.
- **Library csproj:** add `<PackageReleaseNotes>` (prose summary pointing to `RELEASENOTES.md`, like the sibling).
- **RELEASENOTES.md:** expand the `v1.2.0` section to also cover FEATURE-004 (dependency refresh, xUnit v3,
  build-config consolidation).
- **CLAUDE.md:** refresh stale content — "three-class library" → current 4-class core (`License`, `LicenseBuilder`,
  `LicenseService`, `LicenseUtils`) + Tools/CLI/Desktop projects; document the new `Directory.Build.props` +
  `.editorconfig`; update the test stack to xUnit v3.
- **Add `docs/RELEASE.md`** — reusable checklist: merge path to `master`, `git tag v1.2.0`, `dotnet pack`,
  `dotnet nuget push`, post-publish badge verification.
- **Files:** `README.md`, `RELEASENOTES.md`, `CLAUDE.md`, `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj`,
  new `docs/RELEASE.md`.
- **Acceptance:** docs well-formed and internally consistent; samples/CLI reference verified against the build; no
  build/test regressions.

---

## Definition of Done (per phase)

1. `dotnet build Enigma.LicenseManager.slnx` clean, **0 warnings**, all TFMs.
2. `dotnet test Enigma.LicenseManager.slnx` fully green (xUnit v2 for P01–P02, xUnit v3 for P03–P04).
3. All acceptance criteria for the phase met.
4. Roadmap + this plan file statuses updated.
5. `docs/done/FEATURE-004-PHASENN.md` completion record written.
