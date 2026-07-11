# FEATURE-004-PHASE03 — xUnit v2 → v3 migration

**Status:** DONE
**Branch:** `feature/feature-004-phase03-xunit-v3`

## Summary

Migrated the `UnitTests` project from xUnit v2 (VSTest) to **xUnit v3** on the Microsoft Testing
Platform, matching the sibling `Enigma.Cryptography` repo. The test project is now a self-launching
executable (`OutputType=Exe`, `TestingPlatformDotnetTestSupport=true`) referencing `xunit.v3` instead
of the `xunit` + `xunit.runner.visualstudio` pair. All 76 tests pass — full parity with the v2 suite —
and the whole solution builds clean with 0 warnings across `netstandard2.0`/`net8.0`/`net10.0`.

## Files/modules touched

**Modified**
- `Directory.Packages.props` — Tests group: removed `xunit` (2.9.3) and `xunit.runner.visualstudio`
  (3.1.5); added `xunit.v3` **3.2.2** (matching the sibling). `Microsoft.NET.Test.Sdk` (18.7.0),
  `coverlet.collector` (10.0.1) and `Microsoft.Extensions.DependencyInjection` (10.0.9) unchanged.
  Refreshed the group comment.
- `src/UnitTests/UnitTests.csproj` — added `<OutputType>Exe</OutputType>`,
  `<RootNamespace>UnitTests</RootNamespace>`, `<TestingPlatformDotnetTestSupport>true</…>`; swapped the
  xUnit package references for a single `xunit.v3`. Preserved the `Data\*.pem` copy items, the three
  project references, the `Microsoft.Extensions.DependencyInjection` reference (DI is used in
  `ToolsTests`), the coverlet metadata, and the `<Using Include="Xunit"/>` global-using item.
- `src/UnitTests/Tests.cs` — `KeyFixture` `IAsyncLifetime` members now return `ValueTask` (v3 signature)
  instead of `Task`; threaded `TestContext.Current.CancellationToken` into the `SaveAsync`/`LoadAsync`
  calls (xUnit1051).
- `src/UnitTests/ToolsTests.cs` — threaded `TestContext.Current.CancellationToken` into every
  token-accepting service call inside test bodies (xUnit1051).

`CliTests.cs` needed no changes.

**Documentation freshness sweep**
- `CLAUDE.md` — Build & Test: added a note that `UnitTests` runs on xUnit v3 (executable-based) and that
  `DOTNET_ROOT` must point at the SDK dir if the test apphost can't find the runtime. Key Conventions:
  updated the test bullet to state the suite runs on xUnit v3 (Microsoft Testing Platform) with a
  `ValueTask`-based `KeyFixture`. (README / RELEASENOTES / `docs/RELEASE.md` refreshes remain PHASE04's.)

## Deviations & follow-ups

- **`xunit.v3` version:** the plan said "latest stable; sibling uses 3.2.2". Chose **3.2.2** to match the
  sibling exactly (the item's stated objective is repo alignment) and for reproducible offline restore,
  rather than chase an unverified newer build.
- **`xUnit1051` (new v3 analyzer), not called out in the plan:** v3 ships an analyzer that flags every
  call passing a defaulted `CancellationToken`, which failed the `TreatWarningsAsErrors` build at 43
  sites. Resolved the way the sibling did — threading `TestContext.Current.CancellationToken` into each
  call inside a test method — rather than downgrading the rule, so both the code **and** the
  `.editorconfig` stay aligned with the sibling (whose `.editorconfig` does not suppress xUnit1051).
- **`dotnet test` now requires `DOTNET_ROOT` on this machine.** v3 test projects launch as native
  executables; the apphost probes `/usr/share/dotnet` and `DOTNET_ROOT`, but this box's SDK is at
  `~/.dotnet`, so the run fails with "You must install .NET to run this application" unless
  `DOTNET_ROOT=/home/jo/.dotnet` is set (`DOTNET_ROOT=/home/jo/.dotnet dotnet test …`). Environment-
  specific (a default `/usr/share/dotnet` install needs nothing); under v2 the dotnet-hosted test host
  resolved the runtime, so this is new. *Recommendation:* export `DOTNET_ROOT` in the shell profile / CI,
  or note it in the build docs.
- **`warning MTP0001`** ("VSTest-specific properties … ignored when using Microsoft.Testing.Platform":
  `VSTestTestAdapterPath`) is emitted by the MTP MSBuild targets during `dotnet test`. It is benign,
  does not appear in `dotnet build -warnaserror` (which is 0 warnings), and the sibling's identical stack
  produces it too. Left as-is for sibling parity.
- **Coverage under MTP:** `coverlet.collector` is retained, but Microsoft Testing Platform collects
  coverage via `dotnet test --coverage` (Microsoft code-coverage extension) rather than the VSTest
  `--collect "XPlat Code Coverage"` data collector. Not exercised in this phase (coverage was a PHASE02
  acceptance item); flagged for awareness if a coverage report is regenerated.
- **Line endings (CRLF):** no line-ending churn observed in the touched files; no action taken (per house
  policy this is recommendation-only).

## Build/test evidence

- **Build:** `dotnet build Enigma.LicenseManager.slnx -warnaserror` → **Build succeeded. 0 Warning(s),
  0 Error(s)** across `netstandard2.0`, `net8.0`, `net10.0`.
- **Tests:** `DOTNET_ROOT=/home/jo/.dotnet dotnet test Enigma.LicenseManager.slnx` →
  **Passed! Failed: 0, Passed: 76, Skipped: 0, Total: 76** on `UnitTests.dll (net10.0|x64)` running the
  xUnit v3 / Microsoft Testing Platform runner. Parity with the previous 76-test v2 suite.

## Acceptance criteria

- [x] `dotnet test` runs on xUnit v3 — MTP runner, `xunit.v3` 3.2.2.
- [x] All tests pass, parity with the 76 previously passing.
- [x] 0-warning build.
