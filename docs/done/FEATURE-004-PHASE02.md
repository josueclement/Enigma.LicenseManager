# FEATURE-004 · PHASE02 — `Directory.Packages.props` overhaul + non-Avalonia dependency refresh

## Summary

Reorganized the Central Package Management manifest (`Directory.Packages.props`) from a single flat
`ItemGroup` into commented, per-consumer category groups (Core / Tools / CLI / Desktop / Tests), and
refreshed every non-Avalonia dependency to current stable versions. The entire Avalonia ecosystem
(`Avalonia.*`, `AvaloniaUI.DiagnosticsSupport`, `Carbon.Avalonia.Desktop`, `PhosphorIconsAvalonia`,
plus `CommunityToolkit.Mvvm`) was deliberately held at its current versions — Avalonia work is reserved
for the next feature. The CPM invariant is preserved: versions live only in this file.

## Version bumps

| Package                                              | From    | To       | Notes |
|------------------------------------------------------|---------|----------|-------|
| `coverlet.collector`                                 | 8.0.0   | 10.0.1   | Two-major jump (no 9.x shipped); coverage collection re-verified below |
| `Microsoft.Extensions.DependencyInjection.Abstractions` | 8.0.2 | 10.0.9   | Now aligned with `…DependencyInjection` 10.0.9 |
| `Microsoft.NET.Test.Sdk`                             | 18.3.0  | 18.7.0   | |
| `NLog`                                               | 6.1.3   | 6.1.4    | |
| `NLog.Extensions.Logging`                            | 6.1.3   | 6.1.4    | |

Held unchanged (already latest or newer is prerelease-only): Avalonia 12.0.5 ×4, AvaloniaUI.DiagnosticsSupport 2.2.3,
Carbon.Avalonia.Desktop 0.2.0, CommunityToolkit.Mvvm 8.4.2, DeviceId 6.11.0, Enigma.Cryptography 5.0.0,
Microsoft.Extensions.DependencyInjection 10.0.9, Microsoft.Extensions.Hosting 10.0.9, Newtonsoft.Json 13.0.4,
PhosphorIconsAvalonia 1.2.0, System.CommandLine 2.0.9, Ulid 1.4.1.

## Files touched

- **Modified:** `Directory.Packages.props` — regrouped into 5 commented category `ItemGroup`s; bumped the 5 packages above.
- **Modified:** `docs/roadmap.md`, `docs/plan/FEATURE-004.md` — PHASE02 status TODO → IN PROGRESS → DONE.
- **Created:** `docs/done/FEATURE-004-PHASE02.md` (this file).

## Deviations & follow-ups

- **xUnit v2 packages retained.** The plan's PHASE02 Tests-category list omits `xunit` (2.9.3) and
  `xunit.runner.visualstudio` (3.1.5). These are still required for the (still-xUnit-v2) test suite to compile and
  run, and are removed only in PHASE03. They are kept in the Tests group here, consistent with PHASE02's acceptance
  criterion ("existing test suite (still xUnit v2) passes"). No deviation from intent.
- **Line endings (CRLF):** no line-ending inconsistency observed in the touched file; no action taken (per house policy,
  line-ending normalization is never part of a dev).

## Build / test evidence

- `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s), 0 Error(s)**; core lib built for
  `netstandard2.0` + `net8.0`, Tools `net8.0`, CLI/Tests/Desktop `net10.0`. `Enigma.LicenseManager.1.2.0.nupkg` produced.
- `dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0, Passed: 76, Skipped: 0** (parity with the prior 76).
- `dotnet test … --collect:"XPlat Code Coverage"` → coverage report emitted
  (`coverage.cobertura.xml`), confirming coverlet.collector 10.0.1 still collects.
- nupkg dependency floors verified unchanged for both TFM groups: DeviceId 6.11.0, Enigma.Cryptography 5.0.0,
  Newtonsoft.Json 13.0.4, Ulid 1.4.1.
