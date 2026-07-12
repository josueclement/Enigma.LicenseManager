# FEATURE-005-PHASE01 — Bump Avalonia to 12.1.0

## Summary
Picked up the deferred Avalonia stack update. Bumped the four `Avalonia.*` packages
from `12.0.5` to `12.1.0` in Central Package Management, and refreshed the now-stale
"held at current versions" comment on the Desktop package group. The other Desktop
packages (`Carbon.Avalonia.Desktop`, `PhosphorIconsAvalonia`, `CommunityToolkit.Mvvm`,
`AvaloniaUI.DiagnosticsSupport`) were already latest and left unchanged, as the plan
specified; their min-Avalonia constraints (≥12.0.2 / ≥12.0.0) are satisfied by 12.1.0.

## Files/modules touched
**Modified**
- `Directory.Packages.props` — four `Avalonia.*` `<PackageVersion>` lines `12.0.5 → 12.1.0`
  (`Avalonia`, `Avalonia.Desktop`, `Avalonia.Fonts.Inter`, `Avalonia.Themes.Fluent`);
  updated the Desktop group comment.
- `src/Enigma.LicenseManager.Desktop/Helpers/AppIconHelper.cs` — migrated one deprecated
  API call (see Deviations).

## Deviations & follow-ups
- **Unplanned but required one-line fix in `AppIconHelper.cs`.** Avalonia 12.1.0 marks
  `Bitmap.Save(Stream, int?)` `[Obsolete]`, and with the solution-wide
  `TreatWarningsAsErrors=true` this failed PHASE01's own "zero-warning build" acceptance
  criterion. Migrated `rtb.Save(ms)` → `rtb.Save(ms, PngBitmapEncoderOptions.Default)`,
  the exact behavior-preserving replacement (the obsolete overload internally used
  `PngBitmapEncoderOptions.Default`). No new `using` needed — `PngBitmapEncoderOptions`
  is in `Avalonia.Media.Imaging`, already imported. The plan scoped PHASE01 to
  `Directory.Packages.props` only, but a clean build was impossible without this.
- **PHASE03 interaction:** `AppIconHelper.cs` is slated for deletion in PHASE03, so this
  migration is transitional — it will be removed with the file. No action needed now; just
  noting that the fix does not need to be preserved beyond PHASE03.
- **Pre-existing `MTP0001` note** surfaces during `dotnet test` (Microsoft Testing Platform
  ignoring VSTest-specific properties). It predates this phase, comes from the xUnit v3 test
  infrastructure (FEATURE-004-PHASE03), does not fail the build, and is out of PHASE01 scope.
- **Line endings:** no CRLF churn observed (`git diff --check` clean; touched files are LF).

## Build/test evidence
- `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded. 0 Warning(s), 0 Error(s)**
  on Avalonia 12.1.0 (restore succeeded — 12.1.0 resolved from NuGet as planned).
- `dotnet test Enigma.LicenseManager.slnx` (with `DOTNET_ROOT=~/.dotnet`) →
  **Passed! Failed: 0, Passed: 76, Skipped: 0, Total: 76.**
- Manual run (`dotnet run --project src/Enigma.LicenseManager.Desktop`) → app launched and
  ran without crash or error output on 12.1.0 (verified via a timed 15s foreground run that
  exited only on the timeout, code 124).
