# v1.2.0 Release Notes

A production-readiness release for the core library — no public API or behavioural change to the
library itself — with a full pass over dependencies, the test stack, and build configuration to align
the repository with its sibling `Enigma.Cryptography`, plus a round of desktop-app usability
improvements. The library upgrade is recompile-and-verify — licenses and keys created with earlier 1.x
releases remain compatible.

## Dependencies

- **Upgrade `Enigma.Cryptography` to 5.0.0:** The library now builds against `Enigma.Cryptography` 5.0.0 (from 4.x). The consumed cryptographic surface is source-identical between 4.3.0 and 5.0.0, so this is a recompile-and-verify with no API or behavioural change — RSA and ML-DSA sign/verify round-trips and encrypted-PEM load/save are unaffected, and licenses/keys created with 4.x remain compatible. The packaged dependency floor is now `Enigma.Cryptography >= 5.0.0`.
- **Refresh non-Avalonia dependencies:** `coverlet.collector` 8.0.0 → 10.0.1, `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.2 → 10.0.9 (aligned with `Microsoft.Extensions.DependencyInjection` 10.0.9), `Microsoft.NET.Test.Sdk` 18.3.0 → 18.7.0, and `NLog` / `NLog.Extensions.Logging` 6.1.3 → 6.1.4. The core library's packaged dependencies (`DeviceId`, `Newtonsoft.Json`, `Ulid`) were already current and are unchanged.
- **Bump the Avalonia core to 12.1.0:** the four version-coupled `Avalonia.*` packages (`Avalonia`, `Avalonia.Desktop`, `Avalonia.Fonts.Inter`, `Avalonia.Themes.Fluent`) moved together 12.0.5 → 12.1.0. The remaining Avalonia-coupled packages — `Carbon.Avalonia.Desktop` 0.2.0, `PhosphorIconsAvalonia` 1.2.0, and `AvaloniaUI.DiagnosticsSupport` 2.2.3 — were verified compatible with 12.1.0 and held at their current (latest) versions. All Avalonia packages are Desktop-app-only and do not enter the published library's dependency floor.

## Build & Tooling

- **Introduce Central Package Management (CPM):** Package versions are now pinned once in a solution-root `Directory.Packages.props` (`ManagePackageVersionsCentrally=true`); individual `<PackageReference>` items no longer carry a `Version`. This also removes the previous cross-project version drift of `Enigma.Cryptography`.
- **Consolidate build settings:** shared build properties (`Authors`, `Copyright`, `LangVersion 14`, `Nullable enable`, `TreatWarningsAsErrors true`, `EnforceCodeStyleInBuild true`) moved out of the individual csprojs into a solution-root `Directory.Build.props`, with a repository-root `.editorconfig` carrying the code-style rules. Warnings-as-errors and code-style enforcement now apply solution-wide, and the build is warning-free across all target frameworks.

## Tests

- **Migrate to xUnit v3:** the `UnitTests` project moved from xUnit v2 to xUnit v3 on the Microsoft Testing Platform (`OutputType=Exe`, `TestingPlatformDotnetTestSupport=true`), matching the sibling repository. The `xunit` and `xunit.runner.visualstudio` packages were replaced by `xunit.v3`; the full suite passes on the new runner.

## Desktop app

These improvements affect the `Enigma.LicenseManager.Desktop` (Avalonia) app only; the published core library is unchanged.

- **Avalonia bumped to 12.1.0** (see *Dependencies*).
- **Default RSA key size is now 4096** on the Generate Keys page (was 2048) — a safer pre-selected default; switching to ML-DSA and back to RSA preserves it.
- **Real embedded app icon:** a committed multi-resolution `appicon.ico` is embedded in the executable and used for the window/taskbar, replacing the previously runtime-synthesized icon.
- **Reusable license profiles:** the Generate Licenses page can save/load the form fields (product ID, owner, device ID, signing algorithm, expiration, and signing-key path) to a `.json` profile, removing repetitive re-entry. The signing-key password is never persisted.
- **Windows installer (MSI):** the desktop app can now be packaged as a Windows MSI installer ("Enigma License Manager", per-machine, with Start Menu and Desktop shortcuts). A committed WixSharp build profile lives under `msiProfiles/`; see [`docs/RELEASE.md`](docs/RELEASE.md) for the build steps. The app itself is unchanged.

# v1.1.0 Release Notes

## Breaking Changes

- **Fix `GetDataForSignature()` copy-paste bug (#1):** The `Id` field was incorrectly serialized as `DeviceId` in the signature data. Licenses signed with v1.0.0 will fail verification in v1.1.0. Re-sign existing licenses after upgrading.
- **Device ID generation unchanged from v1.0.0:** MAC address was considered but excluded from `GenerateDeviceId()` because removable network adapters (WiFi dongles, USB adapters) cause instability. Device IDs remain based on machine name and OS version.

## Bug Fixes

- **Fix `HasValidLicense` wildcard pre-filter (#2):** `HasValidLicense` now correctly matches wildcard product IDs (e.g., `MyApp 1.*`) instead of requiring an exact string match on the pre-filter.
- **Fix regex metacharacter escaping (#3):** Product IDs containing regex metacharacters (e.g., parentheses, dots) are now properly escaped before wildcard matching.

## Improvements

- **Fix stream disposal (#4):** `SaveAsync` and `LoadAsync` now use `leaveOpen: true`, so the caller's stream is no longer disposed after save/load operations.
- **Thread safety for `LicenseService` (#5):** `AddLicense`, `RemoveLicense`, and `HasValidLicense` are now thread-safe via internal locking.
- **Cache factory/service instances (#7):** Signature signer and verifier delegates are now cached as static fields in `LicenseBuilder` and `LicenseService`, avoiding repeated factory allocations.
- **Add `RemoveLicense` method (#8):** `LicenseService.RemoveLicense(License)` removes a license by reference equality and returns whether it was found.
- **Add `CancellationToken` support (#9):** `SaveAsync` and `LoadAsync` accept an optional `CancellationToken`. On .NET 7+ this enables true async cancellation; on older TFMs it calls `ThrowIfCancellationRequested()` before the operation.

## Test & Documentation

- Extracted key-loading into a shared `KeyFixture` using `IClassFixture<KeyFixture>`, eliminating duplicated file I/O across all tests.
- Converted non-async tests from `async Task` to `void`, removing unnecessary `await Task.CompletedTask`.
- Added `HasValidLicense` tests: exact match, wildcard match, no match, device ID, wrong device ID, regex metacharacter handling.
- Added `LicenseUtils` tests: device ID generation consistency and utility method safety.
- Updated README target framework list to reflect all supported TFMs.
- Added sample code to `ConsoleApp1` demonstrating key generation, license creation, persistence, and validation.
