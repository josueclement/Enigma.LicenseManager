# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
dotnet build Enigma.LicenseManager.slnx
dotnet test Enigma.LicenseManager.slnx
# Run a single test by name
dotnet test Enigma.LicenseManager.slnx --filter "FullyQualifiedName~TestMethodName"
```

The solution uses the modern `.slnx` XML format (requires .NET SDK 9+).

The `UnitTests` project runs on **xUnit v3** (Microsoft Testing Platform), so it builds as an executable and launches itself. If `dotnet test` fails with *"You must install .NET to run this application"*, the test apphost can't locate the runtime — set `DOTNET_ROOT` to your SDK install directory (e.g. `DOTNET_ROOT=~/.dotnet dotnet test Enigma.LicenseManager.slnx`).

## Architecture

Five projects under `src/`: the core library, a shared operations library (`Tools`), a CLI, an Avalonia desktop app, and the tests.

Four-class core library in `src/Enigma.LicenseManager/`:

- **`License`** — Data model with cryptographic signature. Mutable properties (for JSON deserialization); tampering caught at verification time. `GetDataForSignature()` serializes fields deterministically for signing. `SaveAsync`/`LoadAsync` persist to JSON via Newtonsoft.Json with `leaveOpen: true`.
- **`LicenseBuilder`** — Fluent builder that signs licenses. `SignWithRsa()` or `SignWithMlDsa()` configures the algorithm; `Build()` computes the signature. Signer delegates are cached as static fields.
- **`LicenseService`** — Thread-safe in-memory license repository. `AddLicense`/`RemoveLicense`/`HasValidLicense` are lock-protected. `IsValid()` returns `(bool, string?)` tuple — never throws on invalid input.
- **`LicenseUtils`** — Static helpers: `GenerateDeviceId()` derives a stable machine identifier (machine name + OS version, no MAC address); `GetExecutingAppName()`/`GetExecutingAppVersion()` read the entry assembly.

Product ID matching supports wildcards (`MyApp 1.*`): IDs are `Regex.Escape()`d first, then `\*` is replaced with `.*`.

The remaining projects build on the core:

- **`Enigma.LicenseManager.Tools`** (`src/Enigma.LicenseManager.Tools/`) — shared key/license operations: key generation, PEM I/O, and RSA-vs-ML-DSA dispatch behind DI-registered services (`AddLicenseTools()`). Consumed by both the CLI and the desktop app.
- **`Enigma.LicenseManager.Cli`** (`src/Enigma.LicenseManager.Cli/`) — the `enigma-license` command-line tool: a thin System.CommandLine front-end over Tools with `keygen` / `license generate` / `license validate` subcommands and CI-friendly exit codes (`0` valid, `1` invalid, `2` error).
- **`Enigma.LicenseManager.Desktop`** (`src/Enigma.LicenseManager.Desktop/`) — an Avalonia GUI over Tools with Generate Keys / Generate Licenses / Validate Licenses pages.

## Multi-Targeting & Conditional Compilation

The core library targets `netstandard2.0` and `net8.0`. Conditional `#if NET7_0_OR_GREATER` blocks in `License.cs` enable true async cancellation on .NET 7+ vs. pre-check `ThrowIfCancellationRequested()` on older TFMs. The `Tools` library targets `net8.0`; the CLI, desktop app, and tests target `net10.0`.

## Key Conventions

- NuGet pack paths in `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj` reference `../../README.md` and `../../LICENSE.md` (repo root)
- Inter-project references use relative paths (e.g., `../Enigma.LicenseManager/...`)
- Test data files (`src/UnitTests/Data/*.pem`) use `CopyToOutputDirectory` — paths are project-relative
- `GeneratePackageOnBuild` is enabled — every build produces a .nupkg
- Shared *build* settings live in the solution-root `Directory.Build.props` (`Authors`, `Copyright`, `LangVersion 14`, `Nullable enable`, `TreatWarningsAsErrors true`, `EnforceCodeStyleInBuild true`) — applied to every project; don't re-declare them per-csproj. Code-style rules are in the repo-root `.editorconfig`. Keep `Directory.Build.props` free of version/package metadata (that stays per-project or in CPM)
- Central Package Management (CPM) is in effect — package versions are pinned once in the solution-root `Directory.Packages.props` (`<PackageVersion>`); individual `<PackageReference>` items must carry **no** `Version` attribute. Bump a dependency there, not in a csproj
- Tests run on **xUnit v3** (Microsoft Testing Platform) and use a shared `KeyFixture` (`IClassFixture<KeyFixture>`, `IAsyncLifetime` with `ValueTask` init/dispose) that loads PEM keys once; PEM password is `test1234`
- Cryptography comes from `Enigma.Cryptography` (BouncyCastle-based) — keys are `AsymmetricKeyParameter`
