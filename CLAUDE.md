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

## Architecture

Three-class library in `src/Enigma.LicenseManager/`:

- **`License`** — Data model with cryptographic signature. Mutable properties (for JSON deserialization); tampering caught at verification time. `GetDataForSignature()` serializes fields deterministically for signing. `SaveAsync`/`LoadAsync` persist to JSON via Newtonsoft.Json with `leaveOpen: true`.
- **`LicenseBuilder`** — Fluent builder that signs licenses. `SignWithRsa()` or `SignWithMlDsa()` configures the algorithm; `Build()` computes the signature. Signer delegates are cached as static fields.
- **`LicenseService`** — Thread-safe in-memory license repository. `AddLicense`/`RemoveLicense`/`HasValidLicense` are lock-protected. `IsValid()` returns `(bool, string?)` tuple — never throws on invalid input.

Product ID matching supports wildcards (`MyApp 1.*`): IDs are `Regex.Escape()`d first, then `\*` is replaced with `.*`.

## Multi-Targeting & Conditional Compilation

The library targets `netstandard2.0` and `net8.0`. Conditional `#if NET7_0_OR_GREATER` blocks in `License.cs` enable true async cancellation on .NET 7+ vs. pre-check `ThrowIfCancellationRequested()` on older TFMs.

## Key Conventions

- NuGet pack paths in `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj` reference `../../README.md` and `../../LICENSE.md` (repo root)
- Inter-project references use relative paths (e.g., `../Enigma.LicenseManager/...`)
- Test data files (`src/UnitTests/Data/*.pem`) use `CopyToOutputDirectory` — paths are project-relative
- `GeneratePackageOnBuild` is enabled — every build produces a .nupkg
- Tests use a shared `KeyFixture` (`IClassFixture<KeyFixture>`) that loads PEM keys once; PEM password is `test1234`
- Cryptography comes from `Enigma.Cryptography` (BouncyCastle-based) — keys are `AsymmetricKeyParameter`
