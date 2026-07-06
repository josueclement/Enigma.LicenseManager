# FEATURE-001-PHASE01 — Shared operations library `Enigma.LicenseManager.Tools` + unit tests

**Completed:** 2026-07-06 · **Branch:** `feature/feature-001-phase01-license-tools`

## Summary

Added a new `net8.0` class library `Enigma.LicenseManager.Tools` that extracts the "beyond-the-core-library"
glue shared by the coming desktop app (FEATURE-001 PHASE02/03) and CLI (FEATURE-002): RSA/ML-DSA key
generation, PEM save/load with optional password encryption, license generation from a request object, and
license validation that never throws on bad input. The layer is interface-first and DI-ready, so the GUI/CLI
depend only on the abstractions. Unit tests for the whole layer were added to the existing `UnitTests`
project, reusing the shared `KeyFixture` and `Data/*.pem` keys.

## Files / modules touched

**Created — `src/Enigma.LicenseManager.Tools/`:**
- `Enigma.LicenseManager.Tools.csproj` — `net8.0`, `LangVersion 14`, `Nullable enable`, `ImplicitUsings disable`,
  `TreatWarningsAsErrors`, `GenerateDocumentationFile`, `IsPackable=false`. References core lib
  (ProjectReference), `Enigma.Cryptography` 4.3.0, `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.2,
  `Ulid` 1.4.1. The single-target net8.0 choice is documented in a csproj comment.
- `LicenseAlgorithm.cs` — `enum { Rsa, MlDsa }` (ML-DSA is level-87-only).
- `RsaKeySize.cs` — `enum { Rsa2048=2048, Rsa3072=3072, Rsa4096=4096, Rsa8192=8192 }`.
- `LicenseGenerationRequest.cs` — `record` with `required ProductId`/`required Algorithm` + optional
  `Owner`/`DeviceId`/`ExpirationDate`/`Id`/`CreationDate`.
- `LicenseValidationResult.cs` — `record (bool IsValid, string? Message, License? License)`.
- `IKeyGenerationService.cs` / `KeyGenerationService.cs` — `GenerateKeyPair` (sync, CPU-bound),
  `SaveKeyPairAsync` (public plain / private AES-256-CBC-when-password), `GenerateAndSaveKeyPairAsync`
  (owns its file streams). PEM is encoded into a `MemoryStream` then `CopyToAsync`-ed for genuine async I/O;
  caller streams are left open. Exposes `const PrivateKeyEncryptionAlgorithm = "AES-256-CBC"`.
- `ILicenseGenerationService.cs` / `LicenseGenerationService.cs` — three `CreateAndSaveLicenseAsync` overloads
  (loaded key + stream / key PEM stream + password + stream / key path + password + output path). Maps request
  → `LicenseBuilder`, setting `Id`/`CreationDate` only when supplied, dispatches `SignWithRsa`/`SignWithMlDsa`.
- `ILicenseValidationService.cs` / `LicenseValidationService.cs` — `ValidateAsync` stream + path overloads;
  `productId` defaults to the license's own; delegates to core `LicenseService.IsValid`; catches narrowly
  (`JsonException`/`FormatException`/`InvalidOperationException`/`ArgumentException`/`GeneralSecurityException`)
  → `(false, message, license?)`; genuine IO propagates. `ConfigureAwait(false)` throughout.
- `ServiceCollectionExtensions.cs` — `AddLicenseTools()` in `Microsoft.Extensions.DependencyInjection`;
  registers the three interfaces + core `LicenseService` as singletons.

**Created — tests:**
- `src/UnitTests/ToolsTests.cs` — 26 tests (see coverage below).

**Modified:**
- `Enigma.LicenseManager.slnx` — added the Tools project.
- `src/UnitTests/UnitTests.csproj` — added ProjectReference → Tools and a test-only PackageReference on
  `Microsoft.Extensions.DependencyInjection` 10.0.9 (needed to build a `ServiceProvider` in the DI tests).

## Deviations & follow-ups

- **Private-key loading unified on `PemUtils.LoadPrivateKey` (correctness fix).** The plan/Enigma.UI pattern
  loads an unencrypted private key via `PemUtils.LoadKey` when no password is given. That path **throws** for a
  plain RSA private key, because an unencrypted RSA private-key PEM decodes to an `AsymmetricCipherKeyPair`, not
  an `AsymmetricKeyParameter` (verified via test). `LicenseGenerationService` therefore always uses
  `PemUtils.LoadPrivateKey(stream, password ?? "")`, which unwraps the key pair and only consults the password
  when the PEM is actually encrypted — correctly handling plain *and* encrypted keys. A dedicated test
  (`GenerateService_LoadsPlainPrivateKeyFromPem_AndSigns`, RSA + ML-DSA) locks this in.
  **Follow-up:** the reference `Enigma.UI` (`GenerateLicensesPageViewModel` etc.) likely has the same latent
  bug for plain RSA private keys — worth a look outside this repo.
- **Malformed-public-key-PEM contract (chosen & asserted).** A public-key PEM containing no readable key
  returns `(false, message)` without throwing, and the already-parsed license is still carried on the result.
  Asserted by `Validate_MalformedPublicKeyPem_ReturnsFalseWithoutThrowing`. Deeply corrupt PEM *bytes* could
  still surface a BouncyCastle `IOException`, which by design propagates.
- **No defensive algorithm-vs-key-type cross-check.** The plan noted this as "consider". Skipped to avoid
  coupling to BouncyCastle key-parameter internals; a mismatched key surfaces as an exception from the core
  signer. Can be added later if desired.
- **`Ulid` package reference on Tools is currently unused directly** (the core `LicenseBuilder` owns ULID
  defaulting). Kept per the plan's explicit dependency list; harmless. Remove if it stays unused after the CLI.
- **Encoding (not acted on).** New `.cs` files are UTF-8 without BOM; existing repo `.cs` files carry a UTF-8
  BOM. No line-ending (CRLF) issues found and no `.gitattributes` present. Recommendation only — left as-is to
  avoid churn.

## Build / test evidence

- `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s), 0 Error(s)** (Tools builds with
  `TreatWarningsAsErrors`).
- `dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0, Passed: 70, Skipped: 0** (34 pre-existing +
  36 new Tools test cases across 33 test methods). The ~1m33s runtime is dominated by the RSA-8192 slow
  round-trip (tagged `[Trait("Category","Slow")]`; the rest of the suite runs in ~4s).

### Test coverage (`ToolsTests.cs`)
- Keygen → sign → validate round-trips: RSA 2048/3072/4096 (theory), RSA-8192 (slow), ML-DSA-87.
- PEM save/load plain vs encrypted; wrong password throws; encrypted-loaded-as-plain fails; whitespace
  password treated as plain; `GenerateAndSaveKeyPairAsync` writes both files.
- Plain & encrypted private keys load and sign through the generation service (RSA + ML-DSA).
- Algorithm dispatch → `SignedWith == "RSA"` / `"ML-DSA"`.
- Id/CreationDate defaulting (ULID + ≈UtcNow when omitted; explicit values honored).
- Non-private key ⇒ `ArgumentException`; empty/whitespace `ProductId` ⇒ `ArgumentException`.
- Validation: valid ⇒ `(true, null)`; wrong public key (RSA & ML-DSA) ⇒ false; expired ⇒ false; product
  mismatch ⇒ false; wildcard match; regex-metachar exact match; device match/mismatch/none; productId omitted
  ⇒ self-validates; tampered license ⇒ false.
- Corrupt license JSON ⇒ `(false, message)` without throwing; malformed public-key PEM ⇒ chosen contract.
- `AddLicenseTools()` resolves all three interfaces + `LicenseService`; services are singletons.

## Acceptance criteria — met
- ✅ `dotnet build Enigma.LicenseManager.slnx` succeeds with zero warnings.
- ✅ All new Tools tests pass; the existing suite stays green.
- ✅ `AddLicenseTools()` wires the three services; the GUI/CLI can depend purely on the interfaces.
