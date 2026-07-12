# FEATURE-001 — License-management desktop app (Avalonia) + shared Tools library

**Status:** DONE · **Type:** multi-phase FEATURE

## Objective

Deliver an Avalonia desktop application for **RSA / ML-DSA key generation** and **license
generation / validation**, mirroring the architecture of the existing `Enigma.UI` app
(`~/Dev/Enigma.UI`) but scoped to only the key + license features. The orchestration shared with the
coming CLI (FEATURE-002) is extracted once into a testable `Enigma.LicenseManager.Tools` library.

## Context

The `Enigma.LicenseManager` core library only **signs/verifies** — key generation and PEM I/O live in
`Enigma.Cryptography`. There is currently no end-user tooling. Both this GUI and the future CLI need
the same "beyond-the-library" glue (ULID id + `DateTime.UtcNow` stamp, RSA-vs-ML-DSA dispatch, PEM
save/load with optional password). That glue is extracted into `Enigma.LicenseManager.Tools` so it is
written once and unit-tested directly (a GUI is not).

## Scope & key decisions

- New projects added to `Enigma.LicenseManager.slnx`, referencing the core library via
  **ProjectReference** (dogfood the in-development library).
- Key generation supports **RSA + ML-DSA only** (ML-KEM dropped — it's a KEM, irrelevant to signing).
- **ML-DSA restricted to level 87** — the only level the core `LicenseBuilder`/`LicenseService`
  accept (`CreateDsa87Service` is hardcoded). Other levels are a silent footgun and must not be
  offered.
- MVVM follows the repo/Enigma.UI convention: `ObservableObject` + **hand-written `SetProperty` and
  explicit `AsyncRelayCommand`/`RelayCommand`** — NO `[ObservableProperty]`/`[RelayCommand]` source
  generators.
- Supporting infrastructure is a **full mirror** of Enigma.UI (NLog, per-user JSON config,
  `FileDropHelper` / `AppIconHelper` / `ProgressOverlayCard`).
- **Light/dark theme toggle** at runtime, persisted to the per-user config (Enigma.UI forces Dark;
  this app differs deliberately).
- Testing: unit-test the **Tools** library only; **no Avalonia UI tests**. Tests live in the existing
  `src/UnitTests` project (xUnit v2, reusing `KeyFixture` + `Data/*.pem`).

### Applied defaults (adjustable)
- **Tools TFM:** single-target **`net8.0`** (documented deviation from the netstandard2.0 library
  default): internal shared layer consumed only by `net10.0` apps, never packed → native
  records/`init`/`required`, no PolySharp. Alternative `netstandard2.0;net8.0` + PolySharp only if
  Tools is ever published.
- **Enigma.Cryptography:** new projects reference **4.3.0** (matches Enigma.UI); core lib stays
  **4.2.1**; NuGet unifies the app closure to 4.3.0. No Central Package Management.
- **Config:** `~/.config/EnigmaLicenseManager/config.json`; `DefaultPathsOptions` trimmed to
  `Keys` + `Licenses`, plus a persisted `Theme`.
- **Title / icon:** "Enigma License Manager"; window icon via mirrored `AppIconHelper` with a
  license-themed Phosphor glyph (e.g. `Icon.certificate`).
- **Threading:** key generation on a background thread (`Task.Run`) behind `ProgressOverlayCard`;
  license sign/validate on the UI thread (fast). Tools never `Task.Run`s internally.
- **Validation UX:** inline bordered result text (mirrors Enigma.UI), not an InfoBar.

---

## PHASE01 — Shared operations library `Enigma.LicenseManager.Tools` + unit tests

**Status:** DONE · Branch (at build): `feature/feature-001-phase01-license-tools`

New project `src/Enigma.LicenseManager.Tools/`: `net8.0`, `LangVersion 14`, `Nullable enable`,
`ImplicitUsings disable`, `TreatWarningsAsErrors` (≥ `nullable`). References: core library
(ProjectReference), `Enigma.Cryptography` 4.3.0, `Microsoft.Extensions.DependencyInjection.Abstractions`,
`Ulid`. Document the net8.0 single-target choice in a csproj comment.

### Public surface (namespace `Enigma.LicenseManager.Tools`)
- `enum LicenseAlgorithm { Rsa, MlDsa }`
- `enum RsaKeySize { Rsa2048 = 2048, Rsa3072 = 3072, Rsa4096 = 4096, Rsa8192 = 8192 }` — no ML-DSA
  level enum (87 only).
- `record LicenseGenerationRequest { required string ProductId; required LicenseAlgorithm Algorithm;
  string? Owner; string? DeviceId; DateTime? ExpirationDate; string? Id; DateTime? CreationDate; }`
- `record LicenseValidationResult(bool IsValid, string? Message, License? License)` — carries the
  loaded license so the GUI can show fields even on failure.
- `IKeyGenerationService` (singleton):
  - `AsymmetricCipherKeyPair GenerateKeyPair(LicenseAlgorithm algorithm, RsaKeySize rsaKeySize = RsaKeySize.Rsa3072)` — sync, CPU-bound.
  - `Task SaveKeyPairAsync(AsymmetricCipherKeyPair keyPair, Stream publicKeyOutput, Stream privateKeyOutput, string? privateKeyPassword = null, CancellationToken cancellationToken = default)` — public always plain (`PemUtils.SaveKey`); private `AES-256-CBC` iff password non-empty (`PemUtils.SavePrivateKey`), else plain. PEM-encode into a `MemoryStream`, then `CopyToAsync` for genuine async file I/O. `leaveOpen` semantics — do not close caller streams.
  - `Task GenerateAndSaveKeyPairAsync(LicenseAlgorithm algorithm, string publicKeyPath, string privateKeyPath, RsaKeySize rsaKeySize = RsaKeySize.Rsa3072, string? privateKeyPassword = null, CancellationToken cancellationToken = default)` — owns/disposes its own FileStreams.
- `ILicenseGenerationService` (singleton) — `Task<License> CreateAndSaveLicenseAsync(...)` in three
  overloads: (loaded private key + output stream), (private-key PEM stream + password + output stream),
  (private-key path + password + output path). Maps request → `LicenseBuilder`, setting `Id`/
  `CreationDate` **only when supplied** (so the builder's ULID/UtcNow defaulting stays central),
  dispatches `SignWithRsa`/`SignWithMlDsa` on `Algorithm`, `Build()`, `SaveAsync`.
- `ILicenseValidationService` (singleton) — `Task<LicenseValidationResult> ValidateAsync(...)` in
  stream and path overloads; `productId` optional (defaults to the license's own `ProductId`). Loads
  via `License.LoadAsync` + `PemUtils.LoadKey`, delegates to core `LicenseService.IsValid`, wraps the
  `(bool, string?)` tuple + loaded license. Catches **narrowly** (JSON / BouncyCastle / format) →
  returns `(false, message, license?)`; only unexpected faults (IO) propagate. `ConfigureAwait(false)`
  on all awaits.
- `AddLicenseTools(this IServiceCollection)` in namespace `Microsoft.Extensions.DependencyInjection`
  — registers the three interfaces + core `LicenseService`, all singletons.
- `const string PrivateKeyEncryptionAlgorithm = "AES-256-CBC";`.

### Reuse
Core `LicenseBuilder`/`License`/`LicenseService`; `Enigma.Cryptography`
`PublicKeyServiceFactory.CreateRsaService()`, `MLDsaServiceFactory.CreateDsa87Service()`,
`PemUtils.SaveKey/SavePrivateKey/LoadKey/LoadPrivateKey`.

### Pitfalls to honor
ML-DSA-87 hardcoded (keygen must use `CreateDsa87Service`); `SignWith*` throw unless `key.IsPrivate`;
`Algorithm` must match the actual key type (core does not cross-check — consider a defensive check);
password null/whitespace ⇒ plain, else encrypted; `PemUtils` is sync/stream-based.

### Tests (in `src/UnitTests`, xUnit v2, reuse `KeyFixture` + `Data/*.pem`)
Add ProjectReference `UnitTests → Tools`; new test file(s). Cover:
- Keygen → sign → validate round-trips: RSA 2048/3072/4096 (8192 optional/slow theory), ML-DSA-87.
- PEM save/load plain vs encrypted; wrong password throws; encrypted private loaded as plain fails.
- Algorithm dispatch → `SignedWith == "RSA"` / `"ML-DSA"`.
- Id/CreationDate defaulting (ULID + ≈UtcNow when omitted; explicit values honored).
- Non-private key ⇒ `ArgumentException`; empty `ProductId` ⇒ throws.
- Validation: valid ⇒ `(true, null)`; wrong public key ⇒ false (RSA & ML-DSA); expired ⇒ false;
  product mismatch ⇒ false; wildcard `MyApp 1.*` vs `MyApp 1.2.3` ⇒ true; regex-metachar exact ⇒ true;
  device binding match/mismatch/none; productId omitted ⇒ self-validates; tampered license ⇒ false.
- Corrupt license JSON ⇒ `(false, message)` **without throwing**; malformed public-key PEM ⇒ result
  per the chosen contract (assert it).
- `AddLicenseTools()` resolves all three interfaces; resolving twice yields the same instance.

Add the Tools project to `Enigma.LicenseManager.slnx`.

### Acceptance criteria
- `dotnet build Enigma.LicenseManager.slnx` succeeds with **zero warnings**.
- All new Tools tests pass; the existing suite stays green.
- `AddLicenseTools()` wires the three services; the GUI/CLI can depend purely on the interfaces.

---

## PHASE02 — Desktop app shell & infrastructure

**Status:** DONE · Branch (at build): `feature/feature-001-phase02-desktop-shell`

New project `src/Enigma.LicenseManager.Desktop/`: `net10.0`, `WinExe`, Avalonia **12.0.5**,
compiled bindings on. Packages mirror Enigma.UI minus cert/encrypt/ML-KEM: Avalonia (+ Desktop,
Themes.Fluent, Fonts.Inter, DiagnosticsSupport), CommunityToolkit.Mvvm, Carbon.Avalonia.Desktop,
Microsoft.Extensions.Hosting, NLog(+Extensions.Logging), PhosphorIconsAvalonia,
Enigma.Cryptography 4.3.0, Ulid. ProjectReferences: core lib + **Tools**.

Copy/adapt from Enigma.UI:
- `Program.cs` — IHost + `StartWithClassicDesktopLifetime`; config from
  `~/.config/EnigmaLicenseManager/config.json`; NLog.
- `App.axaml` — Carbon theme `ResourceInclude` + `ProgressOverlayCard.axaml`; `RequestedThemeVariant`
  **initialized from the saved config**, not hardcoded Dark.
- `App.axaml.cs` — resolve `MainWindow` + VM from host; `RegisterHost` ×3
  (ContentDialog/Overlay/InfoBar) + `SetStorageProvider`; window icon via `AppIconHelper`; designer
  fallback provider.
- `MainWindow.axaml(.cs)` — NavigationView (left) + `ContentControl` + three named host controls;
  quit-confirm dialog.
- `ServiceCollectionExtensions.cs` — `AddAppConfiguration`, `AddCarbonServices`, **`AddLicenseTools`**,
  trimmed `AddPagesAndViewModels` (MainWindow + the three View/VM pairs).
- `ConfigurationSetup.cs` — new config path + a `Theme` field; ensure-file-exists on first run.
- `NLog.config`, `Helpers/AppIconHelper.cs`, `Helpers/FileDropHelper.cs`,
  `Controls/ProgressOverlayCard.*`, `Models/DefaultPathsOptions.cs` (Keys/Licenses + Theme).

`MainWindowViewModel` registers exactly three `NavigationItem`s (Generate Keys / Generate Licenses /
Validate Licenses) and exposes a `ToggleThemeCommand` that flips
`Application.Current.RequestedThemeVariant` Light↔Dark and **persists** the choice (small settings
write-back to `config.json`). Toggle control placed in the nav-rail footer / shell.

Add the Desktop project to `Enigma.LicenseManager.slnx`.

### Acceptance criteria
- `dotnet build` clean (zero warnings); test suite green.
- `dotnet run --project src/Enigma.LicenseManager.Desktop` launches the window; navigation switches
  between the three pages (placeholders acceptable until PHASE03).
- Theme toggle flips light↔dark at runtime **and persists across a restart**.

---

## PHASE03 — Feature pages

**Status:** DONE · Branch (at build): `feature/feature-001-phase03-feature-pages`

Three View/VM pairs mirroring Enigma.UI's form layout (`ScrollViewer > StackPanel(Margin=24,
Spacing=16, MaxWidth=800)` → `carbon:SettingsCardExpander` sections → `editors:TextEditor` /
`ComboBox` / `CheckBox`+`CalendarDatePicker` → accent `Button`). Each VM is an `ObservableObject`
with hand-written `SetProperty` + `AsyncRelayCommand`, per-field `*HasError` validation flags, an
`IsBusy` re-entrancy guard, and delegates **all** work to the injected Tools services.

- **GenerateKeysPageView/VM** — algorithm = **RSA / ML-DSA** only; parameter dropdown = RSA sizes
  {2048, 3072, 4096, 8192}, and for ML-DSA **fixed to 87** (single option or no dropdown). Password +
  confirm with mismatch guard; public/private output paths (Browse + drag-drop). Calls
  `IKeyGenerationService.GenerateKeyPair` on a background thread (`Task.Run`) behind
  `ProgressOverlayCard`, then `SaveKeyPairAsync`; success/error via Carbon InfoBar.
- **GenerateLicensesPageView/VM** — ProductId (required), Owner (required), DeviceId (optional),
  HasExpiration + ExpirationDate, signing algorithm (RSA/ML-DSA), private-key path + optional
  password, license output path. Calls `ILicenseGenerationService.CreateAndSaveLicenseAsync`;
  InfoBar result.
- **ValidateLicensesPageView/VM** — license path, public-key path, optional ProductId + DeviceId →
  `ILicenseValidationService.ValidateAsync`; inline bordered result text + success flag.

Register the three View (transient) + VM (singleton) pairs. Update README with a short "Tooling"
section (desktop app).

### Acceptance criteria
- `dotnet build` clean (zero warnings); test suite green.
- In-app end-to-end (verified with the `run` skill): generate an RSA key pair → generate a license
  with it → validate → **valid**; then tamper the license or use the wrong public key → **invalid**.
  Repeat the round-trip for **ML-DSA-87**.
- ML-DSA offers only level 87 in the UI; ML-KEM is absent.

---

## Definition of Done (per phase, per dev-workflow)
Build clean (0 warnings) · full test suite passes (incl. new Tools tests) · all acceptance criteria
met · roadmap + this plan's statuses updated · `docs/done/FEATURE-001-PHASENN.md` written.
