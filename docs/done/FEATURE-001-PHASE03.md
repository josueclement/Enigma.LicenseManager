# FEATURE-001-PHASE03 — Feature pages (Generate Keys / Generate Licenses / Validate Licenses)

**Completed:** 2026-07-06 · Branch: `feature/feature-001-phase03-feature-pages`

## Summary

Fleshed out the three placeholder View/ViewModel pairs left by PHASE02 into working feature pages
for the `Enigma.LicenseManager.Desktop` Avalonia app. Each page mirrors the Enigma.UI form layout
(`ScrollViewer > StackPanel(Margin=24, Spacing=16, MaxWidth=800)` → `carbon:SettingsCardExpander`
sections → `editors:TextEditor` / `ComboBox` / `CheckBox` + `CalendarDatePicker` → accent `Button`),
but **delegates all key/license work to the injected `Enigma.LicenseManager.Tools` services**
(`IKeyGenerationService`, `ILicenseGenerationService`, `ILicenseValidationService`) rather than calling
the crypto factories / `LicenseBuilder` / `LicenseService` directly as Enigma.UI does.

Each ViewModel is an `ObservableObject` using hand-written `SetProperty` + `AsyncRelayCommand` (no
`[ObservableProperty]`/`[RelayCommand]` source generators), with per-field `*HasError` validation flags
and an `IsBusy` re-entrancy guard.

- **Generate Keys** — algorithm restricted to **RSA / ML-DSA** (ML-KEM dropped); parameter dropdown is
  RSA sizes {2048, 3072, 4096, 8192}, and for ML-DSA a single fixed `ML-DSA-87` option. Password +
  confirm with a mismatch guard; public/private output paths (Browse + drag-drop). Generation runs on a
  background thread (`Task.Run` → `IKeyGenerationService.GenerateKeyPair`) behind a
  `ProgressOverlayCard`, then `SaveKeyPairAsync`; success/error via Carbon InfoBar.
- **Generate Licenses** — ProductId (required), Owner (required), DeviceId (optional), HasExpiration +
  ExpirationDate, signing algorithm (RSA/ML-DSA), private-key path + optional password, license output
  path. Builds a `LicenseGenerationRequest` (leaving `Id`/`CreationDate` null so the core builder
  supplies its ULID / `UtcNow` defaults) and calls `ILicenseGenerationService.CreateAndSaveLicenseAsync`
  (path overload); InfoBar result.
- **Validate Licenses** — license path, public-key path, optional ProductId + DeviceId →
  `ILicenseValidationService.ValidateAsync` (blank product/device ids passed as `null`). Result shown as
  inline bordered text plus an `IsValidationSuccess` flag.

README updated with a "Tooling" section describing the desktop app + `Enigma.LicenseManager.Tools`, and
the (previously stale) Project Structure table refreshed to list the Tools and Desktop projects.

## Files/modules touched

**Modified (implemented from placeholders):**
- `src/Enigma.LicenseManager.Desktop/ViewModels/GenerateKeysPageViewModel.cs`
- `src/Enigma.LicenseManager.Desktop/ViewModels/GenerateLicensesPageViewModel.cs`
- `src/Enigma.LicenseManager.Desktop/ViewModels/ValidateLicensesPageViewModel.cs`
- `src/Enigma.LicenseManager.Desktop/Views/GenerateKeysPageView.axaml`
- `src/Enigma.LicenseManager.Desktop/Views/GenerateLicensesPageView.axaml`
- `src/Enigma.LicenseManager.Desktop/Views/ValidateLicensesPageView.axaml`
- `README.md`

**Modified (status):** `docs/roadmap.md`, `docs/plan/FEATURE-001.md`
**Created:** `docs/done/FEATURE-001-PHASE03.md`

The page code-behind files (`*.axaml.cs`) were already correct (`InitializeComponent` only) and needed
no change.

## Deviations & follow-ups

- **Registration already in place.** The plan lists "Register the three View (transient) + VM
  (singleton) pairs", but PHASE02's `ServiceCollectionExtensions.AddPagesAndViewModels()` already
  registers all three pairs (they backed the placeholders). No registration change was required — the
  acceptance item is satisfied by the existing wiring.
- **Validate result styling.** Mirrors Enigma.UI's neutral bordered result text; `IsValidationSuccess`
  is retained as backing state (as in the reference) rather than driving colour, to avoid pulling
  Avalonia brush types into the ViewModel. The valid/invalid distinction is carried by the result text.
- **`run`-skill verification.** No UI input-injection tool is available in this environment (no
  xdotool/xte/ydotool/wtype/python-xlib), so the live GUI could be launched and screenshotted but not
  click-driven. Verification was done as: (1) launched the built app on the X display and captured the
  **Generate Keys** page rendering live (shell, nav, theme toggle, real Carbon controls, live VM
  bindings); (2) a zero-warning **compiled-binding** build, which type-checks every binding in all three
  `x:DataType` Views (a bad binding on any page fails the build); (3) a standalone end-to-end driver
  that runs the full round-trip through the app's real `AddLicenseTools()`-composed services. **Follow-up:**
  consider `/run-skill-generator` to capture a navigation-capable desktop run skill (e.g. install an
  input tool + a headless-render or click driver) so future runs can screenshot all three pages.
- **Line endings:** no CRLF/LF inconsistency observed in the touched files.

## Build/test evidence

- `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s), 0 Error(s)** (includes
  Avalonia compiled-binding validation of the three new Views).
- `dotnet test Enigma.LicenseManager.slnx` → **Passed: 70, Failed: 0, Skipped: 0** (the existing Tools
  suite; PHASE03 adds no tests by design — the plan mandates Tools-only tests and no Avalonia UI tests).
- **In-app / end-to-end:** launched the app on display `:1` — clean startup (NLog "Hosting started", no
  exceptions) and the shell + Generate Keys page rendered live (screenshot reviewed). End-to-end driver
  (through the real composed services) passed all checks for **RSA-2048** and **ML-DSA-87**:
  - generate key pair → sign license → validate ⇒ **VALID** (`SignedWith` = `RSA` / `ML-DSA`);
  - wrong public key ⇒ **INVALID** (signature is invalid);
  - tampered license ⇒ **INVALID** (signature is invalid);
  - mismatched product id ⇒ **INVALID** (product id mismatch);
  - wildcard product `MyApp 1.*` validated against `MyApp 1.2.3` ⇒ **VALID**.
- **ML-DSA level / ML-KEM:** UI algorithm options are `["RSA", "ML-DSA"]` (no ML-KEM); the ML-DSA
  parameter list is the single fixed `["ML-DSA-87"]`.
