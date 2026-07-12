# FEATURE-005 — Avalonia desktop improvements

**Status: IN PROGRESS** (PHASE01 DONE · PHASE02 DONE · PHASE03 TODO · PHASE04 TODO)

## Context

The `Enigma.LicenseManager.Desktop` (Avalonia) app works, but four quality-of-life
improvements were requested:

1. **Keep the Avalonia stack current.** The app was intentionally frozen on Avalonia
   `12.0.5` during the 1.2.0 release (FEATURE-004 explicitly deferred Avalonia work). A
   minor update (`12.1.0`) is now available and should be picked up.
2. **License profiles.** Re-typing the license metadata for every issue is tedious and
   error-prone. Save/load a reusable "profile" of the Generate Licenses form fields —
   **never storing any password**.
3. **A real app icon.** Today there is no `.ico` at all; the window icon is synthesized at
   runtime from a Phosphor "certificate" glyph, and the built `.exe` carries no embedded
   icon. Ship a real, embedded multi-resolution `.ico`.
4. **Better RSA default.** The Generate Keys page defaults the RSA key size to `2048`;
   `4096` is the safer default to pre-select.

Intended outcome: a current, better-defaulted desktop app with a proper embedded icon and
a profile mechanism that removes repetitive, typo-prone data entry.

**Tracking:** one multi-phase feature with four phases (each its own branch + commit per the
dev-workflow, branched from the current `HEAD` at build time).

## Objective & scope

In scope: `src/Enigma.LicenseManager.Desktop` and the solution `Directory.Packages.props`.
Out of scope: core library, Tools, CLI, tests project (existing tests must keep passing).

## Requirements (by provenance)

### Decisions made / confirmed
- One feature, four phases: PHASE01 Avalonia bump → PHASE02 RSA default → PHASE03 app icon
  → PHASE04 license profiles.
- **Update = Avalonia `12.0.5 → 12.1.0` only.** Verified on NuGet: the four `Avalonia.*`
  packages are the only ones with a newer release. `Carbon.Avalonia.Desktop` (0.2.0),
  `PhosphorIconsAvalonia` (1.2.0), `CommunityToolkit.Mvvm` (8.4.2) and
  `AvaloniaUI.DiagnosticsSupport` (2.2.3) are already latest; Carbon/Phosphor declare
  min-Avalonia `≥12.0.2 / ≥12.0.0`, both satisfied by 12.1.0 — no conflict.

### Recommendations accepted (delegation)
- **Profile storage model:** Save/Load **file dialogs** (reuse Carbon `IFileDialogService`);
  a profile is a `.json` file placed anywhere. (Not a managed profiles folder, not
  auto-remember.)
- **Profile fields:** Product ID, Owner, Device ID, signing **algorithm**, **expiration**
  setting (checkbox + date), **signing key file path**. **Excluded:** signing key password
  (secret — hard requirement) and license output path.
- **App icon art:** derive a static multi-resolution `Assets/appicon.ico` from the current
  Phosphor "certificate" glyph; retire the runtime `AppIconHelper` window-icon call.

### House conventions applied (no ask)
- **avalonia skill:** wire the icon two ways — `<ApplicationIcon>` (embeds in the `.exe`)
  **and** a runtime window `Icon`; ship the multi-res `.ico` under `Assets/`; add
  `<AvaloniaResource Include="Assets/**" />`.
- **CPM:** version bumps go in `Directory.Packages.props`, never in a csproj.
- **MVVM (memory / communitytoolkit-mvvm):** hand-written `ObservableObject` + `SetProperty`
  + `AsyncRelayCommand` — NO `[ObservableProperty]`/`[RelayCommand]` source generators.
- **Serialization:** Desktop uses **System.Text.Json** (`ConfigurationSetup.cs`); the profile
  feature does too (Desktop does not reference Newtonsoft).
- Solution-wide `TreatWarningsAsErrors=true` + `EnforceCodeStyleInBuild=true` — new code must
  be warning-clean; remove genuinely dead code rather than leave it unused.

### Assumptions & defaults (low-impact)
- Profile files: extension `.json`, dialog filter `License profile (*.json)`, suggested name
  `license-profile.json`.
- Load repopulates the form + success toast (`IInfoBarService`); malformed/partial/old file →
  error toast, no crash; unknown/missing fields ignored.
- Algorithm persisted **by name** (`"RSA"`/`"ML-DSA"`), mapped back to
  `SelectedSigningAlgorithmIndex` on load (survives future reordering).
- **No new automated tests** — Desktop has no test project; verification = clean build +
  manual run. Existing unit tests must still pass.

### Beyond-the-draft resolutions
- Security: password never persisted (omitted from the model); paths are not secrets.
- Resilience: load tolerates malformed/old JSON (error toast).
- UX: load repopulates + toast; save toast; empty fields serialize as null.
- Observability: optionally log save/load at debug via existing NLog.
- Compatibility: minor Avalonia bump; Carbon/Phosphor constraints verified.
- n/a: accessibility, i18n, data migration, deployment/packaging (unchanged).
- Line endings: recommendation-only — note any CRLF churn in the phase's completion doc; take
  no action.

---

## PHASE01 — Bump Avalonia to 12.1.0 · **Status: DONE**
- **File:** `Directory.Packages.props` — change the four `Avalonia.*` `<PackageVersion>`
  lines from `12.0.5` to `12.1.0`: `Avalonia`, `Avalonia.Desktop`, `Avalonia.Fonts.Inter`,
  `Avalonia.Themes.Fluent`. Leave `AvaloniaUI.DiagnosticsSupport`, `Carbon.Avalonia.Desktop`,
  `PhosphorIconsAvalonia`, `CommunityToolkit.Mvvm` unchanged.
- Optionally refresh the stale comment on the Desktop group.
- **Acceptance:** solution restores + builds with zero warnings on 12.1.0; app launches; full
  test suite still green.

## PHASE02 — Default RSA key size = 4096 · **Status: DONE**
- **File:** `src/Enigma.LicenseManager.Desktop/ViewModels/GenerateKeysPageViewModel.cs`,
  `UpdateParameterOptions()` (currently `SelectedParameterIndex = 0` → "2048", ~line 169).
- Pre-select `"4096"` (index 2 of `{ "2048","3072","4096","8192" }`) for RSA while ML-DSA
  keeps its only option (index 0), e.g. `SelectedParameterIndex = SelectedAlgorithmIndex == 0 ? 2 : 0;`.
- **Acceptance:** on launch (RSA selected) the key-size combo shows **4096**; switching to
  ML-DSA and back to RSA still lands on 4096; generation still parses the value correctly.

## PHASE03 — Real embedded app icon · **Status: TODO**
- **Asset:** generate `src/Enigma.LicenseManager.Desktop/Assets/appicon.ico` — multi-resolution
  ICO (16/24/32/48/64/128/256) of the white Phosphor `Icon.certificate` (`IconType.fill`) glyph.
  `Helpers/AppIconHelper.cs` already contains the ICO-writing logic (`WriteIco` writes to any
  stream); reuse it via a one-off generator to emit the file once, then commit the `.ico`.
- **csproj:** add `<ApplicationIcon>Assets/appicon.ico</ApplicationIcon>` to the first
  `<PropertyGroup>` and `<AvaloniaResource Include="Assets/**" />` in an `<ItemGroup>`.
- **App.axaml.cs (line 42):** replace `AppIconHelper.CreateWindowIcon(...)` with loading the
  asset, e.g. `new WindowIcon(AssetLoader.Open(new Uri("avares://Enigma.LicenseManager.Desktop/Assets/appicon.ico")))`
  (or set `Icon="/Assets/appicon.ico"` in `MainWindow.axaml`).
- **Dead-code cleanup:** delete `Helpers/AppIconHelper.cs` and prune the now-unused
  `PhosphorIconsAvalonia`/`Avalonia.Media` usings in `App.axaml.cs` to keep the
  warnings-as-errors build clean. `git-repo-hygiene` already marks `*.ico binary`.
- **Acceptance:** clean build; window/taskbar and the built `.exe` show the certificate icon
  (not the Avalonia default); no unused-symbol warnings.

## PHASE04 — License profiles (save / load) · **Status: TODO**
- **New model:** `src/Enigma.LicenseManager.Desktop/Models/LicenseProfile.cs` — POCO with
  `ProductId`, `Owner`, `DeviceId`, `Algorithm` (string "RSA"/"ML-DSA"), `HasExpiration`
  (bool), `ExpirationDate` (DateTime?), `SigningKeyPath`. **No password, no output path.**
- **ViewModel** (`GenerateLicensesPageViewModel.cs`): add `SaveProfileCommand` /
  `LoadProfileCommand` (`AsyncRelayCommand`, manual pattern):
  - **Save:** `IFileDialogService.ShowSaveFileDialogAsync("Save Profile", …, "license-profile.json", ".json", true, null)`;
    map current VM fields → `LicenseProfile`; serialize with `System.Text.Json`
    (`WriteIndented = true`); success toast.
  - **Load:** `IFileDialogService.ShowOpenFileDialogAsync("Load Profile", false, …, ".json", null)`;
    deserialize; repopulate bound properties (map `Algorithm` name → index); success toast;
    try/catch → error toast on bad file.
- **View** (`Views/GenerateLicensesPageView.axaml`): add a small Profile action row (buttons
  **Load Profile…** / **Save Profile…**) near the top of the page, bound to the new commands,
  matching existing `Button` styling.
- **Acceptance:** save writes a `.json` with exactly the seven allowed fields and **no**
  password/output-path key; load on a fresh launch repopulates all fields and the algorithm
  combo; a malformed/missing file shows an error toast without crashing; clean build.

---

## Critical files
- `Directory.Packages.props` (PHASE01)
- `src/Enigma.LicenseManager.Desktop/ViewModels/GenerateKeysPageViewModel.cs` `UpdateParameterOptions()` (PHASE02)
- `src/Enigma.LicenseManager.Desktop/Enigma.LicenseManager.Desktop.csproj` (PHASE03)
- `src/Enigma.LicenseManager.Desktop/App.axaml.cs:42` (PHASE03)
- `src/Enigma.LicenseManager.Desktop/Helpers/AppIconHelper.cs` — reuse `WriteIco`, then delete (PHASE03)
- `src/Enigma.LicenseManager.Desktop/ViewModels/GenerateLicensesPageViewModel.cs`,
  `Views/GenerateLicensesPageView.axaml`, new `Models/LicenseProfile.cs` (PHASE04)
- Patterns to mirror: `ConfigurationSetup.cs` (System.Text.Json), `Models/DefaultPathsOptions.cs`
  (POCO), existing Browse commands (file-dialog usage).

## Verification (per phase, at /build time)
- `dotnet build Enigma.LicenseManager.slnx` → **zero warnings** (warnings are errors).
- `dotnet test Enigma.LicenseManager.slnx` → existing suite green (set `DOTNET_ROOT` if the
  xUnit v3 apphost can't find the runtime).
- **Manual run** (`dotnet run --project src/Enigma.LicenseManager.Desktop`):
  - PHASE01: app launches on 12.1.0.
  - PHASE02: RSA key-size combo pre-selects 4096.
  - PHASE03: window/taskbar shows the certificate icon; `.exe` has an embedded icon.
  - PHASE04: Save Profile writes a password-free `.json`; Load Profile repopulates the form;
    a corrupt file shows an error toast.
