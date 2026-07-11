# FEATURE-001-PHASE02 — Desktop app shell & infrastructure

**Completed:** 2026-07-06 · **Branch:** `feature/feature-001-phase02-desktop-shell`

## Summary

Added the Avalonia 12 desktop application `Enigma.LicenseManager.Desktop` (`net10.0`, `WinExe`), mirroring
the reference `Enigma.UI` app's architecture (IHost + DI + Carbon.Avalonia.Desktop theme/services + NLog +
per-user JSON config), scoped to the three license features. The shell hosts a left `NavigationView` with
exactly three pages (Generate Keys / Generate Licenses / Validate Licenses — placeholders until PHASE03) and
a nav-rail-footer **theme toggle** that flips Light↔Dark at runtime and persists the choice to the per-user
config. Unlike Enigma.UI (which forces Dark), this app initializes its theme from the saved config. The app
dogfoods the in-development core library and the PHASE01 Tools layer via `ProjectReference`, and wires the
Tools services through `AddLicenseTools()`.

## Files / modules touched

**Created — `src/Enigma.LicenseManager.Desktop/`:**
- `Enigma.LicenseManager.Desktop.csproj` — `net10.0`, `WinExe`, compiled bindings on. Packages mirror
  Enigma.UI minus cert/encrypt/ML-KEM: Avalonia + Desktop + Themes.Fluent + Fonts.Inter 12.0.5,
  AvaloniaUI.DiagnosticsSupport 2.2.3 (Debug-only), CommunityToolkit.Mvvm 8.4.2, Carbon.Avalonia.Desktop
  0.2.0, Microsoft.Extensions.Hosting 10.0.9, NLog(+Extensions.Logging) 6.1.3, PhosphorIconsAvalonia 1.2.0,
  Enigma.Cryptography 4.3.0, Ulid 1.4.1. **ProjectReferences** to the core lib + Tools (not the NuGet
  package Enigma.UI uses).
- `Program.cs` — `Host.CreateDefaultBuilder` + `StartWithClassicDesktopLifetime`; config from
  `~/.config/EnigmaLicenseManager/config.json`; NLog; registers `AddAppConfiguration`, `AddCarbonServices`,
  **`AddLicenseTools`**, `AddPagesAndViewModels`.
- `App.axaml` — `FluentTheme` + Carbon `Fluent.axaml` `ResourceInclude` + `ProgressOverlayCard.axaml`;
  **no** hardcoded `RequestedThemeVariant`.
- `App.axaml.cs` — resolves `MainWindow`+VM from the host; **initializes `RequestedThemeVariant` from the
  saved config**; window icon via `AppIconHelper` with `Icon.certificate`; `RegisterHost` ×3
  (ContentDialog/Overlay/InfoBar) + `SetStorageProvider` ×2; designer-fallback service provider.
- `ServiceCollectionExtensions.cs` — `extension(IServiceCollection)` block (mirrors Enigma.UI's C# 14 style)
  with `AddAppConfiguration`, `AddCarbonServices`, trimmed `AddPagesAndViewModels` (MainWindow + 3 View/VM
  pairs). `AddLicenseTools` comes from the Tools project.
- `ConfigurationSetup.cs` — `~/.config/EnigmaLicenseManager/config.json`; ensure-file-exists on first run
  (writes `Keys`/`Licenses`/`Theme`); new **`SaveTheme(string)`** write-back that preserves other settings.
- `Models/DefaultPathsOptions.cs` — trimmed to `Keys` + `Licenses` + a persisted `Theme` (default "Dark").
- `Helpers/AppIconHelper.cs`, `Helpers/FileDropHelper.cs` — copied from Enigma.UI (namespace adjusted).
- `Controls/ProgressOverlayCard.cs` + `.axaml` — copied from Enigma.UI (namespace adjusted).
- `NLog.config` — copied from Enigma.UI (`CopyToOutputDirectory`).
- `Views/MainWindow.axaml(.cs)` — `NavigationView` (left) + `ContentControl` + three named host controls +
  quit-confirm dialog; a theme-toggle `Button` (bound to `ToggleThemeCommand`, `circle_half` icon) docked in
  the nav-rail footer.
- `ViewModels/MainWindowViewModel.cs` — `ObservableObject`; registers exactly three `NavigationItem`s;
  hand-written `RelayCommand ToggleThemeCommand` (NO `[RelayCommand]` generator) that flips
  `Application.Current.RequestedThemeVariant` and calls `ConfigurationSetup.SaveTheme`.
- `ViewModels/{GenerateKeys,GenerateLicenses,ValidateLicenses}PageViewModel.cs` +
  `Views/*PageView.axaml(.cs)` — placeholder page pairs (fully built in PHASE03).

**Modified:**
- `Enigma.LicenseManager.slnx` — added the Desktop project.
- `docs/roadmap.md`, `docs/plan/FEATURE-001.md` — PHASE02 → DONE (FEATURE-001 stays IN PROGRESS).

## Deviations & follow-ups

- **MVVM per house rule (no source generators).** `MainWindowViewModel` uses `ObservableObject` + a
  hand-written `RelayCommand` (not `[RelayCommand]`), matching the repo convention. PHASE03 VMs will follow
  the same hand-written `SetProperty`/`AsyncRelayCommand` pattern.
- **Theme storage.** Per the plan, `Theme` lives inside the `DefaultPaths` config section (on
  `DefaultPathsOptions`). It is semantically not a "path"; noting it in case a dedicated `Ui`/`Appearance`
  section is preferred later.
- **`Enigma.Cryptography` 4.3.0 + `Ulid` referenced on Desktop but not yet used directly** by the shell
  (they arrive transitively via Tools too). Kept per the plan; PHASE03 pages will use them.
- **App icon.** No `app-icon.ico` asset (Enigma.UI ships one but sets the window icon programmatically);
  the window icon is generated at runtime by `AppIconHelper` from a Phosphor glyph, so the asset is
  unnecessary.
- **Encoding / line endings.** New files are UTF-8 (no BOM) with LF endings; no CRLF churn. Same
  BOM-vs-no-BOM note as PHASE01 — recommendation only, not acted on.

## Build / test evidence

- `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s), 0 Error(s)** across all four
  projects (Desktop compiles with compiled bindings on — every `{Binding}` in the shell/pages was validated
  against its `x:DataType` at build time).
- `dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0, Passed: 70, Skipped: 0** (unchanged from
  PHASE01; the Desktop project adds no tests, per the plan's "no Avalonia UI tests").

### Runtime verification (non-invasive; live Wayland session)
- **Launch + initial navigation:** ran the built app; the host started cleanly and the classic-desktop
  lifetime came up with a **completely clean startup log** (no XAML/binding/DI exceptions) — the `MainWindow`
  and its bindings loaded and rendered. The `MainWindowViewModel` constructor's `NavigateToAsync` to the
  first page ran to completion, so the full page-resolution path (`PageFactory` → resolve
  `GenerateKeysPageView` + its VM from DI → display) executed end-to-end without error; a user click on a nav
  item re-invokes this same path with a different item. First run created
  `~/.config/EnigmaLicenseManager/config.json` with `Theme: "Dark"`.
- **Theme persistence — read path:** seeded the config with `Theme: "Light"` (+ `Keys`/`Licenses` values),
  relaunched → the app started clean and **did not clobber** the file (theme stayed Light, paths preserved),
  proving startup honors the saved theme rather than forcing Dark.
- **Theme persistence — write path:** exercised the real `ConfigurationSetup.SaveTheme` (the method the
  runtime toggle calls) via a throwaway harness → it flips `Theme` both ways and **preserves** the other
  settings. The runtime flip itself is a standard `RequestedThemeVariant` assignment that Fluent + Carbon
  react to via `DynamicResource`.
- **Not automated:** actual pointer-clicks (selecting a nav item; clicking the toggle button) were not
  driven — no input-injection tool is available in this environment, and full-screen capture was avoided to
  protect the user's private session. The wiring for both is compile-verified (compiled bindings + the
  `RelayCommand` + the `PageFactory`), and the Carbon `NavigationView` behavior is proven in Enigma.UI.
  **Recommended manual check:** launch the app, click through the three pages, click the theme toggle, and
  restart to confirm the theme sticks.

## Acceptance criteria — status
- ✅ `dotnet build` clean (zero warnings); test suite green.
- ◑ `dotnet run` launches the window; navigation switches between the three pages — **launch + render + nav
  wiring verified**; the click-to-switch gesture is a recommended manual check (no input tooling here).
- ✅ Theme toggle persists across a restart — **read + write persistence verified**; the runtime light↔dark
  flip is a standard Avalonia `RequestedThemeVariant` change (verified-by-construction), with a recommended
  manual click-through for final visual confirmation.
