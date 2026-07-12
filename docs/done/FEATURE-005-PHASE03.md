# FEATURE-005 · PHASE03 — Real embedded app icon

## Summary
The Desktop app had no `.ico` at all: the window icon was synthesized at runtime from the
Phosphor `Icon.certificate` glyph (via `AppIconHelper.CreateWindowIcon`), and the built
executable carried no embedded icon. Shipped a real, committed multi-resolution
`Assets/appicon.ico` and wired it the two house-standard ways (per the `avalonia` skill):

- **`<ApplicationIcon>`** in the csproj — embeds the icon in the Windows `.exe` (Explorer /
  taskbar show it even when the app isn't running; Windows-only, no effect on the Linux/macOS
  binary).
- **`Icon="/Assets/appicon.ico"`** on `MainWindow` — the runtime titlebar/taskbar icon on
  every platform, resolved from the embedded `AvaloniaResource`.

The `.ico` was generated once from the existing `AppIconHelper` rendering logic (a throwaway
`--generate-icon` entry point that rendered the white `Icon.certificate` (`IconType.fill`)
glyph to PNGs at 16/24/32/48/64/128/256 px and packed them into a multi-resolution ICO). The
generated file was then committed and the runtime helper retired: `Helpers/AppIconHelper.cs`
was deleted and the now-dead `mainWindow.Icon = …` assignment plus its unused usings
(`Avalonia.Media`, `Enigma.LicenseManager.Desktop.Helpers`, `PhosphorIconsAvalonia`) were
removed to keep the warnings-as-errors build clean.

## Files/modules touched
**Created**
- `src/Enigma.LicenseManager.Desktop/Assets/appicon.ico` — multi-resolution ICO (7 images:
  16/24/32/48/64/128/256 px, 32-bit RGBA PNG-encoded) of the white certificate glyph.
- `docs/done/FEATURE-005-PHASE03.md` (this file).

**Modified**
- `src/Enigma.LicenseManager.Desktop/Enigma.LicenseManager.Desktop.csproj` — added
  `<ApplicationIcon>Assets/appicon.ico</ApplicationIcon>` to the first `<PropertyGroup>` and a
  `<AvaloniaResource Include="Assets/**" />` `<ItemGroup>`.
- `src/Enigma.LicenseManager.Desktop/Views/MainWindow.axaml` — added `Icon="/Assets/appicon.ico"`
  on the `Window`.
- `src/Enigma.LicenseManager.Desktop/App.axaml.cs` — removed the runtime
  `AppIconHelper.CreateWindowIcon(...)` assignment and the three now-unused usings.
- `docs/roadmap.md` — PHASE03 status `TODO` → `IN PROGRESS` → `DONE`.
- `docs/plan/FEATURE-005.md` — PHASE03 status and the header progress line updated.

**Deleted**
- `src/Enigma.LicenseManager.Desktop/Helpers/AppIconHelper.cs` — the runtime icon synthesizer
  (its `WriteIco`/`RenderToPng` logic was reused once to emit the static `.ico`, then retired).

## Deviations & follow-ups
- **Plan claim vs. reality — `.gitattributes`:** the plan (and the `avalonia`/`git-repo-hygiene`
  skills) state that `*.ico binary` is "already" marked, but the repo has **no `.gitattributes`
  file at all**. This is harmless for committing the icon — git auto-detects the `.ico` as binary
  by content — so no file was created (it would be out of this phase's scope: Desktop +
  `Directory.Packages.props`). **Follow-up recommendation:** if a `.gitattributes` is ever added
  for this repo (e.g. via `git-repo-hygiene`), include `*.ico binary`.
- **`.exe` icon on Linux:** `<ApplicationIcon>` only stamps the icon into the **Windows** apphost.
  This build runs on Linux, where the apphost is an ELF binary and receives no embedded icon —
  expected and correct; the property takes effect when built/published for a Windows RID. The
  runtime window icon (`Icon="/Assets/appicon.ico"`) works on every platform.
- **Generation approach:** the plan suggested a "one-off generator" reusing `AppIconHelper`. Rather
  than a separate throwaway project, a temporary `--generate-icon <path>` branch was added to
  `Program.Main` (using `BuildAvaloniaApp().SetupWithoutStarting()` to initialize the render
  platform) alongside a temporary `AppIconHelper.WriteIcoFile`. Both were removed before completion:
  `Program.cs` was restored to its exact original (confirmed absent from the final diff) and
  `AppIconHelper.cs` was deleted outright.
- No CRLF / line-ending churn observed in the touched text files.

## Build/test evidence
- **Build:** `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s),
  0 Error(s)** (warnings-as-errors + `EnforceCodeStyleInBuild` solution-wide; the removed usings
  were pruned to stay clean).
- **Tests:** `DOTNET_ROOT=… dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0,
  Passed: 76, Skipped: 0, Total: 76** (existing suite green; Desktop has no test project, so no
  new tests per the plan).
- **Icon asset verified:** parsed the produced `appicon.ico` — a valid `type=1` ICO with **7
  images** at the expected sizes, each 32-bit RGBA PNG; pixel inspection confirmed the white
  certificate glyph rendered (58–69% opaque white pixels, not a blank canvas).
- **Resource embedding verified:** the resource path `Assets/appicon.ico` is present in the built
  `Enigma.LicenseManager.Desktop.dll` (`AvaloniaResource` compiled in).
- **Manual run:** `dotnet run --project src/Enigma.LicenseManager.Desktop` launched cleanly and
  ran to the timeout with **no startup/icon-resolution exceptions** — confirming `MainWindow`
  builds with the `avares://…/Assets/appicon.ico` icon resolving. (The visual taskbar/titlebar
  appearance is best confirmed interactively by the user.)
- **Acceptance criteria met:** clean build; window icon resolves to the committed certificate
  `.ico` (embedded `AvaloniaResource` + clean launch); `.exe` icon wired via `<ApplicationIcon>`;
  no unused-symbol warnings (all three dead usings removed, `AppIconHelper` deleted).
