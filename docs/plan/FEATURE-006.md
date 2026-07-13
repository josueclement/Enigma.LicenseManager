# FEATURE-006 — Package the desktop app as a Windows MSI installer (1.2.0)

**Status: DONE** (single-phase)

## Context

The repo is already released at **1.2.0** (core library, tagged `1.2.0`; `RELEASENOTES.md` and
README already cut for it). The Avalonia desktop app (`Enigma.LicenseManager.Desktop`) shipped its
improvements as part of that 1.2.0 tree (FEATURE-005), but **no distributable installer has ever been
produced for it** and there is no `msiProfiles/` directory. This item delivers a **Windows MSI
installer profile** for the desktop app so it can be installed like a normal Windows product.

This follows the `dotnet-release` skill's **app** path (not the library path): the version/notes/tag
concerns apply, NuGet `pack`/`push` are skipped, and a home-made **MSI profile** (a JSON file that
WixSharp later turns into an `.msi`) is generated. Because 1.2.0 is already released and there are no
pending functional changes, the app is versioned **1.2.0** to match the tree — **no new git tag is
needed** (`1.2.0` already exists).

**Tracking:** single-phase feature, its own branch + commit per the dev-workflow, branched from the
current `HEAD` at build time. Suggested branch: `feature/feature-006-desktop-msi-installer`.

## Objective & scope

In scope:
- `src/Enigma.LicenseManager.Desktop/Enigma.LicenseManager.Desktop.csproj` (add `<Version>`).
- `msiProfiles/` (new dir) + the first MSI profile JSON.
- `docs/RELEASE.md`, `RELEASENOTES.md`, `README.md` (installer documentation/notes).

Out of scope:
- No library version change (stays 1.2.0); no `<PackageReleaseNotes>` edit; no NuGet `pack`/`push`.
- **No new git tag** — `1.2.0` already covers this tree.
- No `.msi` build and no WixSharp invocation (scope stops at the JSON profile).
- No MSI code signing, no self-contained/runtime bundling (framework-dependent, unsigned).
- Line endings: the working tree is dirty across ~85 files, consistent with CRLF/LF churn.
  **Recommendation only** (per house rules) — do not normalize as part of this work; if desired,
  handle separately via a `.gitattributes` `* text=auto eol=lf` renormalize.

## Decisions (confirmed with the user)

| Topic | Decision |
|---|---|
| Release version | **1.2.0** — align to current release; no new tag |
| Desktop csproj `<Version>` | **Add `<Version>1.2.0</Version>`** so the exe reports 1.2.0 instead of the 1.0.0 default |
| Installer display name | **"Enigma License Manager"** (friendly), distinct from the exe name |
| Install scope | **PerMachine** (Program Files; needs admin) |
| Shortcuts | **Start Menu + Desktop**, both targeting the installed exe |
| `.msi` output path | **User-defined** — left as a placeholder for the user to fill when building the MSI |
| Supporting docs | **`docs/RELEASE.md`** (MSI section) + **`RELEASENOTES.md`/`README.md`** (installer note appended to existing 1.2.0 material) |

## Implementation steps

### 1. Desktop csproj — add version
Add `<Version>1.2.0</Version>` to the top `<PropertyGroup>` of
`src/Enigma.LicenseManager.Desktop/Enigma.LicenseManager.Desktop.csproj` (currently none; exe would
otherwise report 1.0.0). No other csproj changes; the app stays `WinExe` / `net10.0`, non-packable,
no `PackageId`.

### 2. MSI profile — new file (first profile for this app)
Create `msiProfiles/` at the solution root and write
**`msiProfiles/Enigma.LicenseManager.Desktop.msiprofile.1.2.0.json`** (version-suffixed; committed so
`upgradeCode` persists across releases). Field order matches the `dotnet-release` template exactly:

```jsonc
{
  "appName": "Enigma License Manager",
  "installPath": "%ProgramFiles%\\Enigma License Manager",
  "releasePath": "src\\Enigma.LicenseManager.Desktop\\bin\\Release\\net10.0",
  "scope": "PerMachine",
  "version": "1.2.0",
  "productId": "<GENERATE new GUID at build>",     // new every release
  "upgradeCode": "<GENERATE once at build>",        // stable identity, reused verbatim forever
  "manufacturer": "Josué Clément",
  "productIcon": "src\\Enigma.LicenseManager.Desktop\\Assets\\appicon.ico",
  "compression": "High",
  "outputPath": "<USER-DEFINED — the user fills this in>",
  "msiFilename": "Enigma.LicenseManager.Desktop",
  "shortcuts": [
    { "shortcutPath": "%Desktop%",     "shortcutName": "Enigma License Manager",
      "targetPath": "[INSTALLDIR]\\Enigma.LicenseManager.Desktop.exe",
      "iconPath": "src\\Enigma.LicenseManager.Desktop\\Assets\\appicon.ico", "arguments": "" },
    { "shortcutPath": "%ProgramMenu%", "shortcutName": "Enigma License Manager",
      "targetPath": "[INSTALLDIR]\\Enigma.LicenseManager.Desktop.exe",
      "iconPath": "src\\Enigma.LicenseManager.Desktop\\Assets\\appicon.ico", "arguments": "" }
  ]
}
```

Notes:
- **GUIDs (`productId`, `upgradeCode`) are generated at build time** with a local generator
  (`uuidgen` / `cat /proc/sys/kernel/random/uuid` / `[guid]::NewGuid()`) — the one documented
  exception to the skill's print-don't-run boundary. **Never fabricated by hand.**
- File stem `Enigma.LicenseManager.Desktop` is used (stable, space-free glob key for detecting the
  most-recent profile on future releases); the friendly display name lives in the `appName` field.
- `releasePath` points at the not-yet-built Release output — warn if `bin\Release\net10.0` is absent.
- The `targetPath` exe is `Enigma.LicenseManager.Desktop.exe` (assembly name = project name).

### 3. `docs/RELEASE.md` — add an MSI/installer section
Append a "Desktop app — Windows installer (MSI)" section documenting the reproducible build:
`dotnet build -c Release` the desktop project, then feed
`msiProfiles/Enigma.LicenseManager.Desktop.msiprofile.<version>.json` to the WixSharp MSI builder to
emit the `.msi` at `outputPath`. Note the scope stops at producing the `.msi` (no signing). Leave the
existing NuGet-library sections untouched.

### 4. `RELEASENOTES.md` + `README.md` — installer note
Version stays 1.2.0, so **append** to the existing 1.2.0 material rather than adding a new section:
- `RELEASENOTES.md` — a short "Desktop app" line under the `v1.2.0` section noting a Windows MSI
  installer is now available.
- `README.md` — a one-line note (near the what's-new callout) that a Windows installer for the
  desktop app is available.

## Acceptance criteria
1. `Enigma.LicenseManager.Desktop.csproj` carries `<Version>1.2.0</Version>`; solution builds clean
   with zero warnings.
2. `msiProfiles/Enigma.LicenseManager.Desktop.msiprofile.1.2.0.json` exists, is valid JSON, matches
   the template field set/order, and has real (generated, non-placeholder) `productId` and
   `upgradeCode` GUIDs.
3. Profile values match the decisions table (display name, PerMachine, both shortcuts, High
   compression, manufacturer, icon, msiFilename); `outputPath` holds the user-supplied value.
4. `docs/RELEASE.md` has an MSI/installer section; `RELEASENOTES.md` and `README.md` mention the
   Windows installer.
5. Roadmap + this plan's status updated and `docs/done/FEATURE-006.md` written.

## Verification
- `dotnet build Enigma.LicenseManager.slnx -c Release` → 0 warnings; confirm the built
  `Enigma.LicenseManager.Desktop.exe` reports file/product version 1.2.0.
- `dotnet test Enigma.LicenseManager.slnx` → suite still green (no test-affecting changes).
- Validate the profile JSON parses and every field is populated (no `{{…}}` placeholders except the
  deliberately user-supplied `outputPath` once filled).
- (Manual, user-side, out of scope) run the WixSharp builder against the profile to confirm an `.msi`
  is produced.
