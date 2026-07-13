# FEATURE-006 — Package the desktop app as a Windows MSI installer (1.2.0)

**Status: DONE** (single-phase)

## Summary

Delivered a Windows MSI installer profile for the `Enigma.LicenseManager.Desktop` Avalonia app so it can
be installed as a normal Windows product. Followed the `dotnet-release` skill's **app** path (not the
library path): the desktop csproj now carries an explicit `<Version>`, a committed WixSharp MSI profile
was generated under `msiProfiles/`, and the release/README/notes docs gained an installer section. No
library version change, no NuGet pack/push, and no new git tag — the tree is already released as `1.2.0`,
so the app is aligned to `1.2.0` and the existing tag covers it. Scope stopped at the JSON profile; no
`.msi` was built and WixSharp was not invoked.

## Files/modules touched

**Created**
- `msiProfiles/Enigma.LicenseManager.Desktop.msiprofile.1.2.0.json` — first MSI profile for the app.
  Field set/order matches the `dotnet-release` template. Display name "Enigma License Manager",
  PerMachine install to `%ProgramFiles%\Enigma License Manager`, High compression, Desktop +
  Start Menu shortcuts targeting `[INSTALLDIR]\Enigma.LicenseManager.Desktop.exe`, icon
  `Assets\appicon.ico`. GUIDs generated locally with `/proc/sys/kernel/random/uuid` (never fabricated):
  - `upgradeCode` = `86a46add-9e89-4a0a-ac28-2c31001c1af4` (stable app identity — reuse verbatim in every
    future release's profile)
  - `productId` = `61c9a745-ea1b-4efd-aade-94cdff7006e4` (regenerate for each new version)
- `docs/done/FEATURE-006.md` — this record.

**Modified**
- `src/Enigma.LicenseManager.Desktop/Enigma.LicenseManager.Desktop.csproj` — added `<Version>1.2.0</Version>`
  (previously none; the exe would otherwise report 1.0.0).
- `docs/RELEASE.md` — appended a "Desktop app — Windows installer (MSI)" section (reproducible build,
  GUID contract, unsigned/framework-dependent scope, 1.2.0 install profile). NuGet-library sections
  left untouched.
- `RELEASENOTES.md` — added a "Windows installer (MSI)" bullet under the existing `v1.2.0` *Desktop app*
  section (version unchanged, so appended rather than a new section).
- `README.md` — added a one-line installer note next to the 1.2.0 what's-new callout.
- `docs/roadmap.md`, `docs/plan/FEATURE-006.md` — status `TODO` → `IN PROGRESS` → `DONE`.

## Deviations & follow-ups

- **No deviations from the plan.** All decisions in the plan's decisions table were implemented as
  specified.
- **`outputPath` is a deliberate placeholder** (`<USER-DEFINED — the user fills this in>`), per the
  decisions table — the user sets the `.msi` destination folder when building the installer. This is the
  one intentionally-unfilled field; every other field is populated.
- **Building the `.msi` is out of scope** — the profile is consumed by the WixSharp MSI builder on the
  user side. No signing and no self-contained/runtime bundling (framework-dependent, unsigned).
- **Line endings (recommendation only, no action taken):** the working tree was already dirty across
  ~88 files that differ **only** by line endings (CRLF/LF churn: symmetric 8163+/8163- diff,
  `git diff --ignore-space-at-eol` shows 0 content-differing files). The branch was cut from that dirty
  `HEAD` at the user's direction. Four docs edited here (`README.md`, `RELEASENOTES.md`,
  `docs/RELEASE.md`, `docs/roadmap.md`) were already in the churn set, so their diffs mix real edits with
  CRLF churn. Recommend normalizing separately via a `.gitattributes` `* text=auto eol=lf` rule +
  `git add --renormalize .` — **not** as part of this dev. At commit time, stage only FEATURE-006's
  files.

## Build/test evidence

- `dotnet build Enigma.LicenseManager.slnx -c Release` → **Build succeeded, 0 Warning(s), 0 Error(s)**
  across all TFMs.
- `dotnet test Enigma.LicenseManager.slnx -c Release` → **Passed! Failed: 0, Passed: 76, Skipped: 0,
  Total: 76.** (No test-affecting changes were made.) The lone `MTP0001` line is a pre-existing
  Microsoft.Testing.Platform tooling notice emitted under `dotnet test`, not a build warning, and is
  unrelated to this change.
- Assembly version confirmed from the SDK-generated `AssemblyInfo`: `AssemblyFileVersion 1.2.0.0`,
  `AssemblyInformationalVersion 1.2.0+<commit>`, `AssemblyVersion 1.2.0.0`.
- MSI profile JSON validated: parses cleanly, all 13 fields present in template order, real
  (non-placeholder) `productId`/`upgradeCode` GUIDs, 2 shortcuts.
