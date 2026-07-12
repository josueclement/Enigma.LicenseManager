# FEATURE-004-PHASE04 — Production-readiness docs & release checklist

## Summary

Final phase of the 1.2.0 production-readiness pass: a documentation sweep and a reusable release runbook.
Added NuGet + MIT-license badges to the README, added `<PackageReleaseNotes>` to the library csproj, expanded
the `RELEASENOTES.md` `v1.2.0` section to cover the FEATURE-004 work (dependency refresh, xUnit v3, build-config
consolidation), refreshed the stale bits of `CLAUDE.md`, and authored a new `docs/RELEASE.md` runbook. No source
or behavioural change — docs and package metadata only.

The README's code samples and CLI reference were verified against the built 1.2.0 API and found accurate (no
correction needed) — see *Deviations* below.

## Files/modules touched

**Created**
- `docs/RELEASE.md` — reusable release checklist (pre-release checks → merge to `master` → tag → `dotnet pack`
  → `dotnet nuget push` → post-publish/badge verification). The sibling repo has no equivalent to mirror, so
  authored fresh.
- `docs/done/FEATURE-004-PHASE04.md` — this record.

**Modified**
- `README.md` — added `[![NuGet]]` (version) and `[![License: MIT]]` badges under the title, plus a "What's
  new in 1.2.0" callout blockquote linking to `RELEASENOTES.md` (added during the freshness sweep, for sibling
  parity).
- `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj` — added `<PackageReleaseNotes>` (prose summary
  pointing to `RELEASENOTES.md`, mirroring the sibling's pattern).
- `RELEASENOTES.md` — expanded the `v1.2.0` section: an intro line, a non-Avalonia dependency-refresh bullet
  and an Avalonia-hold bullet under *Dependencies*, a build-settings-consolidation bullet under *Build &
  Tooling*, and a new *Tests* section for the xUnit v3 migration.
- `CLAUDE.md` — "three-class library" → four-class core (added `LicenseUtils`) plus descriptions of the Tools/
  CLI/Desktop projects; noted per-project TFMs (Tools `net8.0`; CLI/Desktop/tests `net10.0`); added a Key
  Conventions bullet documenting `Directory.Build.props` + `.editorconfig`. (The xUnit v3 test-stack lines were
  already updated in PHASE03.)
- `docs/roadmap.md`, `docs/plan/FEATURE-004.md` — status flips (see below).

## Deviations & follow-ups

- **CLAUDE.md test-stack already current.** Lines describing the test stack were updated to xUnit v3 during
  PHASE03, so this phase completed only the remaining stale items (class count, project list, build config).
- **README samples/CLI reference verified, no drift found.** All samples match the current API — `LicenseBuilder`
  fluent methods, `LicenseService.IsValid(...)` returning a `(bool, string?)` tuple, `LicenseUtils.GenerateDeviceId()`,
  `License.SaveAsync/LoadAsync` — and the CLI command tree (`keygen`, `license generate`, `license validate`),
  options, and exit codes (`0`/`1`/`2`) are accurate against `CliApplication.cs` and `ExitCodes.cs`. Only the
  badges were added.
- **Badges.** Added the two the plan names (NuGet version + MIT license). The sibling additionally carries a
  NuGet *Downloads* badge — optional parity follow-up if fuller alignment is wanted.
- **README "what's new" callout (added via sweep).** During the documentation freshness sweep the user opted
  to add a "What's new in 1.2.0" blockquote to the README top (linking to `RELEASENOTES.md`), matching the
  sibling's convention. It rides in this phase's commit.
- **`CODE-REVIEW.md` left as-is.** The repo-root `CODE-REVIEW.md` is a dated point-in-time review of v1.0.0
  (commit `be390aa`); it is a historical record, not living documentation, so it was intentionally not edited.
- **`MTP0001` test-platform notice (pre-existing).** `dotnet test` emits `warning MTP0001` (VSTest-specific
  `VSTestTestAdapterPath` ignored under the Microsoft Testing Platform). It is benign, originates from the
  PHASE03 xUnit v3 migration (documented in `docs/done/FEATURE-004-PHASE03.md`), and does **not** appear in
  `dotnet build` (0 warnings). Not a PHASE04 regression.
- **Line endings.** No CRLF churn observed in the touched files (all LF). Per house policy this phase runs no
  `git renormalize`; the plan's standing recommendation to add `.gitattributes` (`* text=auto eol=lf`) in a
  separate commit still applies.

## Build/test evidence

- **Build:** `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded. 0 Warning(s), 0 Error(s)** across
  `netstandard2.0` / `net8.0` / `net10.0` (`TreatWarningsAsErrors=true` is solution-wide).
- **Tests:** `dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0, Passed: 76, Skipped: 0, Total: 76**
  on xUnit v3 — parity with the pre-phase baseline; no regression.
- **Acceptance criteria:** docs are well-formed and internally consistent; samples/CLI reference verified against
  the build; no build/test regressions. All met.
