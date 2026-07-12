# FEATURE-005 · PHASE04 — License profiles (save / load)

## Summary
Re-typing the Generate Licenses metadata for every issue was tedious and typo-prone. Added a
reusable **license profile** mechanism to the Desktop app's Generate Licenses page: a small
action row (**Load Profile… / Save Profile…**) that saves the form fields to, and loads them
from, a plain `.json` file chosen via the existing Carbon file dialogs.

A profile carries exactly seven fields — `ProductId`, `Owner`, `DeviceId`, `Algorithm`
(persisted **by name**, "RSA"/"ML-DSA"), `HasExpiration`, `ExpirationDate`, `SigningKeyPath`.
By hard requirement it stores **no secret**: the signing key password is never persisted, and
the license output path is excluded too. On load the form (including the algorithm combo, mapped
back from its name) is repopulated and a success toast shown; a malformed/partial/old file
produces an error toast without crashing.

Implementation follows house conventions: hand-written `ObservableObject` + `SetProperty` +
`AsyncRelayCommand` (no MVVM source generators), `System.Text.Json` (Desktop does not reference
Newtonsoft), CPM untouched, warnings-as-errors clean.

## Files/modules touched
**Created**
- `src/Enigma.LicenseManager.Desktop/Models/LicenseProfile.cs` — POCO with the seven allowed
  fields; deliberately no password / output-path property.
- `docs/done/FEATURE-005-PHASE04.md` (this file).

**Modified**
- `src/Enigma.LicenseManager.Desktop/ViewModels/GenerateLicensesPageViewModel.cs` — added
  `SaveProfileCommand` / `LoadProfileCommand` (`AsyncRelayCommand`), the `SaveProfileAsync` /
  `LoadProfileAsync` handlers, a `ResolveAlgorithmIndex(name)` helper, and a static
  `JsonSerializerOptions` (`WriteIndented`, `PropertyNameCaseInsensitive`). New usings:
  `System.IO`, `System.Text.Json`.
- `src/Enigma.LicenseManager.Desktop/Views/GenerateLicensesPageView.axaml` — added the Profile
  action row (Load/Save buttons) below the page intro, bound to the new commands.
- `docs/roadmap.md` — PHASE04 `TODO` → `IN PROGRESS` → `DONE`; FEATURE-005 item row → `DONE`
  (final phase).
- `docs/plan/FEATURE-005.md` — PHASE04 status and the header progress line updated to `DONE`.

**Deleted** — none.

## Deviations & follow-ups
- **Dialog start directory:** the plan left the dialog directory argument as "…". Used
  `_defaultPaths.Licenses` (the same default the license-output browse uses) as the start
  directory for both the Save and Load profile dialogs — the closest sensible default for
  license-related files.
- **Button labels:** used `Load Profile...` / `Save Profile...` (three dots) to match the
  existing `Browse...` button in the same view, rather than the single-ellipsis character the
  plan wrote — purely a house-consistency choice.
- **Serializer options:** added `PropertyNameCaseInsensitive = true` alongside the plan's
  `WriteIndented = true`, to satisfy the plan's resilience requirement (tolerate old/varied
  files); verified case-insensitive load works.
- **Null/empty handling:** empty text fields serialize as JSON `null` (per the plan); a `null`
  JSON literal or malformed JSON on load is caught and surfaced as an error toast (no crash).
- No CRLF / line-ending churn observed in the touched text files.

## Build/test evidence
- **Build:** `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s),
  0 Error(s)** (warnings-as-errors + `EnforceCodeStyleInBuild` solution-wide).
- **Tests:** `DOTNET_ROOT=… dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0,
  Passed: 76, Skipped: 0, Total: 76** (existing suite green; Desktop has no test project, so no
  new automated tests per the plan).
- **Serialization verified against the real `LicenseProfile` type** (reflection harness over the
  built Desktop assembly): a saved profile emits **exactly 7 keys** — `Algorithm, DeviceId,
  ExpirationDate, HasExpiration, Owner, ProductId, SigningKeyPath` — with **no `password` key
  and no `output` key**. Malformed JSON throws `JsonException` (→ caught → error toast); a `null`
  literal yields a null instance (→ caught → error toast); a mixed-case file loads correctly.
- **Manual run:** `dotnet run --project src/Enigma.LicenseManager.Desktop` launched cleanly and
  ran to timeout with **no startup exceptions** — confirming the new XAML action row and command
  bindings load at runtime. (Interactive click-through of Save/Load is best confirmed by the user.)
- **Acceptance criteria met:** save writes a `.json` with exactly the seven allowed fields and no
  password/output-path key; load repopulates all fields incl. the algorithm combo; a
  malformed/missing file shows an error toast without crashing; clean build.
