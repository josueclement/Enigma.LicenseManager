# FEATURE-005 · PHASE02 — Default RSA key size = 4096

## Summary
The Generate Keys page defaulted the RSA key-size combo to `2048`. Changed the default
pre-selection to `4096` (the safer default) while leaving ML-DSA on its single option. The
change is a one-line adjustment in `UpdateParameterOptions()`: instead of always selecting
index 0, RSA now selects index 2 (`"4096"`) and ML-DSA selects index 0 (`"ML-DSA-87"`).

## Files/modules touched
**Modified**
- `src/Enigma.LicenseManager.Desktop/ViewModels/GenerateKeysPageViewModel.cs` —
  `UpdateParameterOptions()`: `SelectedParameterIndex = SelectedAlgorithmIndex == 0 ? 2 : 0;`
  (was `= 0;`), with an explanatory comment.
- `docs/roadmap.md` — PHASE02 status `TODO` → `IN PROGRESS` → `DONE`.
- `docs/plan/FEATURE-005.md` — PHASE02 status and header progress line updated.

**Created**
- `docs/done/FEATURE-005-PHASE02.md` (this file).

## Deviations & follow-ups
- Implemented exactly as the plan specified (`SelectedParameterIndex = SelectedAlgorithmIndex == 0 ? 2 : 0;`).
  No deviations.
- **Manual-run verification:** the GUI visual check (combo showing 4096 on launch) could not be
  observed in this headless session. The behaviour is verified by code inspection and the clean
  build; the user can confirm visually via `dotnet run --project src/Enigma.LicenseManager.Desktop`.
- No CRLF / line-ending churn observed in the touched files.

## Build/test evidence
- **Build:** `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s), 0 Error(s)**
  (warnings-as-errors solution-wide).
- **Tests:** `DOTNET_ROOT=~/.dotnet dotnet test Enigma.LicenseManager.slnx` →
  **Passed! Failed: 0, Passed: 76, Skipped: 0, Total: 76** (existing suite green; Desktop has no
  test project, so no new tests per the plan).
- **Acceptance criteria met:**
  - On launch (RSA selected), `SelectedParameterIndex = 2` → `ParameterOptions[2] = "4096"`.
  - Switching to ML-DSA (index 0 → `"ML-DSA-87"`) and back to RSA re-selects index 2 (`"4096"`);
    the round-trip toggles 2→0→2 so `SetProperty` fires each time.
  - Generation still parses the value: `(RsaKeySize)int.Parse("4096")` maps to the existing
    `RsaKeySize.Rsa4096 = 4096` enum member.
