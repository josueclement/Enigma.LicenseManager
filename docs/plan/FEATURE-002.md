# FEATURE-002 — License-management CLI tool (`Enigma.LicenseManager.Cli`)

**Status:** TODO · **Type:** FEATURE (single-phase) · **Planned now, built later.**

## Objective

A cross-platform command-line tool for the same operations as the desktop app — **generate keys**,
**generate licenses**, **validate licenses** — for scripting, CI, and headless use. Depends on the
same `Enigma.LicenseManager.Tools` library built in FEATURE-001 (so all crypto/orchestration is
already tested there).

> **Dependency:** FEATURE-001 PHASE01 (`Enigma.LicenseManager.Tools`) must be complete first.

## Context

The repo currently ships a throwaway `src/ConsoleApp1/` demo (hardcoded RSA keygen + license
round-trip, no argument parsing). The real CLI supersedes it — **`ConsoleApp1` is removed as part of
this work item** and dropped from the solution.

## Scope & key decisions

- New project `src/Enigma.LicenseManager.Cli/`: `net10.0`, `Exe`, IHost + **System.CommandLine**.
  ProjectReferences: core library + **`Enigma.LicenseManager.Tools`** (`AddLicenseTools`).
  `LangVersion 14`, `Nullable enable`, `ImplicitUsings disable`, `TreatWarningsAsErrors`.
- Delegates 100% of logic to Tools — the CLI is only argument parsing, wiring, output, and exit codes.
- Remove `src/ConsoleApp1/` and its entry in `Enigma.LicenseManager.slnx`.

## Command surface

```
keygen   --algorithm rsa|ml-dsa [--rsa-size 2048|3072|4096|8192]
         --public <path> --private <path> [--password <pw>]

license generate --product-id <id> [--owner <name>] [--device-id <id>] [--expires <date>]
                 --algorithm rsa|ml-dsa --key <privateKeyPath> [--password <pw>] --out <path>

license validate --license <path> --public-key <path> [--product-id <id>] [--device-id <id>]
```

- ML-DSA is level **87** only (mirrors the library constraint) — `--rsa-size` applies to RSA only.
- `keygen` → `IKeyGenerationService.GenerateAndSaveKeyPairAsync`.
- `license generate` → `ILicenseGenerationService.CreateAndSaveLicenseAsync` (path overload).
- `license validate` → `ILicenseValidationService.ValidateAsync`; prints the result message.
- **Exit codes:** `0` = success / license valid; **non-zero** = failure / license invalid (so it's
  usable in scripts and CI gates). Errors (bad password, missing file) → clear stderr message +
  non-zero exit.
- Auto-generated `--help` / `--version` from System.CommandLine.
- **Follow-up (optional):** a `--json` flag on `license validate` (and others) for machine-readable
  output.

## Testing

Logic is already covered by the Tools unit tests (FEATURE-001 PHASE01). Add a couple of cheap CLI
smoke tests if practical (argument parsing → correct service call; exit-code mapping for
valid/invalid). No heavy end-to-end harness required.

## Acceptance criteria

- `dotnet build Enigma.LicenseManager.slnx` clean (zero warnings); test suite green.
- End-to-end round-trip verified:
  `keygen ...` → `license generate ...` → `license validate ...` returns **valid** (exit 0);
  wrong public key / tampered license returns **invalid** (non-zero exit). Repeat for ML-DSA-87.
- `--help` lists all commands; `ConsoleApp1` no longer exists in the repo or solution.

## Definition of Done (per dev-workflow)
Build clean (0 warnings) · tests pass · acceptance criteria met · roadmap + this plan updated ·
`docs/done/FEATURE-002.md` written.
