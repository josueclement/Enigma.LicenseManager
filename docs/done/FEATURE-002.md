# FEATURE-002 — License-management CLI tool (`Enigma.LicenseManager.Cli`) — DONE

## Summary

Added a cross-platform command-line tool (`enigma-license`) exposing the same three operations as the
desktop app — **generate keys**, **generate licenses**, **validate licenses** — for scripting, CI, and
headless use. The CLI is a thin layer: argument parsing, output, and exit-code mapping only; 100% of the
crypto/orchestration is delegated to the shared `Enigma.LicenseManager.Tools` services
(`AddLicenseTools()`), which are already covered by the FEATURE-001 PHASE01 unit tests.

The throwaway `src/ConsoleApp1/` demo is removed and dropped from the solution, superseded by this CLI.

Command surface (auto-generated `--help` / `--version` via System.CommandLine):

```
keygen   --algorithm rsa|ml-dsa [--rsa-size 2048|3072|4096|8192] --public <path> --private <path> [--password <pw>]
license generate --product-id <id> [--owner <name>] [--device-id <id>] [--expires <date>] --algorithm rsa|ml-dsa --key <privKey> [--password <pw>] --out <path>
license validate --license <path> --public-key <path> [--product-id <id>] [--device-id <id>]
```

Exit codes: `0` = success / license valid · `1` = license invalid · `2` = operation error (bad password,
missing/unreadable file — reported on stderr).

## Files / modules touched

**Created**
- `src/Enigma.LicenseManager.Cli/Enigma.LicenseManager.Cli.csproj` — `net10.0`, `Exe`, `LangVersion 14`,
  `Nullable enable`, `ImplicitUsings disable`, `TreatWarningsAsErrors`. Packages: `System.CommandLine 2.0.9`,
  `Microsoft.Extensions.Hosting 10.0.9`. ProjectReferences: core library + `Enigma.LicenseManager.Tools`.
  Assembly name `enigma-license`.
- `src/Enigma.LicenseManager.Cli/Program.cs` — entry point; builds an `IHost` (`Host.CreateApplicationBuilder`),
  registers `AddLicenseTools()`, resolves the three services and invokes the root command.
- `src/Enigma.LicenseManager.Cli/CliApplication.cs` — builds the `keygen` / `license generate` /
  `license validate` command tree and maps parsed args onto the Tools path-based overloads. Public + service
  constructor so it is unit-testable with fakes.
- `src/Enigma.LicenseManager.Cli/ExitCodes.cs` — the `0` / `1` / `2` exit-code contract.
- `src/UnitTests/CliTests.cs` — 6 CLI smoke tests using recording/stub fakes (no crypto).

**Modified**
- `Enigma.LicenseManager.slnx` — added the CLI project, removed the `ConsoleApp1` entry.
- `src/UnitTests/UnitTests.csproj` — added ProjectReference to the CLI project.
- `README.md` — Project Structure table: replaced the `src/ConsoleApp1/` row with `src/Enigma.LicenseManager.Cli/`; added a **"### Command-line tool"** examples subsection under `## Tooling` (run-from-source note + `enigma-license` shorthand, end-to-end round-trip, per-command examples for keygen/generate/validate, an exit-codes table, and a CI note). Every example command was executed against the built CLI and confirmed to behave as documented.
- `docs/roadmap.md`, `docs/plan/FEATURE-002.md` — status → `IN PROGRESS` → `DONE`.

**Deleted**
- `src/ConsoleApp1/` (ConsoleApp1.csproj, Program.cs) and its solution entry.

## Deviations & follow-ups

- **README row updated (minor scope addition).** The plan named only the slnx removal, but the README's
  Project Structure table still listed `src/ConsoleApp1/`; left dangling it would contradict the acceptance
  criterion "ConsoleApp1 no longer exists in the repo". Replaced the row with the new CLI project.
- **Historical docs left untouched.** `RELEASENOTES.md` and `CODE-REVIEW.md` also mention ConsoleApp1; these
  are historical records (changelog / a past review), so they were deliberately not edited.
- **`--json` follow-up not implemented.** The plan's optional machine-readable-output flag was left out
  (explicitly optional); can be added later if needed.
- **Error message for a wrong private-key password** surfaces the underlying BouncyCastle text
  ("pad block corrupted") on stderr with exit 2. It is a clear failure signal but not friendly; a future
  polish could translate common crypto/IO exceptions into tidier messages.
- **Line endings:** no CRLF/LF issues observed in the touched files; no action taken (recommendation-only per
  the workflow).

## Build / test evidence

- `dotnet build Enigma.LicenseManager.slnx` → **Build succeeded, 0 Warning(s), 0 Error(s)** (all 5 projects).
- `dotnet test Enigma.LicenseManager.slnx` → **Passed! Failed: 0, Passed: 76, Skipped: 0** (6 new CLI smoke
  tests + 70 existing).
- **End-to-end round-trip (manual), both algorithms:** `keygen` → `license generate` → `license validate`
  returns **VALID (exit 0)**; validating with an unrelated public key and with a tampered license both return
  **INVALID (exit 1)**; product-id mismatch returns **INVALID (exit 1)**. Verified for **RSA** and
  **ML-DSA-87**. Password-protected private-key round-trip validates VALID (exit 0); a wrong password fails
  with a stderr message and **exit 2**.
- `enigma-license --help` lists `keygen` and `license`; `--version` present; `ConsoleApp1` no longer exists in
  `src/` or the solution.
