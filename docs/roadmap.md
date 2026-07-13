# Roadmap

Single registry of every tracked work item. Status vocabulary: `TODO`, `IN PROGRESS`, `DONE`, `ABANDONED`.

| ID          | Title                                              | Status | Plan                     |
|-------------|----------------------------------------------------|--------|--------------------------|
| FEATURE-001 | License-management desktop app (Avalonia) + Tools  | DONE   | docs/plan/FEATURE-001.md |
| - PHASE01   | Shared operations library `Enigma.LicenseManager.Tools` + unit tests | DONE | (in FEATURE-001.md) |
| - PHASE02   | Desktop app shell & infrastructure                 | DONE   | (in FEATURE-001.md)      |
| - PHASE03   | Feature pages: Generate Keys / Generate Licenses / Validate Licenses | DONE | (in FEATURE-001.md) |
| FEATURE-002 | License-management CLI tool (`Enigma.LicenseManager.Cli`) | DONE | docs/plan/FEATURE-002.md |
| FEATURE-003 | Upgrade Enigma.Cryptography to 5.0.0 + Central Package Management | DONE | docs/plan/FEATURE-003.md |
| FEATURE-004 | Prepare 1.2.0 release (build-config, deps, xUnit v3, docs) | DONE   | docs/plan/FEATURE-004.md |
| - PHASE01   | Build-settings consolidation (`Directory.Build.props` + `.editorconfig`) | DONE | (in FEATURE-004.md) |
| - PHASE02   | `Directory.Packages.props` overhaul + non-Avalonia dependency refresh | DONE | (in FEATURE-004.md) |
| - PHASE03   | xUnit v2 → v3 migration                            | DONE   | (in FEATURE-004.md)      |
| - PHASE04   | Production-readiness docs + release checklist      | DONE   | (in FEATURE-004.md)      |
| FEATURE-005 | Avalonia desktop improvements                      | DONE   | docs/plan/FEATURE-005.md |
| - PHASE01   | Bump Avalonia 12.0.5 → 12.1.0                       | DONE   | (in FEATURE-005.md)      |
| - PHASE02   | Default RSA key size = 4096                        | DONE   | (in FEATURE-005.md)      |
| - PHASE03   | Real embedded app icon (`Assets/appicon.ico`)      | DONE   | (in FEATURE-005.md)      |
| - PHASE04   | License profiles (save / load)                     | DONE   | (in FEATURE-005.md)      |
| FEATURE-006 | Package the desktop app as a Windows MSI installer (1.2.0) | DONE   | docs/plan/FEATURE-006.md |
