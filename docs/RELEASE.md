# Release runbook

Reusable checklist for publishing a new **Enigma.LicenseManager** version to NuGet. Only the core library
(`src/Enigma.LicenseManager/`) is packable and published; the Tools, CLI, and Desktop projects ship as source.

Replace `X.Y.Z` with the version being released (e.g. `1.2.0`) throughout. The version lives in
`src/Enigma.LicenseManager/Enigma.LicenseManager.csproj` (`<Version>`); the CLI carries its own independent
`<Version>` and is not published to NuGet.

## 1. Pre-release checks

Run from the repository root, on the branch that will be merged:

- [ ] `<Version>X.Y.Z</Version>` set in `src/Enigma.LicenseManager/Enigma.LicenseManager.csproj`.
- [ ] `RELEASENOTES.md` has a top `vX.Y.Z` section describing the release.
- [ ] `<PackageReleaseNotes>` in the library csproj summarizes the release and points to `RELEASENOTES.md`.
- [ ] Clean, warning-free build across all TFMs:
      ```bash
      dotnet build Enigma.LicenseManager.slnx -c Release
      ```
- [ ] Full test suite green (xUnit v3 / Microsoft Testing Platform):
      ```bash
      dotnet test Enigma.LicenseManager.slnx -c Release
      # If the test apphost can't find the runtime, prefix: DOTNET_ROOT=~/.dotnet
      ```
- [ ] `README.md` samples and the CLI reference verified against the built version.

## 2. Merge to `master`

The default (published) branch is `master`. Merge the release branch in via a pull request (or fast-forward),
then check it out locally:

```bash
git switch master
git pull
```

## 3. Tag the release

Tag the merge commit and push the tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

## 4. Pack

`GeneratePackageOnBuild` produces a `.nupkg` on every build, but pack explicitly in Release to get the
artifact you publish:

```bash
dotnet pack src/Enigma.LicenseManager/Enigma.LicenseManager.csproj -c Release -o ./artifacts
```

This writes `./artifacts/Enigma.LicenseManager.X.Y.Z.nupkg`. Confirm the version in the filename matches the
tag, and (optionally) inspect the package contents — it should bundle `README.md` and `LICENSE.md` and declare
the expected dependency floors (`Enigma.Cryptography`, `DeviceId`, `Newtonsoft.Json`, `Ulid`).

## 5. Push to NuGet

Publish with a NuGet API key that has push rights for the `Enigma.LicenseManager` package:

```bash
dotnet nuget push ./artifacts/Enigma.LicenseManager.X.Y.Z.nupkg \
  --api-key <NUGET_API_KEY> \
  --source https://api.nuget.org/v3/index.json
```

`dotnet pack` also emits a `.snupkg` symbols package alongside the `.nupkg`; pushing the `.nupkg` uploads the
matching symbols automatically.

## 6. Post-publish verification

- [ ] The package page shows the new version: <https://www.nuget.org/packages/Enigma.LicenseManager> (indexing
      can take a few minutes).
- [ ] The README NuGet badge resolves to `X.Y.Z` (shields.io caches briefly).
- [ ] A scratch project can restore the new version:
      ```bash
      dotnet add package Enigma.LicenseManager --version X.Y.Z
      ```
- [ ] The GitHub release/tag `vX.Y.Z` is present and its notes match `RELEASENOTES.md`.
