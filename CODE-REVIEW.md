# Code Review: Enigma.LicenseManager

**Date:** 2026-03-13
**Scope:** Full solution review
**Version reviewed:** v1.0.0 (commit `be390aa`)

---

## Critical

### 1. Copy-paste bug in `GetDataForSignature()` — `Id` is never signed

**File:** `Enigma.LicenseManager/License.cs:66-67`

```csharp
if (Id is not null)
    sb.Append(", Id: ").Append(DeviceId);  // <-- should be Id, not DeviceId
```

The guard checks `Id`, but appends `DeviceId`. This has two consequences:

- The license `Id` is **never** included in the signature data. An attacker can change the `Id` field without invalidating the signature.
- When both `Id` and `DeviceId` are set, `DeviceId` is included **twice** in the signature data (once on line 67 under the `Id` label, once on line 76 under the `DeviceId` label). This doesn't break verification but makes the signature semantically wrong.

**Fix:**

```csharp
if (Id is not null)
    sb.Append(", Id: ").Append(Id);
```

> **Note:** Fixing this is a breaking change — all existing signed licenses become invalid because the signature data changes. A migration strategy (re-signing existing licenses or supporting both formats during a transition period) should be considered.

---

## Bugs

### 2. `HasValidLicense` does not support wildcard product IDs

**File:** `Enigma.LicenseManager/LicenseService.cs:34`

```csharp
var licenses = _licenses.Where(x => x.Item1.ProductId == productId);
```

This pre-filters using exact string equality (`==`) **before** calling `IsValid`, which supports wildcard matching via `IsProductIdMatch`. A wildcard license like `"MyApp 1.*"` will never be found when querying for `"MyApp 1.2.3"` because `"MyApp 1.*" != "MyApp 1.2.3"`.

**Fix:** Remove the pre-filter and let `IsValid` handle matching, or replace the exact match with `IsProductIdMatch`:

```csharp
var licenses = _licenses.Where(x =>
    x.Item1.ProductId != null && IsProductIdMatch(x.Item1.ProductId, productId));
```

### 3. `IsProductIdMatch` doesn't escape regex metacharacters

**File:** `Enigma.LicenseManager/LicenseService.cs:113`

```csharp
var pattern = licenseProductId.Replace("*", ".*");
return Regex.IsMatch(requestedProductId, $"^{pattern}$");
```

Only `*` is converted to `.*`, but other regex metacharacters (`.`, `+`, `(`, `)`, `[`, etc.) in the product ID are left unescaped. A license for `"MyApp 1.1.*"` would match `"MyApp 1X1Y7"` because the dots are treated as regex "any character" wildcards.

**Fix:** Escape the product ID before converting wildcards:

```csharp
var pattern = "^" + Regex.Escape(licenseProductId).Replace("\\*", ".*") + "$";
return Regex.IsMatch(requestedProductId, pattern);
```

---

## Design Issues

### 4. `SaveAsync` / `LoadAsync` dispose the caller's stream

**File:** `Enigma.LicenseManager/License.cs:98,109`

```csharp
using var sw = new StreamWriter(output, Encoding.UTF8);   // disposes 'output'
using var sr = new StreamReader(input, Encoding.UTF8);     // disposes 'input'
```

Wrapping the caller's stream in a `using StreamWriter`/`StreamReader` disposes the underlying stream when the method returns. This is surprising — callers typically expect to own stream lifetime. The existing test (`SaveLoadRsaLicense`) works only because `MemoryStream.ToArray()` is called before `LoadAsync` disposes the stream, and `MemoryStream` remains readable after disposal.

**Fix:** Use the `leaveOpen` parameter:

```csharp
using var sw = new StreamWriter(output, Encoding.UTF8, bufferSize: 1024, leaveOpen: true);
using var sr = new StreamReader(input, Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
    bufferSize: 1024, leaveOpen: true);
```

### 5. `LicenseService` is not thread-safe

**File:** `Enigma.LicenseManager/LicenseService.cs:16,24,34`

The `_licenses` list is a plain `List<T>`. `AddLicense` can be called concurrently with `HasValidLicense` iterating over the same list, which can throw `InvalidOperationException` ("Collection was modified during enumeration") or cause data corruption.

**Options:**
- Use `ConcurrentBag<T>` or a lock around mutations and reads.
- Document that `LicenseService` is not thread-safe and callers must synchronize.

### 6. All `License` properties have public setters

**File:** `Enigma.LicenseManager/License.cs:18-56`

Post-construction mutation is possible (and demonstrated in tests at `Tests.cs:301,323`). While signature verification catches tampering, `init`-only setters would prevent accidental mutation and make the tamper-resistance intent clearer. The `LicenseBuilder` would still work since it uses object initializer syntax.

### 7. Factory/service instances re-created on every verification call

**File:** `Enigma.LicenseManager/LicenseService.cs:95-96`

```csharp
"RSA" => new PublicKeyServiceFactory().CreateRsaService().Verify,
"ML-DSA" => new MLDsaServiceFactory().CreateDsa87Service().Verify,
```

`GetSignatureVerifier` creates new factory and service instances on every call to `IsValid`. These could be cached as static fields since they carry no mutable state.

The same pattern appears in `LicenseBuilder.cs:102,119`.

### 8. No `RemoveLicense` method

**File:** `Enigma.LicenseManager/LicenseService.cs`

Licenses can be added via `AddLicense` but there is no way to remove them. This prevents cleanup of expired or revoked licenses.

### 9. No `CancellationToken` support in async methods

**File:** `Enigma.LicenseManager/License.cs:95,107`

`SaveAsync` and `LoadAsync` accept no `CancellationToken`. For network-backed streams or large files, callers cannot cancel the operation.

---

## Test Issues

### 10. Multiple `async Task` tests contain no async operations

**File:** `UnitTests/Tests.cs`

Several tests are marked `async Task` but only use `await` for loading key files at the top. Two tests have no async work at all:

- `TryGenerateMlDsaLicense_WithMissingMembers` (line 196) — uses `await Task.CompletedTask` as a workaround.
- `TryGenerateRsaLicense_WithMissingMembers` (line 182) — marked `async` but has no `await` (will produce compiler warning CS1998).

These should either be changed to synchronous `void` test methods or should genuinely test async paths.

### 11. No test for `HasValidLicense`

**File:** `UnitTests/Tests.cs`

`HasValidLicense` is the primary public API consumers would use, but it has zero test coverage. This means Bug #2 (wildcard mismatch) went undetected.

### 12. No test for `LicenseUtils` methods

**File:** `UnitTests/Tests.cs`

`LicenseUtils.GenerateDeviceId()`, `GetExecutingAppName()`, and `GetExecutingAppVersion()` have no test coverage.

### 13. Repetitive key-loading boilerplate

**File:** `UnitTests/Tests.cs`

Every test repeats the same 4 lines for loading keys. A shared test fixture (`IClassFixture<T>` in xUnit) or helper method would reduce duplication and make tests easier to maintain.

---

## Minor / Suggestions

### 14. Weak device ID generation

**File:** `Enigma.LicenseManager/LicenseUtils.cs:16`

```csharp
new DeviceIdBuilder().AddMachineName().AddOsVersion().ToString();
```

Using only machine name + OS version is weak:
- OS updates (even minor patches) can invalidate existing device-bound licenses.
- Multiple VMs or containers with the same name and OS version produce identical device IDs.

Consider adding more stable hardware identifiers (e.g., `AddMacAddress()`, `AddSystemDriveSerialNumber()`).

### 15. README lists incomplete target frameworks

**File:** `README.md:9`

> Supports .NET Standard 2.0, 2.1, and .NET 9.0

The csproj targets `netstandard2.0;netstandard2.1;net6.0;net7.0;net8.0;net9.0;net472`. The README should list all supported TFMs, or use a generic statement like "Supports .NET Standard 2.0+, .NET 6.0+, and .NET Framework 4.7.2".

### 16. Empty sample application

**File:** `ConsoleApp1/Program.cs`

```csharp
static async Task Main()
{
    await Task.CompletedTask;
}
```

The sample application contains no example code. It should either demonstrate basic usage (create, sign, validate a license) or be removed from the solution.

### 17. Consider `System.Text.Json` for modern TFMs

**File:** `Enigma.LicenseManager/Enigma.LicenseManager.csproj:34`

Newtonsoft.Json is fine for broad compatibility (especially `netstandard2.0` and `net472`), but for `net6.0+` TFMs, `System.Text.Json` is built-in and would eliminate an external dependency. This could be done via conditional compilation (`#if NET6_0_OR_GREATER`) if desired. Low priority — Newtonsoft.Json works correctly as-is.

---

## Summary

| Severity | Count | Items |
|----------|-------|-------|
| Critical | 1 | #1 (Id not signed) |
| Bug | 2 | #2 (wildcard filter), #3 (regex escape) |
| Design | 6 | #4-#9 |
| Test | 4 | #10-#13 |
| Minor | 4 | #14-#17 |

The most urgent fix is the copy-paste bug in `GetDataForSignature()` (#1), which is a security issue — the license `Id` can be tampered with without invalidating the signature. The `HasValidLicense` bug (#2) means the primary consumer-facing API is broken for wildcard licenses. The regex escape issue (#3) allows unintended product ID matches.
