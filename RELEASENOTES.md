# v1.1.0 Release Notes

## Breaking Changes

- **Fix `GetDataForSignature()` copy-paste bug (#1):** The `Id` field was incorrectly serialized as `DeviceId` in the signature data. Licenses signed with v1.0.0 will fail verification in v1.1.0. Re-sign existing licenses after upgrading.
- **Strengthen device ID generation (#14):** `GenerateDeviceId()` now includes the MAC address in the device fingerprint. Device IDs generated with v1.0.0 will differ from v1.1.0. Update any device-bound licenses accordingly.

## Bug Fixes

- **Fix `HasValidLicense` wildcard pre-filter (#2):** `HasValidLicense` now correctly matches wildcard product IDs (e.g., `MyApp 1.*`) instead of requiring an exact string match on the pre-filter.
- **Fix regex metacharacter escaping (#3):** Product IDs containing regex metacharacters (e.g., parentheses, dots) are now properly escaped before wildcard matching.

## Improvements

- **Fix stream disposal (#4):** `SaveAsync` and `LoadAsync` now use `leaveOpen: true`, so the caller's stream is no longer disposed after save/load operations.
- **Thread safety for `LicenseService` (#5):** `AddLicense`, `RemoveLicense`, and `HasValidLicense` are now thread-safe via internal locking.
- **Cache factory/service instances (#7):** Signature signer and verifier delegates are now cached as static fields in `LicenseBuilder` and `LicenseService`, avoiding repeated factory allocations.
- **Add `RemoveLicense` method (#8):** `LicenseService.RemoveLicense(License)` removes a license by reference equality and returns whether it was found.
- **Add `CancellationToken` support (#9):** `SaveAsync` and `LoadAsync` accept an optional `CancellationToken`. On .NET 7+ this enables true async cancellation; on older TFMs it calls `ThrowIfCancellationRequested()` before the operation.

## Test & Documentation

- Extracted key-loading into a shared `KeyFixture` using `IClassFixture<KeyFixture>`, eliminating duplicated file I/O across all tests.
- Converted non-async tests from `async Task` to `void`, removing unnecessary `await Task.CompletedTask`.
- Added `HasValidLicense` tests: exact match, wildcard match, no match, device ID, wrong device ID, regex metacharacter handling.
- Added `LicenseUtils` tests: device ID generation consistency and utility method safety.
- Updated README target framework list to reflect all supported TFMs.
- Added sample code to `ConsoleApp1` demonstrating key generation, license creation, persistence, and validation.
