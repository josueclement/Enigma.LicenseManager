# Enigma.LicenseManager

[![NuGet](https://img.shields.io/nuget/v/Enigma.LicenseManager.svg)](https://www.nuget.org/packages/Enigma.LicenseManager)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)

**Enigma.LicenseManager** is a comprehensive .NET library designed for secure license management in applications. It provides robust cryptographic protection using both traditional RSA and modern ML-DSA (FIPS 204) digital signature algorithms, ensuring your software licensing is both secure and future-proof.

> **What's new in 1.2.0** — a production-readiness release: `Enigma.Cryptography` upgraded to 5.0.0, Central Package Management adopted, a non-Avalonia dependency refresh, the test suite migrated to xUnit v3, and build configuration consolidated. No public API or behavioural change — see the [release notes](RELEASENOTES.md).

## Features

- **Dual Cryptographic Support**: Choose between RSA and ML-DSA (post-quantum) signatures
- **Flexible License Management**: Create, validate, and manage licenses with customizable properties
- **Device Binding**: Lock licenses to specific machines using hardware-derived device identifiers
- **Cross-Platform Compatibility**: Supports .NET Standard 2.0 and .NET 8.0+
- **JSON Serialization**: Easy license storage and distribution in JSON format
- **Product Version Matching**: Support for wildcard patterns in product IDs (e.g., `MyApp 1.*`)
- **Expiration Handling**: Built-in support for time-based license expiration
- **Thread-Safe Service**: `LicenseService` is fully thread-safe for concurrent access

## Installation

```bash
dotnet add package Enigma.LicenseManager
```

## License Creation

### Create an RSA-Signed License

Generate a license with RSA digital signature for traditional cryptographic security:

```csharp
await using var privateKeyFile = new FileStream("<YourKeyFile.pem>", FileMode.Open, FileAccess.Read);
var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "<KeyPassword>");

var license = new LicenseBuilder()
    .SetProductId("MyApp 1.*")
    .SetExpirationDate(DateTime.UtcNow.AddDays(365))
    .SetOwner("Acme Corp")
    .SignWithRsa(privateKey)
    .Build();
```

### Create an ML-DSA-Signed License

Generate a license with ML-DSA (post-quantum) signature for enhanced future security:

```csharp
await using var privateKeyFile = new FileStream("<YourKeyFile.pem>", FileMode.Open, FileAccess.Read);
var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "<KeyPassword>");

var license = new LicenseBuilder()
    .SetProductId("MyApp")
    .SignWithMlDsa(privateKey)
    .Build();
```

### Create a Device-Bound License

Bind a license to a specific machine so it cannot be used elsewhere:

```csharp
// On the target machine, generate the device ID
var deviceId = LicenseUtils.GenerateDeviceId();

// When creating the license, bind it to that device
var license = new LicenseBuilder()
    .SetProductId("MyApp 1.*")
    .SetDeviceId(deviceId)
    .SetExpirationDate(DateTime.UtcNow.AddDays(365))
    .SignWithRsa(privateKey)
    .Build();
```

> `Id` defaults to a ULID and `CreationDate` defaults to `DateTime.UtcNow` when not explicitly set.

## License Persistence

### Save License to JSON

Export your generated license to a JSON file for distribution:

```csharp
await using var fs = new FileStream("<DestinationPath>", FileMode.Create, FileAccess.Write);
await license.SaveAsync(fs);
```

### Load License from JSON

Import a license from a JSON file for validation:

```csharp
await using var fs = new FileStream("<LicenseFilePath>", FileMode.Open, FileAccess.Read);
var license = await License.LoadAsync(fs);
```

Both `SaveAsync` and `LoadAsync` accept an optional `CancellationToken` parameter.

## License Validation

### Verify a Single License

Validate a license against its public key. `IsValid` returns a `(bool, string?)` tuple with an error message on failure:

```csharp
await using var publicKeyFile = new FileStream("<YourKeyFile.pem>", FileMode.Open, FileAccess.Read);
var publicKey = PemUtils.LoadKey(publicKeyFile);

var service = new LicenseService();
var (isValid, errorMessage) = service.IsValid(license, publicKey, "MyApp 1.0");

if (!isValid)
    Console.WriteLine($"License rejected: {errorMessage}");
```

For device-bound licenses, pass the device ID:

```csharp
var deviceId = LicenseUtils.GenerateDeviceId();
var (isValid, errorMessage) = service.IsValid(license, publicKey, "MyApp 1.0", deviceId);
```

### Using LicenseService

`LicenseService` maintains an in-memory, thread-safe collection of licenses. Register licenses once, then check validity by product ID throughout your application:

```csharp
var service = new LicenseService();

// Register licenses with their public keys
service.AddLicense(license, publicKey);

// Check if any registered license is valid for a product
if (service.HasValidLicense("MyApp 1.0"))
{
    // Feature is licensed
}

// For device-bound licenses
var deviceId = LicenseUtils.GenerateDeviceId();
if (service.HasValidLicense("MyApp 1.0", deviceId))
{
    // Feature is licensed for this device
}

// Remove a license when no longer needed
service.RemoveLicense(license);
```

## Tooling

### Desktop app

**Enigma License Manager** is an [Avalonia](https://avaloniaui.net/) desktop application (`src/Enigma.LicenseManager.Desktop/`) for working with keys and licenses through a GUI, without writing code. It provides three pages:

- **Generate Keys** — generate an RSA (2048/3072/4096/8192) or ML-DSA (level 87) key pair and save the public / private keys to PEM, optionally encrypting the private key with a password.
- **Generate Licenses** — build and sign a license (product ID, owner, optional device binding and expiration) with an RSA or ML-DSA private key, and save it as JSON. Reusable **profiles** save/load the form fields to a `.json` file (the signing key password is never stored).
- **Validate Licenses** — validate a license file against a public key, optionally constraining the product ID and device ID.

A runtime light / dark theme toggle is persisted per user. Run it with:

```bash
dotnet run --project src/Enigma.LicenseManager.Desktop
```

The GUI's key/license operations are backed by the shared **`Enigma.LicenseManager.Tools`** library (`src/Enigma.LicenseManager.Tools/`), which wraps the core library's signing/verification with key generation, PEM I/O, and RSA-vs-ML-DSA dispatch behind DI-registered services (`AddLicenseTools()`).

### Command-line tool

**`enigma-license`** (`src/Enigma.LicenseManager.Cli/`) runs the same key and license operations as the desktop app from a terminal or CI pipeline. Run it with:

```bash
dotnet run --project src/Enigma.LicenseManager.Cli -- <command>
```

The examples below use `enigma-license` as shorthand for `dotnet run --project src/Enigma.LicenseManager.Cli --`.

Full round-trip — generate a key pair, sign a license, validate it:

```bash
mkdir -p keys

# 1. Generate an RSA key pair (private key encrypted with a password)
enigma-license keygen --algorithm rsa --rsa-size 3072 \
  --public keys/public.pem --private keys/private.pem --password s3cret

# 2. Sign a license with the private key
enigma-license license generate --product-id "MyApp 1.*" --owner "Acme Corp" \
  --expires 2027-01-31 --algorithm rsa --key keys/private.pem --password s3cret \
  --out app.license.json

# 3. Validate it with the public key
enigma-license license validate --license app.license.json \
  --public-key keys/public.pem --product-id "MyApp 1.2.3"
# License is VALID.
```

`keygen` writes to the paths you give it and does not create parent directories, so create the output directory first (`mkdir -p keys`) or use paths in the current directory.

#### Generate keys

```bash
mkdir -p keys

# RSA key pair (--rsa-size is one of 2048/3072/4096/8192, default 3072; RSA only)
enigma-license keygen --algorithm rsa --rsa-size 4096 \
  --public keys/public.pem --private keys/private.pem

# ML-DSA key pair (post-quantum, fixed to level 87)
enigma-license keygen --algorithm ml-dsa \
  --public keys/public.pem --private keys/private.pem

# Encrypt the private key with a password
enigma-license keygen --algorithm rsa \
  --public keys/public.pem --private keys/private.pem --password s3cret
```

#### Generate a license

```bash
enigma-license license generate \
  --product-id "MyApp 1.*" \
  --owner "Acme Corp" \
  --device-id "abc123" \
  --expires 2027-01-31 \
  --algorithm rsa --key keys/private.pem --password s3cret \
  --out app.license.json
```

`--owner`, `--device-id` and `--expires` are optional; omitting `--expires` means the license never expires. `--algorithm` must match the private key. Drop `--password` for an unencrypted key.

#### Validate a license

```bash
# Valid — product and device match → exit 0
enigma-license license validate \
  --license app.license.json --public-key keys/public.pem \
  --product-id "MyApp 1.2.3" --device-id "abc123"
# License is VALID.

# Invalid — product id mismatch → exit 1
enigma-license license validate \
  --license app.license.json --public-key keys/public.pem \
  --product-id "OtherApp 1.0"
# License is INVALID: Product id mismatch. (License productId: MyApp 1.*, requested productId: OtherApp 1.0)
```

`--product-id` and `--device-id` are optional; omit `--product-id` to validate against the license's own product id. A wrong public key or a device-id mismatch is also reported as invalid (exit 1).

#### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success / license valid |
| `1` | License invalid |
| `2` | Operation error (bad password, missing file — message on stderr) |

Exit codes make the tool scriptable in CI: `enigma-license license validate ... && ./deploy.sh`.

Every command supports `--help`; `enigma-license --version` prints the tool version.

## Project Structure

| Path | Description |
|------|-------------|
| `src/Enigma.LicenseManager/` | Core library |
| `src/Enigma.LicenseManager.Tools/` | Shared key / license operations (used by the desktop app) |
| `src/Enigma.LicenseManager.Desktop/` | Avalonia desktop application |
| `src/Enigma.LicenseManager.Cli/` | Command-line tool (`enigma-license`) |
| `src/UnitTests/` | Unit tests |
