# Enigma.LicenseManager

**Enigma.LicenseManager** is a comprehensive .NET library designed for secure license management in applications. It provides robust cryptographic protection using both traditional RSA and modern ML-DSA (FIPS 204) digital signature algorithms, ensuring your software licensing is both secure and future-proof.

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

## Project Structure

| Path | Description |
|------|-------------|
| `src/Enigma.LicenseManager/` | Core library |
| `src/UnitTests/` | Unit tests |
| `src/ConsoleApp1/` | Example console application |
