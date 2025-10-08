# Enigma.LicenseManager

**Enigma.LicenseManager** is a comprehensive .NET library designed for secure license management in applications. It provides robust cryptographic protection using both traditional RSA and modern ML-DSA (FIPS 204) digital signature algorithms, ensuring your software licensing is both secure and future-proof.

## ✨ Features

- **Dual Cryptographic Support**: Choose between RSA and ML-DSA (post-quantum) signatures
- **Flexible License Management**: Create, validate, and manage licenses with customizable properties
- **Cross-Platform Compatibility**: Supports .NET Standard 2.0, 2.1, and .NET 9.0
- **JSON Serialization**: Easy license storage and distribution in JSON format
- **Product Version Matching**: Support for wildcard patterns in product IDs
- **Expiration Handling**: Built-in support for time-based license expiration

## 📝 License Creation

### Create an RSA-Signed License

Generate a license with RSA digital signature for traditional cryptographic security:

```csharp
await using var privateKeyFile = new FileStream("<YourKeyFile.pem>", FileMode.Open, FileAccess.Read);
var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "<KeyPassword>");

var license = new LicenseBuilder()
    .SetProductId("MyApp 1.*")
    .SetExpirationDate(DateTime.UtcNow.AddDays(1))
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

## 💾 License Persistence

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

## ✅ License Validation

### Verify License Authenticity

Validate a license against its public key to ensure authenticity and integrity:

```csharp
await using var publicKeyFile = new FileStream("<YourKeyFile.pem>", FileMode.Open, FileAccess.Read);
var publicKey = PemUtils.LoadKey(publicKeyFile);

var service = new LicenseService();
var (isValid, _) = service.IsValid(license, publicKey, "MyApp");
```