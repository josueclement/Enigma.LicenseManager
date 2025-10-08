using Enigma.Cryptography.PQC;
using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System;

namespace Enigma.LicenseManager;

/// <summary>
/// Service for managing and validating software licenses with cryptographic signature verification.
/// </summary>
public class LicenseService
{
    private readonly List<(License, AsymmetricKeyParameter)> _licenses = [];

    /// <summary>
    /// Adds a license with its corresponding public key to the service for validation.
    /// </summary>
    /// <param name="license">The license to add.</param>
    /// <param name="publicKey">The public key used to verify the license signature.</param>
    public void AddLicense(License license, AsymmetricKeyParameter publicKey)
        => _licenses.Add((license, publicKey));
    
    /// <summary>
    /// Checks if there is a valid license for the specified product and device.
    /// </summary>
    /// <param name="productId">The product identifier to check for.</param>
    /// <param name="deviceId">The optional device identifier to check for. If null, device-specific validation is skipped.</param>
    /// <returns>True if a valid license is found; otherwise, false.</returns>
    public bool HasValidLicense(string productId, string? deviceId = null)
    {
        var licenses = _licenses.Where(x => x.Item1.ProductId == productId);
        foreach (var license in licenses)
        {
            var (isValid, _) = IsValid(license.Item1, license.Item2, productId, deviceId);
            if (isValid)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Validates a license against the specified criteria and verifies its cryptographic signature.
    /// </summary>
    /// <param name="license">The license to validate.</param>
    /// <param name="publicKey">The public key to verify the license signature.</param>
    /// <param name="productId">The product identifier to validate against.</param>
    /// <param name="deviceId">The optional device identifier to validate against. If null, device-specific validation is skipped.</param>
    /// <returns>A tuple containing a boolean indicating if the license is valid and an optional error message.</returns>
    public (bool isValid, string? message) IsValid(
        License license,
        AsymmetricKeyParameter publicKey,
        string productId,
        string? deviceId = null)
    {
        if (license.Signature is null)
            return (false, "Invalid license: signature is missing.");

        if (license.ProductId is null)
            return (false, "Invalid license: productId is missing.");

        if (license.SignedWith is null)
            return (false, "Invalid license: missing signature infos.");

        var signatureVerifier = GetSignatureVerifier(license.SignedWith);
        var data = license.GetDataForSignature();

        if (!signatureVerifier(data, license.Signature, publicKey))
            return (false, "Invalid license: signature is invalid.");

        if (license.ExpirationDate is not null && DateTime.UtcNow > license.ExpirationDate)
            return (false, $"The license has expired. Expiration date: {license.ExpirationDate:O}");

        if (!IsProductIdMatch(license.ProductId, productId))
            return (false, $"Product id mismatch. (License productId: {license.ProductId}, requested productId: {productId})");

        if (license.DeviceId is not null && license.DeviceId != deviceId)
            return (false, $"Device id mismatch. (License deviceId: {license.DeviceId}, requested deviceId: {deviceId})");

        return (true, null);
    }

    /// <summary>
    /// Gets the appropriate signature verification function based on the signature algorithm.
    /// </summary>
    /// <param name="signedWith">The name of the signature algorithm (e.g., "RSA", "ML-DSA").</param>
    /// <returns>A function that verifies signatures using the specified algorithm.</returns>
    /// <exception cref="InvalidOperationException">Thrown when an unsupported signature type is specified.</exception>
    private Func<byte[], byte[], AsymmetricKeyParameter, bool> GetSignatureVerifier(string signedWith)
    {
        switch (signedWith)
        {
            case "RSA":
                return new PublicKeyServiceFactory().CreateRsaService().Verify;
            case "ML-DSA":
                return new MLDsaServiceFactory().CreateDsa87Service().Verify;
            default:
                throw new InvalidOperationException("Invalid signature type. Supported types: RSA, ML-DSA.");
        }
    }

    /// <summary>
    /// Checks if a requested product ID matches the license product ID, supporting wildcard patterns.
    /// </summary>
    /// <param name="licenseProductId">The product ID from the license, which may contain wildcard patterns (*).</param>
    /// <param name="requestedProductId">The product ID to validate.</param>
    /// <returns>True if the product IDs match; otherwise, false.</returns>
    private static bool IsProductIdMatch(string licenseProductId, string requestedProductId)
    {
        // If no wildcard, use the exact match
        if (!licenseProductId.Contains('*'))
            return licenseProductId == requestedProductId;

        // Convert wildcard pattern to regex-like matching
        var pattern = licenseProductId.Replace("*", ".*");
        return Regex.IsMatch(requestedProductId, $"^{pattern}$");
    }
}