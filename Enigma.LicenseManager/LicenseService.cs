using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System;

namespace Enigma.LicenseManager;

/// <summary>
/// Service for validating and managing licenses using RSA cryptography.
/// Verifies license signatures, expiration dates, and product/device bindings.
/// </summary>
/// <param name="publicKey">The RSA public key used to verify license signatures.</param>
public class LicenseService(AsymmetricKeyParameter publicKey)
{
    /// <summary>
    /// Internal collection of loaded licenses.
    /// </summary>
    private readonly List<License> _licenses = [];

    /// <summary>
    /// Gets an array of all currently loaded licenses in the service.
    /// </summary>
    public License[] LoadedLicenses => _licenses.ToArray();

    /// <summary>
    /// Validates a license using RSA signature verification and checks all license constraints.
    /// Verifies signature authenticity, expiration date, product ID match, and device binding.
    /// </summary>
    /// <param name="license">The license to validate.</param>
    /// <param name="productId">The product identifier to validate against.</param>
    /// <param name="deviceId">Optional device identifier to validate against (for device-bound licenses).</param>
    /// <returns>A tuple containing validation result (true/false) and an optional error message.</returns>
    public (bool isValid, string? message) IsValid(License license, string productId, string? deviceId = null)
    {
        if (license.Signature is null)
            return (false, "Invalid license: signature is missing.");

        if (license.ProductId is null)
            return (false, "Invalid license: productId is missing.");

        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var data = license.GetDataForSignature();

        if (!rsa.Verify(data, license.Signature, publicKey))
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
    /// Checks if the license product ID matches the requested product ID.
    /// Supports wildcard matching using the '*' character in the license product ID.
    /// </summary>
    /// <param name="licenseProductId">The product ID from the license (may contain wildcards).</param>
    /// <param name="requestedProductId">The product ID to validate.</param>
    /// <returns>True if the product IDs match; otherwise, false.</returns>
    private static bool IsProductIdMatch(string licenseProductId, string requestedProductId)
    {
        // If no wildcard, use exact match
        if (!licenseProductId.Contains('*'))
            return licenseProductId == requestedProductId;

        // Convert wildcard pattern to regex-like matching
        var pattern = licenseProductId.Replace("*", ".*");
        return Regex.IsMatch(requestedProductId, $"^{pattern}$");
    }

    /// <summary>
    /// Adds a license to the service's internal collection of loaded licenses.
    /// </summary>
    /// <param name="license">The license to add.</param>
    public void AddLicense(License license)
        => _licenses.Add(license);

    /// <summary>
    /// Checks if any of the loaded licenses is valid for the specified product and device.
    /// </summary>
    /// <param name="productId">The product identifier to check for.</param>
    /// <param name="deviceId">Optional device identifier to check for (for device-bound licenses).</param>
    /// <returns>True if at least one valid license is found; otherwise, false.</returns>
    public bool HasValidLicense(string productId, string? deviceId = null)
    {
        var licenses = _licenses.Where(l => l.ProductId == productId);
        foreach (var license in licenses)
        {
            var (isValid, _) = IsValid(license, productId, deviceId);
            if (isValid)
                return true;
        }

        return false;
    }
}