using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;

namespace Enigma.LicenseManager;

public class LicenseService(AsymmetricKeyParameter publicKey) : ILicenseService
{
    private readonly List<License> _licenses = [];
    
    public License[] LoadedLicenses => _licenses.ToArray();
    
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
    
    private static bool IsProductIdMatch(string licenseProductId, string requestedProductId)
    {
        // If no wildcard, use exact match
        if (!licenseProductId.Contains('*'))
            return licenseProductId == requestedProductId;

        // Convert wildcard pattern to regex-like matching
        var pattern = licenseProductId.Replace("*", ".*");
        return Regex.IsMatch(requestedProductId, $"^{pattern}$");
    }

    public void AddLicense(License license)
        => _licenses.Add(license);

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