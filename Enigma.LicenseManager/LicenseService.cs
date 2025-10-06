using Enigma.Cryptography.PQC;
using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using System.Linq;
using System.Text.RegularExpressions;
using System;
using System.Collections.Generic;

namespace Enigma.LicenseManager;

public class LicenseService
{
    private List<(License, AsymmetricKeyParameter)> _licenses = [];

    public void AddLicense(License license, AsymmetricKeyParameter publicKey)
        => _licenses.Add((license, publicKey));
    
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

    private static bool IsProductIdMatch(string licenseProductId, string requestedProductId)
    {
        // If no wildcard, use exact match
        if (!licenseProductId.Contains('*'))
            return licenseProductId == requestedProductId;

        // Convert wildcard pattern to regex-like matching
        var pattern = licenseProductId.Replace("*", ".*");
        return Regex.IsMatch(requestedProductId, $"^{pattern}$");
    }
}