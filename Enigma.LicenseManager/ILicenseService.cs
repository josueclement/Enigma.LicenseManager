using Org.BouncyCastle.Crypto;

namespace Enigma.LicenseManager;

public interface ILicenseService
{
    License[] LoadedLicenses { get; }
    
    (bool isValid, string? message) IsValid(License license, string productId, string? deviceId = null);
    void AddLicense(License license);
    bool HasValidLicense(string productId, string? deviceId = null);
}