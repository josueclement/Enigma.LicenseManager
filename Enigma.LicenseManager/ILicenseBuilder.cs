using System;

namespace Enigma.LicenseManager;

public interface ILicenseBuilder
{
    ILicenseBuilder SetId(string id);
    ILicenseBuilder SetCreationDate(DateTime creationDate);
    ILicenseBuilder SetDeviceId(string deviceId);
    ILicenseBuilder SetProductId(string productId);
    ILicenseBuilder SetExpirationDate(DateTime expirationDate);
    ILicenseBuilder SetOwner(string owner);
    License Build();
}