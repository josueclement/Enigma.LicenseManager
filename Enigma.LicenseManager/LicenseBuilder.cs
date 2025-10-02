using System;
using System.Text;
using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using Enigma.Cryptography.Extensions;

namespace Enigma.LicenseManager;

public class LicenseBuilder
{
    private LicenseType _licenseType;
    private string? _licenseId;
    private DateTime? _licenseCreationDate;
    private DateTime? _licenseExpirationDate;
    private string? _licenseRecipient;
    
    private AsymmetricKeyParameter? _privateKey;
    
    public LicenseBuilder SetPrivateKey(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("Private key must be private.", nameof(privateKey));
        
        _privateKey = privateKey;
        return this;
    }

    public LicenseBuilder SetType(LicenseType type)
    {
        _licenseType = type;
        return this;
    }
    
    public LicenseBuilder SetId(string id)
    {
        _licenseId = id;
        return this;
    }

    public LicenseBuilder SetCreationDate(DateTime creationDate)
    {
        _licenseCreationDate = creationDate;
        return this;
    }

    public LicenseBuilder SetExpirationDate(DateTime expirationDate)
    {
        _licenseExpirationDate = expirationDate;
        return this; 
    }

    public LicenseBuilder SetRecipient(string recipient)
    {
        _licenseRecipient = recipient;
        return this; 
    }

    public License Build()
    {
        if (_privateKey is null)
            throw new InvalidOperationException("Private key is missing. Call SetPrivateKey() first.");

        if (_licenseType != LicenseType.Unlimited && _licenseId is null)
            throw new InvalidOperationException($"License id is missing for license type {_licenseType}.");
        
        var license = new License
        {
            Type = _licenseType,
            Id = _licenseId,
            CreationDate = _licenseCreationDate,
            ExpirationDate = _licenseExpirationDate,
            Recipient = _licenseRecipient
        };
        
        license.SignLicense(_privateKey);

        return license;
    }
}