using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using System;

namespace Enigma.LicenseManager;

public class LicenseBuilder
{
    private string? _id;
    private DateTime? _creationDate;
    private string? _deviceId;
    private string? _productId;
    private DateTime? _expirationDate;
    private string? _owner;
    
    private AsymmetricKeyParameter? _privateKey;
    
    public LicenseBuilder SetPrivateKey(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("Private key must be private.", nameof(privateKey));
        
        _privateKey = privateKey;
        return this;
    }
    
    public LicenseBuilder SetId(string id)
    {
        _id = id;
        return this;
    }

    public LicenseBuilder SetCreationDate(DateTime creationDate)
    {
        _creationDate = creationDate;
        return this;
    }

    public LicenseBuilder SetProductId(string productId)
    {
        _productId = productId;
        return this;
    }

    public LicenseBuilder SetDeviceId(string deviceId)
    {
        _deviceId = deviceId;
        return this;
    }

    public LicenseBuilder SetExpirationDate(DateTime expirationDate)
    {
        _expirationDate = expirationDate;
        return this; 
    }

    public LicenseBuilder SetOwner(string owner)
    {
        _owner = owner;
        return this; 
    }

    private byte[] GenerateSignature(byte[] data)
    {
        if (_privateKey is null)
            throw new InvalidOperationException("Private key is missing. Call SetPrivateKey first.");
        
        var rsa = new PublicKeyServiceFactory().CreateRsaService(); 
        return rsa.Sign(data, _privateKey);
    }

    public License Build()
    {
        if (_productId is null)
            throw new InvalidOperationException("Product id is missing. Call SetProductId first.");
        
        var license = new License
        {
            Id = _id ?? Ulid.NewUlid().ToString(),
            CreationDate = _creationDate ?? DateTime.UtcNow,
            ProductId = _productId,
            DeviceId = _deviceId,
            ExpirationDate = _expirationDate,
            Owner = _owner
        };

        var data = license.GetDataForSignature();
        license.Signature = GenerateSignature(data);

        return license;
    }
}