using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using System;
using Enigma.Cryptography.PQC;

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
    private Func<byte[], AsymmetricKeyParameter, byte[]>? _signatureGenerator;
    private string? _signedWith;

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

    public LicenseBuilder SignWithRsa(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("The provided key must be a private key.", nameof(privateKey));
        
        _privateKey = privateKey;
        _signedWith = "RSA";
        _signatureGenerator = new PublicKeyServiceFactory().CreateRsaService().Sign;
        return this;
    }

    public LicenseBuilder SignWithMlDsa(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("The provided key must be a private key.", nameof(privateKey));
        
        _privateKey = privateKey;
        _signedWith = "ML-DSA";
        _signatureGenerator = new MLDsaServiceFactory().CreateDsa87Service().Sign;
        return this;
    }

    private byte[] GenerateSignature(byte[] data)
    {
        if (_signatureGenerator is null)
            throw new InvalidOperationException("Signature generator is missing. Call SignWithRsa or SignWithMlDsa first.");
        
        if (_privateKey is null)
            throw new InvalidOperationException("Private key is missing. Call SignWithRsa or SignWithMlDsa first.");

        return _signatureGenerator(data, _privateKey);
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
            Owner = _owner,
            SignedWith = _signedWith
        };

        var data = license.GetDataForSignature();
        license.Signature = GenerateSignature(data);

        return license;
    }
}