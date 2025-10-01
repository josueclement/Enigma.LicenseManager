using System;
using System.Text;
using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using Enigma.Cryptography.Extensions;

namespace Enigma.LicenseManager;

public class LicenseBuilder
{
    private License? _license;
    private AsymmetricKeyParameter? _privateKey;
    
    public LicenseBuilder SetPrivateKey(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("Private key must be private.", nameof(privateKey));
        
        _privateKey = privateKey;
        return this;
    }

    public LicenseBuilder CreateLicense(LicenseType type, string id)
    {
        _license = new License(type, id);
        return this;
    }

    public LicenseBuilder SetCreationDate(DateTime creationDate)
    {
        if (_license is null)
            throw new InvalidOperationException("License not created. Call CreateLicense first.");
        
        _license.CreationDate = creationDate;
        return this;
    }

    public LicenseBuilder SetExpirationDate(DateTime expirationDate)
    {
        if (_license is null)
            throw new InvalidOperationException("License not created. Call CreateLicense first.");
        
        _license.ExpirationDate = expirationDate;
        return this; 
    }

    public LicenseBuilder SetRecipient(string recipient)
    {
        if (_license is null)
            throw new InvalidOperationException("License not created. Call CreateLicense first.");
        
        _license.Recipient = recipient;
        return this; 
    }

    private byte[] GenerateDataToSign(License license)
    {
        var sb = new StringBuilder();
        
        sb.Append("Type: ").Append(license.Type);
        sb.Append(", Id: ").Append(license.Id);

        if (license.CreationDate is not null)
            sb.Append(", CreationDate: ").Append(license.CreationDate.Value.ToString("O"));

        if (license.ExpirationDate is not null)
            sb.Append(", ExpirationDate: ").Append(license.ExpirationDate.Value.ToString("O"));

        if (license.Recipient is not null)
            sb.Append(", Recipient: ").Append(license.Recipient);

        return sb.ToString().GetUtf8Bytes();
    }

    private void GenerateMessage()
    {
        if (_license is null)
            throw new InvalidOperationException("License not created. Call CreateLicense first.");
        
        if (_privateKey is null)
            throw new InvalidOperationException("Private key not set. Call SetPrivateKey first.");
        
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var data = GenerateDataToSign(_license);
        _license.Message = rsa.Sign(data, _privateKey); 
    }

    public License Build()
    {
        if (_license is null)
            throw new InvalidOperationException("License not created. Call CreateLicense first.");
        
        GenerateMessage();
        _privateKey = null;
        
        return _license!;
    }
}