using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Cryptography.Extensions;
using Enigma.Cryptography.PublicKey;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;

namespace Enigma.LicenseManager;

public class License()
{
    public LicenseType Type { get; set; }
    public string? Id { get; set; }
    public DateTime? CreationDate { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public string? Recipient { get; set; }
    public byte[]? Signature { get; set; }

    public void SignLicense(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("The provided key is not a private key.", nameof(privateKey));
        
        var data = GetDataForSignature();
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        Signature = rsa.Sign(data, privateKey);
    }

    private string? GetId() => Type switch
    {
        LicenseType.App => IdGenerator.GenerateAppId(),
        LicenseType.Machine => IdGenerator.GenerateMachineId(),
        LicenseType.Unlimited => null,
        _ => throw new InvalidOperationException("Invalid license type.")
    };

    public bool IsValid(AsymmetricKeyParameter publicKey)
    {
        if (Signature is null)
            throw new InvalidOperationException("Signature is missing.");
        
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var data = GetDataForSignature();

        if (!rsa.Verify(data, Signature, publicKey))
            return false;

        if (ExpirationDate is not null && DateTime.UtcNow > ExpirationDate)
            return false;

        if (Type == LicenseType.Unlimited)
            return true;
        
        var id = GetId();

        if (Id is not null && id is not null && Id == id)
            return true;

        return false;
    }

    public async Task SaveAsync(string filePath)
    {
        var json = JsonConvert.SerializeObject(this, Formatting.Indented);
        using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write);
        using var sw = new StreamWriter(fs);
        await sw.WriteAsync(json);
    }

    public static async Task<License?> LoadAsync(string filePath)
    {
        if (!File.Exists(filePath))
            return null;

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        using var sr = new StreamReader(fs);
        var json = await sr.ReadToEndAsync();
        return JsonConvert.DeserializeObject<License>(json);
    }

    private byte[] GetDataForSignature()
    {
        var sb = new StringBuilder();
        
        sb.Append("Type: ").Append(Type);
        
        if (Id is not null)
            sb.Append(", Id: ").Append(Id);

        if (CreationDate is not null)
            sb.Append(", CreationDate: ").Append(CreationDate.Value.ToString("O"));

        if (ExpirationDate is not null)
            sb.Append(", ExpirationDate: ").Append(ExpirationDate.Value.ToString("O"));

        if (Recipient is not null)
            sb.Append(", Recipient: ").Append(Recipient);

        return sb.ToString().GetUtf8Bytes(); 
    }
}