using Enigma.Cryptography.Extensions;
using Newtonsoft.Json;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System;

namespace Enigma.LicenseManager;

public class License
{
    public string? Id { get; set; }

    public DateTime? CreationDate { get; set; }

    public string? ProductId { get; set; }

    public string? DeviceId { get; set; }

    public DateTime? ExpirationDate { get; set; }

    public string? Owner { get; set; }

    public byte[]? Signature { get; set; }
    
    public string? SignedWith { get; set; }

    public byte[] GetDataForSignature()
    {
        var sb = new StringBuilder();

        if (Id is not null)
            sb.Append(", Id: ").Append(DeviceId);

        if (CreationDate is not null)
            sb.Append(", CreationDate: ").Append(CreationDate.Value.ToString("O"));

        if (ProductId is not null)
            sb.Append(", ProductId: ").Append(ProductId);

        if (DeviceId is not null)
            sb.Append(", DeviceId: ").Append(DeviceId);

        if (ExpirationDate is not null)
            sb.Append(", ExpirationDate: ").Append(ExpirationDate.Value.ToString("O"));

        if (Owner is not null)
            sb.Append(", Owner: ").Append(Owner);
        
        if (SignedWith is not null)
            sb.Append(", SignedWith: ").Append(SignedWith);

        return sb.ToString().GetUtf8Bytes(); 
    }

    public async Task SaveAsync(Stream output)
    {
        var json = JsonConvert.SerializeObject(this, Formatting.Indented);
        using var sw = new StreamWriter(output, Encoding.UTF8);
        await sw.WriteAsync(json);
    }

    public static async Task<License?> LoadAsync(Stream input)
    {
        using var sr = new StreamReader(input, Encoding.UTF8);
        var json = await sr.ReadToEndAsync();
        return JsonConvert.DeserializeObject<License>(json);
    }
}