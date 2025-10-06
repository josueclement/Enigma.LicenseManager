using Enigma.Cryptography.Extensions;
using Newtonsoft.Json;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System;

namespace Enigma.LicenseManager;

/// <summary>
/// Represents a software license with cryptographic signature support.
/// </summary>
public class License
{
    /// <summary>
    /// Gets or sets the unique identifier for this license.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Gets or sets the creation date of the license.
    /// </summary>
    public DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the product identifier that this license applies to.
    /// Supports wildcard patterns using asterisk (*) for flexible matching.
    /// </summary>
    public string? ProductId { get; set; }

    /// <summary>
    /// Gets or sets the unique device identifier that this license is bound to.
    /// If null, the license is not device-specific.
    /// </summary>
    public string? DeviceId { get; set; }

    /// <summary>
    /// Gets or sets the expiration date of the license.
    /// If null, the license does not expire.
    /// </summary>
    public DateTime? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the owner of the license.
    /// </summary>
    public string? Owner { get; set; }

    /// <summary>
    /// Gets or sets the cryptographic signature of the license.
    /// </summary>
    public byte[]? Signature { get; set; }

    /// <summary>
    /// Gets or sets the signature algorithm used to sign the license (e.g., "RSA", "ML-DSA").
    /// </summary>
    public string? SignedWith { get; set; }

    /// <summary>
    /// Generates the byte array representation of the license data that should be signed.
    /// </summary>
    /// <returns>A byte array containing the UTF-8 encoded license data.</returns>
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

    /// <summary>
    /// Asynchronously saves the license to a stream in JSON format.
    /// </summary>
    /// <param name="output">The stream to write the license data to.</param>
    /// <returns>A task representing the asynchronous save operation.</returns>
    public async Task SaveAsync(Stream output)
    {
        var json = JsonConvert.SerializeObject(this, Formatting.Indented);
        using var sw = new StreamWriter(output, Encoding.UTF8);
        await sw.WriteAsync(json);
    }

    /// <summary>
    /// Asynchronously loads a license from a stream containing JSON data.
    /// </summary>
    /// <param name="input">The stream to read the license data from.</param>
    /// <returns>A task representing the asynchronous load operation, containing the deserialized license or null if deserialization fails.</returns>
    public static async Task<License?> LoadAsync(Stream input)
    {
        using var sr = new StreamReader(input, Encoding.UTF8);
        var json = await sr.ReadToEndAsync();
        return JsonConvert.DeserializeObject<License>(json);
    }
}