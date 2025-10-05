using Enigma.Cryptography.Extensions;
using Newtonsoft.Json;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System;

namespace Enigma.LicenseManager;

/// <summary>
/// Represents a software license with all its metadata and signature.
/// </summary>
public class License
{
    /// <summary>
    /// Gets or sets the unique identifier of the license.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the license was created.
    /// </summary>
    public DateTime? CreationDate { get; set; }

    /// <summary>
    /// Gets or sets the product identifier this license is valid for.
    /// Supports wildcard patterns with the '*' character.
    /// </summary>
    public string? ProductId { get; set; }

    /// <summary>
    /// Gets or sets the device identifier this license is bound to.
    /// If null, the license is not device-specific.
    /// </summary>
    public string? DeviceId { get; set; }

    /// <summary>
    /// Gets or sets the expiration date and time of the license.
    /// If null, the license never expires.
    /// </summary>
    public DateTime? ExpirationDate { get; set; }

    /// <summary>
    /// Gets or sets the owner of the license.
    /// </summary>
    public string? Owner { get; set; }

    /// <summary>
    /// Gets or sets the cryptographic signature of the license data.
    /// Used to verify the authenticity and integrity of the license.
    /// </summary>
    public byte[]? Signature { get; set; }

    /// <summary>
    /// Generates a byte array representing the license data that should be signed.
    /// This includes all relevant license properties in a consistent format.
    /// </summary>
    /// <returns>UTF-8 encoded byte array containing the license data for signing.</returns>
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

        return sb.ToString().GetUtf8Bytes(); 
    }

    /// <summary>
    /// Asynchronously saves the license to a stream in JSON format.
    /// </summary>
    /// <param name="output">The output stream to write the license data to.</param>
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
    /// <param name="input">The input stream to read the license data from.</param>
    /// <returns>A task representing the asynchronous load operation, returning the loaded license or null if deserialization fails.</returns>
    public static async Task<License?> LoadAsync(Stream input)
    {
        using var sr = new StreamReader(input, Encoding.UTF8);
        var json = await sr.ReadToEndAsync();
        return JsonConvert.DeserializeObject<License>(json);
    }
}