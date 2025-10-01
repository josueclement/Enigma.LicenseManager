using System;

namespace Enigma.LicenseManager;

public class License(LicenseType type, string id)
{
    public LicenseType Type { get; } = type;
    public string Id { get; } = id;
    public byte[]? Message { get; set; }
    public DateTime? CreationDate { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public string? Recipient { get; set; }
}