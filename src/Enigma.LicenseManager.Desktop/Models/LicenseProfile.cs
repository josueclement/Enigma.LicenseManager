using System;

namespace Enigma.LicenseManager.Desktop.Models;

/// <summary>
/// A reusable, serializable snapshot of the Generate Licenses form fields, saved to / loaded from a
/// <c>.json</c> file so recurring license metadata need not be re-typed. Intentionally carries
/// <b>no secret</b>: the signing key password is never persisted, nor is the license output path.
/// </summary>
public class LicenseProfile
{
    public string? ProductId { get; set; }
    public string? Owner { get; set; }
    public string? DeviceId { get; set; }

    /// <summary>The signing algorithm, persisted by name ("RSA" or "ML-DSA") so it survives reordering.</summary>
    public string? Algorithm { get; set; }

    public bool HasExpiration { get; set; }
    public DateTime? ExpirationDate { get; set; }

    public string? SigningKeyPath { get; set; }
}
