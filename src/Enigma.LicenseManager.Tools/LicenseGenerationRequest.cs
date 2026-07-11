using System;

namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Describes the license to generate. Only <see cref="ProductId"/> and <see cref="Algorithm"/> are
/// required; when <see cref="Id"/> or <see cref="CreationDate"/> are omitted the core
/// <see cref="LicenseBuilder"/> supplies its own defaults (a new ULID and <see cref="DateTime.UtcNow"/>),
/// keeping that defaulting logic in one place.
/// </summary>
public record LicenseGenerationRequest
{
    /// <summary>
    /// The product identifier the license applies to. Supports wildcard patterns (e.g. <c>MyApp 1.*</c>).
    /// </summary>
    public required string ProductId { get; init; }

    /// <summary>The signature algorithm to sign the license with.</summary>
    public required LicenseAlgorithm Algorithm { get; init; }

    /// <summary>The optional owner of the license.</summary>
    public string? Owner { get; init; }

    /// <summary>The optional device identifier to bind the license to a specific device.</summary>
    public string? DeviceId { get; init; }

    /// <summary>The optional expiration date. When null, the license does not expire.</summary>
    public DateTime? ExpirationDate { get; init; }

    /// <summary>The optional license identifier. When null, the builder generates a new ULID.</summary>
    public string? Id { get; init; }

    /// <summary>The optional creation date. When null, the builder stamps <see cref="DateTime.UtcNow"/>.</summary>
    public DateTime? CreationDate { get; init; }
}
