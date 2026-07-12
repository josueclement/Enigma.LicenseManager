namespace Enigma.LicenseManager.Tools;

/// <summary>
/// The outcome of a license validation. Carries the loaded <see cref="LicenseManager.License"/> (when it
/// could be parsed) so callers can display its fields even when validation fails.
/// </summary>
/// <param name="IsValid">Whether the license is valid.</param>
/// <param name="Message">An optional message describing why validation failed; null when valid.</param>
/// <param name="License">The loaded license, or null when it could not be parsed.</param>
public record LicenseValidationResult(bool IsValid, string? Message, License? License);
