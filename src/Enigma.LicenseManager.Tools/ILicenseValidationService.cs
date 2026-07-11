using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Loads and validates licenses against a public key. Malformed license or key input never throws — such
/// failures are reported through the returned <see cref="LicenseValidationResult"/>. Genuine environmental
/// faults (e.g. file I/O errors) still propagate.
/// </summary>
public interface ILicenseValidationService
{
    /// <summary>
    /// Loads a license and a public key from streams and validates the license. Both streams are left open.
    /// </summary>
    /// <param name="licenseInput">The stream to read the license (JSON) from.</param>
    /// <param name="publicKeyInput">The stream to read the public-key PEM from.</param>
    /// <param name="productId">The product identifier to validate against; when null, the license's own product id is used.</param>
    /// <param name="deviceId">The optional device identifier to validate against.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The validation result.</returns>
    Task<LicenseValidationResult> ValidateAsync(Stream licenseInput, Stream publicKeyInput,
        string? productId = null, string? deviceId = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads a license and a public key from file paths and validates the license.
    /// </summary>
    /// <param name="licensePath">The file path to read the license (JSON) from.</param>
    /// <param name="publicKeyPath">The file path to read the public-key PEM from.</param>
    /// <param name="productId">The product identifier to validate against; when null, the license's own product id is used.</param>
    /// <param name="deviceId">The optional device identifier to validate against.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The validation result.</returns>
    Task<LicenseValidationResult> ValidateAsync(string licensePath, string publicKeyPath,
        string? productId = null, string? deviceId = null, CancellationToken cancellationToken = default);
}
