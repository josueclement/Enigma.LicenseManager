using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Cryptography.Utils;
using Newtonsoft.Json;
using Org.BouncyCastle.Security;

namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Default <see cref="ILicenseValidationService"/> implementation. Delegates the cryptographic and rule
/// checks to the core <see cref="LicenseService"/>.
/// </summary>
public sealed class LicenseValidationService : ILicenseValidationService
{
    private readonly LicenseService _licenseService;

    /// <summary>
    /// Initializes a new instance backed by the given core license service.
    /// </summary>
    /// <param name="licenseService">The core service performing signature verification and rule checks.</param>
    public LicenseValidationService(LicenseService licenseService)
    {
        _licenseService = licenseService ?? throw new ArgumentNullException(nameof(licenseService));
    }

    /// <inheritdoc />
    public async Task<LicenseValidationResult> ValidateAsync(Stream licenseInput, Stream publicKeyInput,
        string? productId = null, string? deviceId = null, CancellationToken cancellationToken = default)
    {
        if (licenseInput is null) throw new ArgumentNullException(nameof(licenseInput));
        if (publicKeyInput is null) throw new ArgumentNullException(nameof(publicKeyInput));

        License? license = null;
        try
        {
            license = await License.LoadAsync(licenseInput, cancellationToken).ConfigureAwait(false);
            if (license is null)
                return new LicenseValidationResult(false, "The license could not be parsed.", null);

            var publicKey = PemUtils.LoadKey(publicKeyInput);

            // A null productId means "validate against the license's own product id".
            var effectiveProductId = productId ?? license.ProductId;
            if (effectiveProductId is null)
                return new LicenseValidationResult(false, "Invalid license: productId is missing.", license);

            var (isValid, message) = _licenseService.IsValid(license, publicKey, effectiveProductId, deviceId);
            return new LicenseValidationResult(isValid, message, license);
        }
        catch (Exception ex) when (IsRecoverable(ex))
        {
            return new LicenseValidationResult(false, ex.Message, license);
        }
    }

    /// <inheritdoc />
    public async Task<LicenseValidationResult> ValidateAsync(string licensePath, string publicKeyPath,
        string? productId = null, string? deviceId = null, CancellationToken cancellationToken = default)
    {
        using var licenseStream = new FileStream(licensePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 4096, useAsync: true);
        using var publicKeyStream = new FileStream(publicKeyPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return await ValidateAsync(licenseStream, publicKeyStream, productId, deviceId, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Recognizes exceptions caused by malformed license / key input (corrupt JSON, unreadable PEM, or
    /// crypto parse failures), which are converted into a failed <see cref="LicenseValidationResult"/>.
    /// Genuine environmental faults (e.g. <see cref="IOException"/> while opening or reading a file) are
    /// deliberately excluded so they propagate to the caller.
    /// </summary>
    private static bool IsRecoverable(Exception ex)
        => ex is JsonException
            or FormatException
            or InvalidOperationException
            or ArgumentException
            or GeneralSecurityException;
}
