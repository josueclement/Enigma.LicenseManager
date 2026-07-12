using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Builds, signs and persists licenses from a <see cref="LicenseGenerationRequest"/>.
/// </summary>
public interface ILicenseGenerationService
{
    /// <summary>
    /// Builds and signs a license using an already-loaded private key, and writes it to the output stream.
    /// The output stream is left open.
    /// </summary>
    /// <param name="request">The license description.</param>
    /// <param name="privateKey">The private key to sign with.</param>
    /// <param name="output">The stream to write the signed license (JSON) to.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The signed license.</returns>
    Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, AsymmetricKeyParameter privateKey,
        Stream output, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads a private key from a PEM stream (decrypted when <paramref name="privateKeyPassword"/> is
    /// non-empty), then builds, signs and writes the license to the output stream. Both streams are left open.
    /// </summary>
    /// <param name="request">The license description.</param>
    /// <param name="privateKeyInput">The stream to read the private-key PEM from.</param>
    /// <param name="privateKeyPassword">Optional password for an encrypted private key.</param>
    /// <param name="output">The stream to write the signed license (JSON) to.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The signed license.</returns>
    Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, Stream privateKeyInput,
        string? privateKeyPassword, Stream output, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads a private key from a PEM file, builds and signs the license, and writes it to the output file
    /// path. Owns and disposes its own file streams.
    /// </summary>
    /// <param name="request">The license description.</param>
    /// <param name="privateKeyPath">The file path to read the private-key PEM from.</param>
    /// <param name="privateKeyPassword">Optional password for an encrypted private key.</param>
    /// <param name="outputPath">The file path to write the signed license (JSON) to.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The signed license.</returns>
    Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, string privateKeyPath,
        string? privateKeyPassword, string outputPath, CancellationToken cancellationToken = default);
}
