using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Generates RSA / ML-DSA key pairs and persists them to PEM.
/// </summary>
public interface IKeyGenerationService
{
    /// <summary>
    /// Generates a new key pair for the given algorithm. This is a synchronous, CPU-bound operation;
    /// callers on a UI thread should wrap it in a background task.
    /// </summary>
    /// <param name="algorithm">The algorithm to generate a key pair for.</param>
    /// <param name="rsaKeySize">The RSA key size; ignored for <see cref="LicenseAlgorithm.MlDsa"/> (fixed to level 87).</param>
    /// <returns>The generated key pair.</returns>
    AsymmetricCipherKeyPair GenerateKeyPair(LicenseAlgorithm algorithm, RsaKeySize rsaKeySize = RsaKeySize.Rsa3072);

    /// <summary>
    /// Saves a key pair to the given output streams in PEM format. The public key is always written
    /// unencrypted; the private key is encrypted with AES-256-CBC when <paramref name="privateKeyPassword"/>
    /// is non-empty, otherwise written unencrypted. The caller's streams are left open.
    /// </summary>
    /// <param name="keyPair">The key pair to save.</param>
    /// <param name="publicKeyOutput">The stream to write the public key to.</param>
    /// <param name="privateKeyOutput">The stream to write the private key to.</param>
    /// <param name="privateKeyPassword">Optional password; when non-empty the private key is encrypted.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A task representing the asynchronous save operation.</returns>
    Task SaveKeyPairAsync(AsymmetricCipherKeyPair keyPair, Stream publicKeyOutput, Stream privateKeyOutput,
        string? privateKeyPassword = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a key pair and saves it to the given file paths. Owns and disposes its own file streams.
    /// </summary>
    /// <param name="algorithm">The algorithm to generate a key pair for.</param>
    /// <param name="publicKeyPath">The file path to write the public key to.</param>
    /// <param name="privateKeyPath">The file path to write the private key to.</param>
    /// <param name="rsaKeySize">The RSA key size; ignored for ML-DSA.</param>
    /// <param name="privateKeyPassword">Optional password; when non-empty the private key is encrypted.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task GenerateAndSaveKeyPairAsync(LicenseAlgorithm algorithm, string publicKeyPath, string privateKeyPath,
        RsaKeySize rsaKeySize = RsaKeySize.Rsa3072, string? privateKeyPassword = null,
        CancellationToken cancellationToken = default);
}
