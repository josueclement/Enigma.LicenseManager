using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Cryptography.PQC;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto;

namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Default <see cref="IKeyGenerationService"/> implementation backed by <c>Enigma.Cryptography</c>.
/// </summary>
public sealed class KeyGenerationService : IKeyGenerationService
{
    /// <summary>
    /// The symmetric algorithm used to encrypt private keys that are saved with a password.
    /// </summary>
    public const string PrivateKeyEncryptionAlgorithm = "AES-256-CBC";

    private readonly PublicKeyServiceFactory _publicKeyServiceFactory = new();
    private readonly MLDsaServiceFactory _mlDsaServiceFactory = new();

    /// <inheritdoc />
    public AsymmetricCipherKeyPair GenerateKeyPair(LicenseAlgorithm algorithm,
        RsaKeySize rsaKeySize = RsaKeySize.Rsa3072)
        => algorithm switch
        {
            // ML-DSA is hardcoded to level 87 — the only level the core LicenseBuilder / LicenseService accept.
            LicenseAlgorithm.Rsa => _publicKeyServiceFactory.CreateRsaService().GenerateKeyPair((int)rsaKeySize),
            LicenseAlgorithm.MlDsa => _mlDsaServiceFactory.CreateDsa87Service().GenerateKeyPair(),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported license algorithm.")
        };

    /// <inheritdoc />
    public async Task SaveKeyPairAsync(AsymmetricCipherKeyPair keyPair, Stream publicKeyOutput,
        Stream privateKeyOutput, string? privateKeyPassword = null, CancellationToken cancellationToken = default)
    {
        if (keyPair is null) throw new ArgumentNullException(nameof(keyPair));
        if (publicKeyOutput is null) throw new ArgumentNullException(nameof(publicKeyOutput));
        if (privateKeyOutput is null) throw new ArgumentNullException(nameof(privateKeyOutput));

        // Public key: always unencrypted.
        await WritePemAsync(publicKeyOutput,
            buffer => PemUtils.SaveKey(keyPair.Public, buffer), cancellationToken).ConfigureAwait(false);

        // Private key: encrypted only when a non-empty password is supplied.
        await WritePemAsync(privateKeyOutput, buffer =>
        {
            if (string.IsNullOrWhiteSpace(privateKeyPassword))
                PemUtils.SaveKey(keyPair.Private, buffer);
            else
                PemUtils.SavePrivateKey(keyPair.Private, buffer, privateKeyPassword!, PrivateKeyEncryptionAlgorithm);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task GenerateAndSaveKeyPairAsync(LicenseAlgorithm algorithm, string publicKeyPath,
        string privateKeyPath, RsaKeySize rsaKeySize = RsaKeySize.Rsa3072, string? privateKeyPassword = null,
        CancellationToken cancellationToken = default)
    {
        var keyPair = GenerateKeyPair(algorithm, rsaKeySize);

        using var publicKeyStream = new FileStream(publicKeyPath, FileMode.Create, FileAccess.Write,
            FileShare.None, bufferSize: 4096, useAsync: true);
        using var privateKeyStream = new FileStream(privateKeyPath, FileMode.Create, FileAccess.Write,
            FileShare.None, bufferSize: 4096, useAsync: true);

        await SaveKeyPairAsync(keyPair, publicKeyStream, privateKeyStream, privateKeyPassword, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// PEM-encodes into an in-memory buffer (the synchronous <see cref="PemUtils"/> API), then copies the
    /// bytes to <paramref name="destination"/> asynchronously so file I/O is genuinely async. The
    /// destination stream is left open.
    /// </summary>
    private static async Task WritePemAsync(Stream destination, Action<Stream> writePem,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        writePem(buffer);
        buffer.Position = 0;
        await buffer.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
    }
}
