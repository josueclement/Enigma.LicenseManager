using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto;

namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Default <see cref="ILicenseGenerationService"/> implementation. Maps a
/// <see cref="LicenseGenerationRequest"/> onto a <see cref="LicenseBuilder"/>, signs and persists it.
/// </summary>
public sealed class LicenseGenerationService : ILicenseGenerationService
{
    /// <inheritdoc />
    public async Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request,
        AsymmetricKeyParameter privateKey, Stream output, CancellationToken cancellationToken = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (string.IsNullOrWhiteSpace(request.ProductId))
            throw new ArgumentException("ProductId must be a non-empty value.", nameof(request));

        var builder = new LicenseBuilder().SetProductId(request.ProductId);

        if (request.Owner is not null)
            builder.SetOwner(request.Owner);
        if (request.DeviceId is not null)
            builder.SetDeviceId(request.DeviceId);
        if (request.ExpirationDate is not null)
            builder.SetExpirationDate(request.ExpirationDate.Value);
        // Set Id / CreationDate only when supplied so the builder's ULID / UtcNow defaulting stays central.
        if (request.Id is not null)
            builder.SetId(request.Id);
        if (request.CreationDate is not null)
            builder.SetCreationDate(request.CreationDate.Value);

        switch (request.Algorithm)
        {
            case LicenseAlgorithm.Rsa:
                builder.SignWithRsa(privateKey);
                break;
            case LicenseAlgorithm.MlDsa:
                builder.SignWithMlDsa(privateKey);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(request), request.Algorithm,
                    "Unsupported license algorithm.");
        }

        var license = builder.Build();
        await license.SaveAsync(output, cancellationToken).ConfigureAwait(false);
        return license;
    }

    /// <inheritdoc />
    public Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, Stream privateKeyInput,
        string? privateKeyPassword, Stream output, CancellationToken cancellationToken = default)
    {
        if (privateKeyInput is null) throw new ArgumentNullException(nameof(privateKeyInput));

        var privateKey = LoadPrivateKey(privateKeyInput, privateKeyPassword);
        return CreateAndSaveLicenseAsync(request, privateKey, output, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<License> CreateAndSaveLicenseAsync(LicenseGenerationRequest request, string privateKeyPath,
        string? privateKeyPassword, string outputPath, CancellationToken cancellationToken = default)
    {
        AsymmetricKeyParameter privateKey;
        // PemUtils is synchronous; read the key on the caller's thread, then do async I/O for the license.
        using (var keyStream = new FileStream(privateKeyPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            privateKey = LoadPrivateKey(keyStream, privateKeyPassword);
        }

        using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None,
            bufferSize: 4096, useAsync: true);
        return await CreateAndSaveLicenseAsync(request, privateKey, output, cancellationToken).ConfigureAwait(false);
    }

    // Always use LoadPrivateKey: a plain (unencrypted) RSA private key PEM decodes to an
    // AsymmetricCipherKeyPair, which PemUtils.LoadKey rejects — LoadPrivateKey unwraps it and only
    // consults the password when the PEM is actually encrypted, so this handles plain and encrypted keys.
    private static AsymmetricKeyParameter LoadPrivateKey(Stream input, string? password)
        => PemUtils.LoadPrivateKey(input, password ?? string.Empty);
}
