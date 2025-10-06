using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using System;
using Enigma.Cryptography.PQC;

namespace Enigma.LicenseManager;

/// <summary>
/// Builder class for creating and configuring License instances with cryptographic signatures.
/// </summary>
public class LicenseBuilder
{
    private string? _id;
    private DateTime? _creationDate;
    private string? _deviceId;
    private string? _productId;
    private DateTime? _expirationDate;
    private string? _owner;
    private AsymmetricKeyParameter? _privateKey;
    private Func<byte[], AsymmetricKeyParameter, byte[]>? _signatureGenerator;
    private string? _signedWith;

    /// <summary>
    /// Sets the unique identifier for the license.
    /// </summary>
    /// <param name="id">The unique identifier for the license.</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    public LicenseBuilder SetId(string id)
    {
        _id = id;
        return this;
    }

    /// <summary>
    /// Sets the creation date for the license.
    /// </summary>
    /// <param name="creationDate">The creation date of the license.</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    public LicenseBuilder SetCreationDate(DateTime creationDate)
    {
        _creationDate = creationDate;
        return this;
    }

    /// <summary>
    /// Sets the product identifier that the license applies to.
    /// </summary>
    /// <param name="productId">The product identifier. Can include wildcard patterns using asterisk (*).</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    public LicenseBuilder SetProductId(string productId)
    {
        _productId = productId;
        return this;
    }

    /// <summary>
    /// Sets the device identifier to bind the license to a specific device.
    /// </summary>
    /// <param name="deviceId">The unique device identifier.</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    public LicenseBuilder SetDeviceId(string deviceId)
    {
        _deviceId = deviceId;
        return this;
    }

    /// <summary>
    /// Sets the expiration date for the license.
    /// </summary>
    /// <param name="expirationDate">The date when the license expires.</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    public LicenseBuilder SetExpirationDate(DateTime expirationDate)
    {
        _expirationDate = expirationDate;
        return this; 
    }

    /// <summary>
    /// Sets the owner of the license.
    /// </summary>
    /// <param name="owner">The name or identifier of the license owner.</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    public LicenseBuilder SetOwner(string owner)
    {
        _owner = owner;
        return this; 
    }

    /// <summary>
    /// Configures the builder to sign the license using RSA cryptographic algorithm.
    /// </summary>
    /// <param name="privateKey">The RSA private key to use for signing.</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when the provided key is not a private key.</exception>
    public LicenseBuilder SignWithRsa(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("The provided key must be a private key.", nameof(privateKey));
        
        _privateKey = privateKey;
        _signedWith = "RSA";
        _signatureGenerator = new PublicKeyServiceFactory().CreateRsaService().Sign;
        return this;
    }

    /// <summary>
    /// Configures the builder to sign the license using ML-DSA (Module-Lattice-Based Digital Signature Algorithm) post-quantum cryptographic algorithm.
    /// </summary>
    /// <param name="privateKey">The ML-DSA private key to use for signing.</param>
    /// <returns>The current LicenseBuilder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when the provided key is not a private key.</exception>
    public LicenseBuilder SignWithMlDsa(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("The provided key must be a private key.", nameof(privateKey));
        
        _privateKey = privateKey;
        _signedWith = "ML-DSA";
        _signatureGenerator = new MLDsaServiceFactory().CreateDsa87Service().Sign;
        return this;
    }

    /// <summary>
    /// Generates a cryptographic signature for the provided data using the configured signature generator.
    /// </summary>
    /// <param name="data">The data to be signed.</param>
    /// <returns>The generated cryptographic signature as a byte array.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the signature generator or private key is not configured.</exception>
    private byte[] GenerateSignature(byte[] data)
    {
        if (_signatureGenerator is null)
            throw new InvalidOperationException("Signature generator is missing. Call SignWithRsa or SignWithMlDsa first.");
        
        if (_privateKey is null)
            throw new InvalidOperationException("Private key is missing. Call SignWithRsa or SignWithMlDsa first.");

        return _signatureGenerator(data, _privateKey);
    }

    /// <summary>
    /// Builds and returns a signed License instance with all configured properties.
    /// </summary>
    /// <returns>A signed License instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the product ID is not set.</exception>
    public License Build()
    {
        if (_productId is null)
            throw new InvalidOperationException("Product id is missing. Call SetProductId first.");
        
        var license = new License
        {
            Id = _id ?? Ulid.NewUlid().ToString(),
            CreationDate = _creationDate ?? DateTime.UtcNow,
            ProductId = _productId,
            DeviceId = _deviceId,
            ExpirationDate = _expirationDate,
            Owner = _owner,
            SignedWith = _signedWith
        };

        var data = license.GetDataForSignature();
        license.Signature = GenerateSignature(data);

        return license;
    }
}