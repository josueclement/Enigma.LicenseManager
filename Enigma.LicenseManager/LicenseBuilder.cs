using Enigma.Cryptography.PublicKey;
using Org.BouncyCastle.Crypto;
using System;

namespace Enigma.LicenseManager;

/// <summary>
/// Builder class for creating and signing licenses using RSA cryptography.
/// Provides a fluent API for configuring license properties before generation.
/// </summary>
public class LicenseBuilder
{
    /// <summary>
    /// The unique identifier for the license.
    /// </summary>
    private string? _id;

    /// <summary>
    /// The creation date of the license.
    /// </summary>
    private DateTime? _creationDate;

    /// <summary>
    /// The device identifier the license is bound to.
    /// </summary>
    private string? _deviceId;

    /// <summary>
    /// The product identifier this license is valid for.
    /// </summary>
    private string? _productId;

    /// <summary>
    /// The expiration date of the license.
    /// </summary>
    private DateTime? _expirationDate;

    /// <summary>
    /// The owner of the license.
    /// </summary>
    private string? _owner;

    /// <summary>
    /// The RSA private key used for signing the license.
    /// </summary>
    private AsymmetricKeyParameter? _privateKey;

    /// <summary>
    /// Sets the RSA private key that will be used to sign the license.
    /// This key is required for the Build operation.
    /// </summary>
    /// <param name="privateKey">The RSA private key parameter.</param>
    /// <returns>This builder instance for method chaining.</returns>
    /// <exception cref="ArgumentException">Thrown when the provided key is not a private key.</exception>
    public LicenseBuilder SetPrivateKey(AsymmetricKeyParameter privateKey)
    {
        if (!privateKey.IsPrivate)
            throw new ArgumentException("Private key must be private.", nameof(privateKey));

        _privateKey = privateKey;
        return this;
    }

    /// <summary>
    /// Sets the unique identifier for the license.
    /// If not set, a ULID will be automatically generated during build.
    /// </summary>
    /// <param name="id">The license identifier.</param>
    /// <returns>This builder instance for method chaining.</returns>
    public LicenseBuilder SetId(string id)
    {
        _id = id;
        return this;
    }

    /// <summary>
    /// Sets the creation date for the license.
    /// If not set, the current UTC time will be used during build.
    /// </summary>
    /// <param name="creationDate">The creation date and time.</param>
    /// <returns>This builder instance for method chaining.</returns>
    public LicenseBuilder SetCreationDate(DateTime creationDate)
    {
        _creationDate = creationDate;
        return this;
    }

    /// <summary>
    /// Sets the product identifier this license is valid for.
    /// This is a required field and must be set before building.
    /// </summary>
    /// <param name="productId">The product identifier.</param>
    /// <returns>This builder instance for method chaining.</returns>
    public LicenseBuilder SetProductId(string productId)
    {
        _productId = productId;
        return this;
    }

    /// <summary>
    /// Sets the device identifier this license is bound to.
    /// If not set, the license will not be device-specific.
    /// </summary>
    /// <param name="deviceId">The device identifier.</param>
    /// <returns>This builder instance for method chaining.</returns>
    public LicenseBuilder SetDeviceId(string deviceId)
    {
        _deviceId = deviceId;
        return this;
    }

    /// <summary>
    /// Sets the expiration date for the license.
    /// If not set, the license will never expire.
    /// </summary>
    /// <param name="expirationDate">The expiration date and time.</param>
    /// <returns>This builder instance for method chaining.</returns>
    public LicenseBuilder SetExpirationDate(DateTime expirationDate)
    {
        _expirationDate = expirationDate;
        return this; 
    }

    /// <summary>
    /// Sets the owner of the license.
    /// </summary>
    /// <param name="owner">The license owner name or identifier.</param>
    /// <returns>This builder instance for method chaining.</returns>
    public LicenseBuilder SetOwner(string owner)
    {
        _owner = owner;
        return this; 
    }

    /// <summary>
    /// Generates an RSA digital signature for the license data.
    /// </summary>
    /// <param name="data">The license data to sign.</param>
    /// <returns>The RSA signature as a byte array.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the private key is not set.</exception>
    private byte[] GenerateSignature(byte[] data)
    {
        if (_privateKey is null)
            throw new InvalidOperationException("Private key is missing. Call SetPrivateKey first.");

        var rsa = new PublicKeyServiceFactory().CreateRsaService(); 
        return rsa.Sign(data, _privateKey);
    }

    /// <summary>
    /// Builds and signs the license using RSA cryptography.
    /// Generates default values for optional fields if not set.
    /// </summary>
    /// <returns>A signed license ready for distribution.</returns>
    /// <exception cref="InvalidOperationException">Thrown when required fields (product ID or private key) are not set.</exception>
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
            Owner = _owner
        };

        var data = license.GetDataForSignature();
        license.Signature = GenerateSignature(data);

        return license;
    }
}