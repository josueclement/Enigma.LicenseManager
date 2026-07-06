using Enigma.Cryptography.Utils;
using Enigma.LicenseManager;
using Enigma.LicenseManager.Tools;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System;

namespace UnitTests;

/// <summary>
/// Tests for the <c>Enigma.LicenseManager.Tools</c> orchestration layer (key generation, license
/// generation and license validation services). Reuses <see cref="KeyFixture"/> for the pre-generated
/// PEM keys; fresh key pairs are generated only where a test exercises key generation itself.
/// </summary>
public class ToolsTests : IClassFixture<KeyFixture>
{
    private readonly KeyFixture _keys;

    private static readonly KeyGenerationService KeyGen = new();
    private static readonly LicenseGenerationService LicenseGen = new();

    public ToolsTests(KeyFixture keys)
    {
        _keys = keys;
    }

    private static LicenseValidationService NewValidator() => new(new LicenseService());

    /// <summary>Builds and signs a license into a rewound, readable memory stream.</summary>
    private static async Task<MemoryStream> BuildLicenseStreamAsync(LicenseGenerationRequest request,
        AsymmetricKeyParameter privateKey)
    {
        var ms = new MemoryStream();
        await LicenseGen.CreateAndSaveLicenseAsync(request, privateKey, ms);
        ms.Position = 0;
        return ms;
    }

    /// <summary>Writes a public key to a rewound, readable PEM memory stream.</summary>
    private static MemoryStream PublicPem(AsymmetricKeyParameter publicKey)
    {
        var ms = new MemoryStream();
        PemUtils.SaveKey(publicKey, ms);
        ms.Position = 0;
        return ms;
    }

    // ---------- Key generation → sign → validate round-trips ----------

    [Theory]
    [InlineData(RsaKeySize.Rsa2048)]
    [InlineData(RsaKeySize.Rsa3072)]
    [InlineData(RsaKeySize.Rsa4096)]
    public async Task Rsa_GenerateSignValidate_RoundTrip(RsaKeySize keySize)
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, keySize);

        using var licenseStream = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            keyPair.Private);
        using var publicPem = PublicPem(keyPair.Public);

        var result = await NewValidator().ValidateAsync(licenseStream, publicPem, "MyApp");

        Assert.True(result.IsValid, result.Message);
        Assert.Null(result.Message);
        Assert.NotNull(result.License);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public async Task Rsa8192_GenerateSignValidate_RoundTrip()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, RsaKeySize.Rsa8192);

        using var licenseStream = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            keyPair.Private);
        using var publicPem = PublicPem(keyPair.Public);

        var result = await NewValidator().ValidateAsync(licenseStream, publicPem, "MyApp");

        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task MlDsa_GenerateSignValidate_RoundTrip()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.MlDsa);

        using var licenseStream = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.MlDsa },
            keyPair.Private);
        using var publicPem = PublicPem(keyPair.Public);

        var result = await NewValidator().ValidateAsync(licenseStream, publicPem, "MyApp");

        Assert.True(result.IsValid, result.Message);
    }

    // ---------- PEM save / load: plain vs encrypted ----------

    [Fact]
    public async Task SaveKeyPair_Plain_PublicLoadsViaLoadKey_PrivateLoadsViaLoadPrivateKey()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, RsaKeySize.Rsa2048);

        using var pub = new MemoryStream();
        using var priv = new MemoryStream();
        await KeyGen.SaveKeyPairAsync(keyPair, pub, priv, privateKeyPassword: null);

        pub.Position = 0;
        var publicKey = PemUtils.LoadKey(pub);
        Assert.False(publicKey.IsPrivate);

        // A plain RSA private key PEM decodes to an AsymmetricCipherKeyPair, so it must be loaded via
        // LoadPrivateKey (LoadKey rejects it); the password is ignored for an unencrypted key.
        priv.Position = 0;
        var privateKey = PemUtils.LoadPrivateKey(priv, string.Empty);
        Assert.True(privateKey.IsPrivate);
    }

    [Fact]
    public async Task SaveKeyPair_Encrypted_LoadsBackWithCorrectPassword()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, RsaKeySize.Rsa2048);

        using var pub = new MemoryStream();
        using var priv = new MemoryStream();
        await KeyGen.SaveKeyPairAsync(keyPair, pub, priv, "s3cret");

        priv.Position = 0;
        var privateKey = PemUtils.LoadPrivateKey(priv, "s3cret");
        Assert.True(privateKey.IsPrivate);
    }

    [Fact]
    public async Task SaveKeyPair_Encrypted_WrongPassword_Throws()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, RsaKeySize.Rsa2048);

        using var pub = new MemoryStream();
        using var priv = new MemoryStream();
        await KeyGen.SaveKeyPairAsync(keyPair, pub, priv, "correct-password");

        priv.Position = 0;
        Assert.ThrowsAny<Exception>(() => PemUtils.LoadPrivateKey(priv, "wrong-password"));
    }

    [Fact]
    public async Task SaveKeyPair_Encrypted_LoadedAsPlain_Fails()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, RsaKeySize.Rsa2048);

        using var pub = new MemoryStream();
        using var priv = new MemoryStream();
        await KeyGen.SaveKeyPairAsync(keyPair, pub, priv, "correct-password");

        priv.Position = 0;
        // An encrypted private key must not be loadable via the plain (password-less) path.
        Assert.ThrowsAny<Exception>(() => PemUtils.LoadKey(priv));
    }

    [Fact]
    public async Task SaveKeyPair_WhitespacePassword_IsTreatedAsPlain()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, RsaKeySize.Rsa2048);

        using var pub = new MemoryStream();
        using var priv = new MemoryStream();
        await KeyGen.SaveKeyPairAsync(keyPair, pub, priv, "   ");

        priv.Position = 0;
        // Whitespace-only password ⇒ plain save ⇒ loadable without a real password (via LoadPrivateKey).
        var privateKey = PemUtils.LoadPrivateKey(priv, string.Empty);
        Assert.True(privateKey.IsPrivate);
    }

    [Theory]
    [InlineData(LicenseAlgorithm.Rsa)]
    [InlineData(LicenseAlgorithm.MlDsa)]
    public async Task GenerateService_LoadsPlainPrivateKeyFromPem_AndSigns(LicenseAlgorithm algorithm)
    {
        var keyPair = KeyGen.GenerateKeyPair(algorithm, RsaKeySize.Rsa2048);

        using var pub = new MemoryStream();
        using var priv = new MemoryStream();
        await KeyGen.SaveKeyPairAsync(keyPair, pub, priv, privateKeyPassword: null);
        priv.Position = 0;

        // The generation service must load a PLAIN (unencrypted) private key from a PEM stream and sign.
        using var licenseStream = new MemoryStream();
        await LicenseGen.CreateAndSaveLicenseAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = algorithm },
            priv, privateKeyPassword: null, licenseStream);
        licenseStream.Position = 0;

        using var publicPem = PublicPem(keyPair.Public);
        var result = await NewValidator().ValidateAsync(licenseStream, publicPem, "MyApp");
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task GenerateService_LoadsEncryptedPrivateKeyFromPem_AndSigns()
    {
        var keyPair = KeyGen.GenerateKeyPair(LicenseAlgorithm.Rsa, RsaKeySize.Rsa2048);

        using var pub = new MemoryStream();
        using var priv = new MemoryStream();
        await KeyGen.SaveKeyPairAsync(keyPair, pub, priv, "key-password");
        priv.Position = 0;

        using var licenseStream = new MemoryStream();
        await LicenseGen.CreateAndSaveLicenseAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            priv, "key-password", licenseStream);
        licenseStream.Position = 0;

        using var publicPem = PublicPem(keyPair.Public);
        var result = await NewValidator().ValidateAsync(licenseStream, publicPem, "MyApp");
        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task GenerateAndSaveKeyPairAsync_WritesBothFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), "enigma-tools-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var pubPath = Path.Combine(dir, "public.pem");
        var privPath = Path.Combine(dir, "private.pem");
        try
        {
            await KeyGen.GenerateAndSaveKeyPairAsync(LicenseAlgorithm.Rsa, pubPath, privPath,
                RsaKeySize.Rsa2048, "pwd");

            Assert.True(File.Exists(pubPath));
            Assert.True(File.Exists(privPath));

            await using var pub = File.OpenRead(pubPath);
            Assert.False(PemUtils.LoadKey(pub).IsPrivate);

            await using var priv = File.OpenRead(privPath);
            Assert.True(PemUtils.LoadPrivateKey(priv, "pwd").IsPrivate);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---------- Algorithm dispatch ----------

    [Fact]
    public async Task Dispatch_Rsa_SetsSignedWithRsa()
    {
        using var ms = new MemoryStream();
        var license = await LicenseGen.CreateAndSaveLicenseAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey, ms);

        Assert.Equal("RSA", license.SignedWith);
    }

    [Fact]
    public async Task Dispatch_MlDsa_SetsSignedWithMlDsa()
    {
        using var ms = new MemoryStream();
        var license = await LicenseGen.CreateAndSaveLicenseAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.MlDsa },
            _keys.MlDsa1PrivateKey, ms);

        Assert.Equal("ML-DSA", license.SignedWith);
    }

    // ---------- Id / CreationDate defaulting ----------

    [Fact]
    public async Task Defaulting_IdAndCreationDate_GeneratedWhenOmitted()
    {
        var before = DateTime.UtcNow.AddSeconds(-1);
        using var ms = new MemoryStream();
        var license = await LicenseGen.CreateAndSaveLicenseAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey, ms);
        var after = DateTime.UtcNow.AddSeconds(1);

        Assert.False(string.IsNullOrWhiteSpace(license.Id));
        Assert.Equal(26, license.Id!.Length); // ULID string length
        Assert.NotNull(license.CreationDate);
        Assert.InRange(license.CreationDate!.Value, before, after);
    }

    [Fact]
    public async Task Defaulting_ExplicitIdAndCreationDate_Honored()
    {
        const string id = "my-explicit-id";
        var created = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);

        using var ms = new MemoryStream();
        var license = await LicenseGen.CreateAndSaveLicenseAsync(
            new LicenseGenerationRequest
            {
                ProductId = "MyApp",
                Algorithm = LicenseAlgorithm.Rsa,
                Id = id,
                CreationDate = created
            },
            _keys.Rsa1PrivateKey, ms);

        Assert.Equal(id, license.Id);
        Assert.Equal(created, license.CreationDate);
    }

    // ---------- Generation input guards ----------

    [Fact]
    public async Task CreateLicense_WithPublicKey_ThrowsArgumentException()
    {
        using var ms = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            LicenseGen.CreateAndSaveLicenseAsync(
                new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
                _keys.Rsa1PublicKey, ms));
    }

    [Fact]
    public async Task CreateLicense_EmptyProductId_ThrowsArgumentException()
    {
        using var ms = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            LicenseGen.CreateAndSaveLicenseAsync(
                new LicenseGenerationRequest { ProductId = "   ", Algorithm = LicenseAlgorithm.Rsa },
                _keys.Rsa1PrivateKey, ms));
    }

    // ---------- Validation outcomes ----------

    [Fact]
    public async Task Validate_ValidRsa_ReturnsTrueWithNullMessage()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp");

        Assert.True(result.IsValid);
        Assert.Null(result.Message);
        Assert.NotNull(result.License);
    }

    [Fact]
    public async Task Validate_WrongPublicKeyRsa_ReturnsFalseButKeepsLicense()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa2PublicKey); // wrong key

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp");

        Assert.False(result.IsValid);
        Assert.NotNull(result.Message);
        Assert.NotNull(result.License);
    }

    [Fact]
    public async Task Validate_WrongPublicKeyMlDsa_ReturnsFalse()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.MlDsa },
            _keys.MlDsa1PrivateKey);
        using var pub = PublicPem(_keys.MlDsa2PublicKey); // wrong key

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp");

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Validate_Expired_ReturnsFalse()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest
            {
                ProductId = "MyApp",
                Algorithm = LicenseAlgorithm.Rsa,
                ExpirationDate = DateTime.UtcNow.AddMinutes(-5)
            },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp");

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Validate_ProductMismatch_ReturnsFalse()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "OtherApp");

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Validate_WildcardProduct_Matches()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp 1.*", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp 1.2.3");

        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task Validate_RegexMetacharProduct_ExactMatch()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp (1.0)", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp (1.0)");

        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task Validate_DeviceBinding_Match()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest
            {
                ProductId = "MyApp",
                Algorithm = LicenseAlgorithm.Rsa,
                DeviceId = "device-abc"
            },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp", "device-abc");

        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task Validate_DeviceBinding_Mismatch_ReturnsFalse()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest
            {
                ProductId = "MyApp",
                Algorithm = LicenseAlgorithm.Rsa,
                DeviceId = "device-abc"
            },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp", "device-xyz");

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Validate_NoDeviceBinding_IgnoresProvidedDeviceId()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp", "any-device");

        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task Validate_ProductIdOmitted_SelfValidates()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp 1.*", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        // productId omitted ⇒ the license validates against its own ProductId.
        var result = await NewValidator().ValidateAsync(lic, pub, productId: null);

        Assert.True(result.IsValid, result.Message);
    }

    [Fact]
    public async Task Validate_TamperedLicense_ReturnsFalse()
    {
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa, Owner = "Alice" },
            _keys.Rsa1PrivateKey);

        // Tamper a signed field while keeping the JSON well-formed ⇒ signature no longer matches.
        var json = Encoding.UTF8.GetString(lic.ToArray()).Replace("Alice", "Mallory");
        using var tampered = new MemoryStream(Encoding.UTF8.GetBytes(json));
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(tampered, pub, "MyApp");

        Assert.False(result.IsValid);
    }

    // ---------- Malformed input: recoverable, never throws ----------

    [Fact]
    public async Task Validate_CorruptLicenseJson_ReturnsFalseWithoutThrowing()
    {
        using var lic = new MemoryStream(Encoding.UTF8.GetBytes("this is not valid json {"));
        using var pub = PublicPem(_keys.Rsa1PublicKey);

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp");

        Assert.False(result.IsValid);
        Assert.NotNull(result.Message);
    }

    [Fact]
    public async Task Validate_MalformedPublicKeyPem_ReturnsFalseWithoutThrowing()
    {
        // Chosen contract: a public-key PEM that contains no readable key ⇒ (false, message) without
        // throwing; the already-parsed license is still returned on the result.
        using var lic = await BuildLicenseStreamAsync(
            new LicenseGenerationRequest { ProductId = "MyApp", Algorithm = LicenseAlgorithm.Rsa },
            _keys.Rsa1PrivateKey);
        using var pub = new MemoryStream(Encoding.UTF8.GetBytes("not a pem at all"));

        var result = await NewValidator().ValidateAsync(lic, pub, "MyApp");

        Assert.False(result.IsValid);
        Assert.NotNull(result.Message);
        Assert.NotNull(result.License);
    }

    // ---------- Dependency injection ----------

    [Fact]
    public void AddLicenseTools_ResolvesAllServices()
    {
        using var provider = new ServiceCollection().AddLicenseTools().BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<IKeyGenerationService>());
        Assert.NotNull(provider.GetRequiredService<ILicenseGenerationService>());
        Assert.NotNull(provider.GetRequiredService<ILicenseValidationService>());
        Assert.NotNull(provider.GetRequiredService<LicenseService>());
    }

    [Fact]
    public void AddLicenseTools_ServicesAreSingletons()
    {
        using var provider = new ServiceCollection().AddLicenseTools().BuildServiceProvider();

        Assert.Same(
            provider.GetRequiredService<IKeyGenerationService>(),
            provider.GetRequiredService<IKeyGenerationService>());
        Assert.Same(
            provider.GetRequiredService<ILicenseValidationService>(),
            provider.GetRequiredService<ILicenseValidationService>());
    }
}
