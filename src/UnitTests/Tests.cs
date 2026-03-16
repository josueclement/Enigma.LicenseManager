using Enigma.Cryptography.Utils;
using Enigma.LicenseManager;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System;

namespace UnitTests;

public class KeyFixture : IAsyncLifetime
{
    public AsymmetricKeyParameter Rsa1PrivateKey { get; private set; } = null!;
    public AsymmetricKeyParameter Rsa1PublicKey { get; private set; } = null!;
    public AsymmetricKeyParameter MlDsa1PrivateKey { get; private set; } = null!;
    public AsymmetricKeyParameter MlDsa1PublicKey { get; private set; } = null!;
    public AsymmetricKeyParameter Rsa2PublicKey { get; private set; } = null!;
    public AsymmetricKeyParameter MlDsa2PublicKey { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await using var rsa1Priv = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        Rsa1PrivateKey = PemUtils.LoadPrivateKey(rsa1Priv, "test1234");

        await using var rsa1Pub = new FileStream("Data/RSA1_public.pem", FileMode.Open, FileAccess.Read);
        Rsa1PublicKey = PemUtils.LoadKey(rsa1Pub);

        await using var mldsa1Priv = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        MlDsa1PrivateKey = PemUtils.LoadPrivateKey(mldsa1Priv, "test1234");

        await using var mldsa1Pub = new FileStream("Data/MLDSA1_public.pem", FileMode.Open, FileAccess.Read);
        MlDsa1PublicKey = PemUtils.LoadKey(mldsa1Pub);

        await using var rsa2Pub = new FileStream("Data/RSA2_public.pem", FileMode.Open, FileAccess.Read);
        Rsa2PublicKey = PemUtils.LoadKey(rsa2Pub);

        await using var mldsa2Pub = new FileStream("Data/MLDSA2_public.pem", FileMode.Open, FileAccess.Read);
        MlDsa2PublicKey = PemUtils.LoadKey(mldsa2Pub);
    }

    public Task DisposeAsync() => Task.CompletedTask;
}

public class Tests : IClassFixture<KeyFixture>
{
    private readonly KeyFixture _keys;

    public Tests(KeyFixture keys)
    {
        _keys = keys;
    }

    [Fact]
    public void SimpleRsaTest_WithoutDeviceId()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.Rsa1PublicKey, "MyApp 1.1.7-beta1");

        Assert.True(isValid);
    }

    [Fact]
    public void SimpleRsaTest_WithDeviceId()
    {
        var deviceId = LicenseUtils.GenerateDeviceId();

        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetDeviceId(deviceId)
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.Rsa1PublicKey, "MyApp", deviceId);

        Assert.True(isValid);
    }

    [Fact]
    public void SimpleRsaTest_WithDeviceIdNotNeeded()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.Rsa1PublicKey, "MyApp", "myDeviceId");

        Assert.True(isValid);
    }

    [Fact]
    public void SimpleMlDsaTest_WithoutDeviceId()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.MlDsa1PublicKey, "MyApp");

        Assert.True(isValid);
    }

    [Fact]
    public void SimpleMlDsaTest_WithDeviceId()
    {
        var deviceId = LicenseUtils.GenerateDeviceId();

        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetDeviceId(deviceId)
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.MlDsa1PublicKey, "MyApp", deviceId);

        Assert.True(isValid);
    }

    [Fact]
    public void SimpleMlDsaTest_WithDeviceIdNotNeeded()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.MlDsa1PublicKey, "MyApp", "myDeviceId");

        Assert.True(isValid);
    }

    [Fact]
    public async Task SaveLoadRsaLicense()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var originalLicenseData = license.GetDataForSignature();

        var ms = new MemoryStream();
        await license.SaveAsync(ms);
        var serializedLicenseData = ms.ToArray();

        var ms2 = new MemoryStream(serializedLicenseData);
        var license2 = await License.LoadAsync(ms2);

        Assert.NotNull(license2);
        Assert.Equal(originalLicenseData, license2.GetDataForSignature());
    }

    [Fact]
    public async Task SaveLoadMlDsaLicense()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        var originalLicenseData = license.GetDataForSignature();

        var ms = new MemoryStream();
        await license.SaveAsync(ms);
        var serializedLicenseData = ms.ToArray();

        var ms2 = new MemoryStream(serializedLicenseData);
        var license2 = await License.LoadAsync(ms2);

        Assert.NotNull(license2);
        Assert.Equal(originalLicenseData, license2.GetDataForSignature());
    }

    [Fact]
    public void TryGenerateRsaLicense_WithMissingMembers()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            _ = new LicenseBuilder()
                .SignWithRsa(_keys.Rsa1PrivateKey)
                .Build();
        });
    }

    [Fact]
    public void TryGenerateMlDsaLicense_WithMissingMembers()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            _ = new LicenseBuilder()
                .SetProductId("MyApp")
                .Build();
        });
    }

    [Fact]
    public void TryValidateLicense_WithBadProductId()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.Rsa1PublicKey, "MyApp 1.2.7");

        Assert.False(isValid);
    }

    [Fact]
    public void TryValidateLicense_WithBadExpirationDate()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetExpirationDate(DateTime.UtcNow.AddMinutes(-1))
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.MlDsa1PublicKey, "MyApp");

        Assert.False(isValid);
    }

    [Fact]
    public void TryValidateRsaLicense_WithBadKey()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.Rsa2PublicKey, "MyApp");

        Assert.False(isValid);
    }

    [Fact]
    public void TryValidateMlDsaLicense_WithBadKey()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.MlDsa2PublicKey, "MyApp");

        Assert.False(isValid);
    }

    [Fact]
    public void TryValidateRsaLicense_WithBadLicenseData()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetExpirationDate(DateTime.UtcNow.AddDays(-1))
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        // Try to change the expiration date -> signature will be invalid
        license.ExpirationDate = DateTime.UtcNow.AddDays(1);

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.Rsa1PublicKey, "MyApp");

        Assert.False(isValid);
    }

    [Fact]
    public void TryValidateMlDsaLicense_WithBadLicenseData()
    {
        var license = new LicenseBuilder()
            .SetProductId("AnotherApp")
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        // Try to change the product id -> signature will be invalid
        license.ProductId = "MyApp";

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, _keys.MlDsa1PublicKey, "MyApp");

        Assert.False(isValid);
    }

    // HasValidLicense tests

    [Fact]
    public void HasValidLicense_ExactMatch()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.True(service.HasValidLicense("MyApp"));
    }

    [Fact]
    public void HasValidLicense_WildcardMatch()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.True(service.HasValidLicense("MyApp 1.2.3"));
    }

    [Fact]
    public void HasValidLicense_NoMatch()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.False(service.HasValidLicense("OtherApp"));
    }

    [Fact]
    public void HasValidLicense_WithDeviceId()
    {
        var deviceId = LicenseUtils.GenerateDeviceId();

        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetDeviceId(deviceId)
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.True(service.HasValidLicense("MyApp", deviceId));
    }

    [Fact]
    public void HasValidLicense_WrongDeviceId()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetDeviceId("device-abc")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.False(service.HasValidLicense("MyApp", "device-xyz"));
    }

    [Fact]
    public void HasValidLicense_RegexMetacharRejection()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp (1.0)")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.True(service.HasValidLicense("MyApp (1.0)"));
    }

    // LicenseUtils tests

    [Fact]
    public void GenerateDeviceId_ReturnsNonEmpty()
    {
        var deviceId = LicenseUtils.GenerateDeviceId();
        Assert.False(string.IsNullOrWhiteSpace(deviceId));
    }

    [Fact]
    public void GenerateDeviceId_IsConsistent()
    {
        var id1 = LicenseUtils.GenerateDeviceId();
        var id2 = LicenseUtils.GenerateDeviceId();
        Assert.Equal(id1, id2);
    }

    [Fact]
    public void GetExecutingAppName_DoesNotThrow()
    {
        var ex = Record.Exception(() => LicenseUtils.GetExecutingAppName());
        Assert.Null(ex);
    }

    [Fact]
    public void GetExecutingAppVersion_DoesNotThrow()
    {
        var ex = Record.Exception(() => LicenseUtils.GetExecutingAppVersion());
        Assert.Null(ex);
    }

    // RemoveLicense tests

    [Fact]
    public void RemoveLicense_ExistingLicense_ReturnsTrue()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.True(service.RemoveLicense(license));
    }

    [Fact]
    public void RemoveLicense_NonExistentLicense_ReturnsFalse()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();

        Assert.False(service.RemoveLicense(license));
    }

    [Fact]
    public void RemoveLicense_LicenseNoLongerValid()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license, _keys.Rsa1PublicKey);

        Assert.True(service.HasValidLicense("MyApp"));

        service.RemoveLicense(license);

        Assert.False(service.HasValidLicense("MyApp"));
    }

    [Fact]
    public void RemoveLicense_UsesReferenceEquality()
    {
        var license1 = new LicenseBuilder()
            .SetId("same-id")
            .SetProductId("MyApp")
            .SetCreationDate(DateTime.UtcNow)
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var license2 = new LicenseBuilder()
            .SetId("same-id")
            .SetProductId("MyApp")
            .SetCreationDate(license1.CreationDate!.Value)
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var service = new LicenseService();
        service.AddLicense(license1, _keys.Rsa1PublicKey);

        Assert.False(service.RemoveLicense(license2));
    }

    // Save/load round-trip with full validation

    [Fact]
    public async Task SaveLoadRsaLicense_ThenValidate()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(_keys.Rsa1PrivateKey)
            .Build();

        var ms = new MemoryStream();
        await license.SaveAsync(ms);

        var ms2 = new MemoryStream(ms.ToArray());
        var loaded = await License.LoadAsync(ms2);

        Assert.NotNull(loaded);

        var service = new LicenseService();
        var (isValid, message) = service.IsValid(loaded, _keys.Rsa1PublicKey, "MyApp 1.2.3");

        Assert.True(isValid, message);
    }

    [Fact]
    public async Task SaveLoadMlDsaLicense_ThenValidate()
    {
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(_keys.MlDsa1PrivateKey)
            .Build();

        var ms = new MemoryStream();
        await license.SaveAsync(ms);

        var ms2 = new MemoryStream(ms.ToArray());
        var loaded = await License.LoadAsync(ms2);

        Assert.NotNull(loaded);

        var service = new LicenseService();
        var (isValid, message) = service.IsValid(loaded, _keys.MlDsa1PublicKey, "MyApp");

        Assert.True(isValid, message);
    }

    // Public key rejection tests

    [Fact]
    public void SignWithRsa_PublicKey_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            new LicenseBuilder()
                .SetProductId("MyApp")
                .SignWithRsa(_keys.Rsa1PublicKey);
        });
    }

    [Fact]
    public void SignWithMlDsa_PublicKey_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            new LicenseBuilder()
                .SetProductId("MyApp")
                .SignWithMlDsa(_keys.MlDsa1PublicKey);
        });
    }
}
