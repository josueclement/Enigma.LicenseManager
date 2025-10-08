using Enigma.Cryptography.Utils;
using Enigma.LicenseManager;
using System.IO;
using System.Threading.Tasks;
using System;

namespace UnitTests;

public class Tests
{
    [Fact]
    public async Task SimpleRsaTest_WithoutDeviceId()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/RSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp 1.1.7-beta1");
        
        Assert.True(isValid);
    }
    
    [Fact]
    public async Task SimpleRsaTest_WithDeviceId()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/RSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var deviceId = LicenseUtils.GenerateDeviceId();
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetDeviceId(deviceId)
            .SignWithRsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp", deviceId);
        
        Assert.True(isValid);
    }
    
    [Fact]
    public async Task SimpleRsaTest_WithDeviceIdNotNeeded()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/RSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp", "myDeviceId");
        
        Assert.True(isValid);
    }
    
    [Fact]
    public async Task SimpleMlDsaTest_WithoutDeviceId()
    {
        await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/MLDSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp");
        
        Assert.True(isValid);
    }
    
    [Fact]
    public async Task SimpleMlDsaTest_WithDeviceId()
    {
        await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/MLDSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var deviceId = LicenseUtils.GenerateDeviceId();
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetDeviceId(deviceId)
            .SignWithMlDsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp", deviceId);
        
        Assert.True(isValid);
    }
    
    [Fact]
    public async Task SimpleMlDsaTest_WithDeviceIdNotNeeded()
    {
        await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/MLDSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp", "myDeviceId");
        
        Assert.True(isValid);
    }

    [Fact]
    public async Task SaveLoadRsaLicense()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(privateKey)
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
        await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(privateKey)
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
    public async Task TryGenerateRsaLicense_WithMissingMembers()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        
        Assert.Throws<InvalidOperationException>(() =>
        {
            _ = new LicenseBuilder()
                .SignWithRsa(privateKey)
                .Build(); 
        });
    }

    [Fact]
    public async Task TryGenerateMlDsaLicense_WithMissingMembers()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            _ = new LicenseBuilder()
                .SetProductId("MyApp")
                .Build();
        });

        await Task.CompletedTask;
    }

    [Fact]
    public async Task TryValidateLicense_WithBadProductId()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/RSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.1.*")
            .SetExpirationDate(DateTime.UtcNow.AddDays(1))
            .SignWithRsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp 1.2.7");
        
        Assert.False(isValid); 
    }

    [Fact]
    public async Task TryValidateLicense_WithBadExpirationDate()
    {
        await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/MLDSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetExpirationDate(DateTime.UtcNow.AddMinutes(-1))
            .SignWithMlDsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp");
        
        Assert.False(isValid); 
    }

    [Fact]
    public async Task TryValidateRsaLicense_WithBadKey()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/RSA2_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithRsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp");
        
        Assert.False(isValid); 
    }

    [Fact]
    public async Task TryValidateMlDsaLicense_WithBadKey()
    {
        await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/MLDSA2_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SignWithMlDsa(privateKey)
            .Build();

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp");
        
        Assert.False(isValid); 
    }

    [Fact]
    public async Task TryValidateRsaLicense_WithBadLicenseData()
    {
        await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/RSA2_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("MyApp")
            .SetExpirationDate(DateTime.UtcNow.AddDays(-1))
            .SignWithRsa(privateKey)
            .Build();
        
        // Try to change the expiration date -> signature will be invalid
        license.ExpirationDate = DateTime.UtcNow.AddDays(1);

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp");
        
        Assert.False(isValid); 
    }

    [Fact]
    public async Task TryValidateMlDsaLicense_WithBadLicenseData()
    {
        await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
        await using var publicKeyFile = new FileStream("Data/MLDSA2_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
        var license = new LicenseBuilder()
            .SetProductId("AnotherApp")
            .SignWithMlDsa(privateKey)
            .Build();
        
        // Try to change the product id -> signature will be invalid
        license.ProductId = "MyApp";

        var service = new LicenseService();
        var (isValid, _) = service.IsValid(license, publicKey, "MyApp");
        
        Assert.False(isValid); 
    }
}