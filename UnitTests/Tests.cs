using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.Utils;
using Enigma.LicenseManager;

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
        await using var publicKeyFile = new FileStream("Data/RSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
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
        await using var publicKeyFile = new FileStream("Data/MLDSA1_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyFile);
        
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
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using var privateKeyFile = new FileStream("Data/RSA1_private.pem", FileMode.Open, FileAccess.Read);
            var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
            await using var publicKeyFile = new FileStream("Data/RSA1_public.pem", FileMode.Open, FileAccess.Read);
            var publicKey = PemUtils.LoadKey(publicKeyFile);
        
            var license = new LicenseBuilder()
                .SignWithRsa(privateKey)
                .Build(); 
        });
    }

    [Fact]
    public async Task TryGenerateMlDsaLicense_WithMissingMembers()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await using var privateKeyFile = new FileStream("Data/MLDSA1_private.pem", FileMode.Open, FileAccess.Read);
            var privateKey = PemUtils.LoadPrivateKey(privateKeyFile, "test1234");
            await using var publicKeyFile = new FileStream("Data/MLDSA1_public.pem", FileMode.Open, FileAccess.Read);
            var publicKey = PemUtils.LoadKey(publicKeyFile);
        
            var license = new LicenseBuilder()
                .SetProductId("MyApp")
                .Build();
        });
    }
}