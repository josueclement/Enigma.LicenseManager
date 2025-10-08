using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.PQC;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Enigma.LicenseManager;

namespace ConsoleApp1;

static class Program
{
    static async Task Main()
    {
        // string basePath = @"C:\Dev\DotNet\Enigma.LicenseManager\UnitTests\Data";
        // await GenerateRsaKey(basePath, "RSA1");
        // await GenerateRsaKey(basePath, "RSA2");
        // await GenerateMlDsaKey(basePath, "MLDSA1");
        // await GenerateMlDsaKey(basePath, "MLDSA2");
        
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var mldsa = new MLDsaServiceFactory().CreateDsa87Service();
        
        var privateKeyPath = @"D:\MLDSA1_private.pem";
        var privateKeyPassword = "test1234";
        var publicKeyPath = @"D:\MLDSA1_pub.pem";
        
        await using var fsPrivateKey = new FileStream(privateKeyPath, FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(fsPrivateKey, privateKeyPassword);
        
        await using var fsPublicKey = new FileStream(publicKeyPath, FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(fsPublicKey);

        
        // var license = new LicenseBuilder()
        //     .SetProductId("MyApp 1.*")
        //     .SetExpirationDate(DateTime.UtcNow.AddDays(2))
        //     .SignWithMlDsa(privateKey)
        //     .Build();
        //
        // await using var fs = new FileStream(@"D:/license2.lic", FileMode.Create, FileAccess.Write);
        // await license.SaveAsync(fs);
        
        await using var fs = new FileStream(@"D:/license2.lic", FileMode.Open, FileAccess.Read);
        var license = await License.LoadAsync(fs);

        var service = new LicenseService();
        var (isValid, msg) = service.IsValid(license, publicKey, "MyApp 1.1.3-beta22", "myPC");

        Console.WriteLine(isValid ? "Valid" : "Not valid");
    }

    static async Task GenerateRsaKey(string path, string keyName)
    {
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsa.GenerateKeyPair(4096);
        
        await using var privateFile = new FileStream(Path.Combine(path, keyName + "_private.pem"), FileMode.Create, FileAccess.Write);
        PemUtils.SavePrivateKey(keyPair.Private, privateFile, "test1234");
        await using var publicFile = new FileStream(Path.Combine(path, keyName + "_public.pem"), FileMode.Create, FileAccess.Write);
        PemUtils.SaveKey(keyPair.Public, publicFile);
    }

    static async Task GenerateMlDsaKey(string path, string keyName)
    {
        var mldsa = new MLDsaServiceFactory().CreateDsa87Service();
        var keyPair = mldsa.GenerateKeyPair();
        
        await using var privateFile = new FileStream(Path.Combine(path, keyName + "_private.pem"), FileMode.Create, FileAccess.Write);
        PemUtils.SavePrivateKey(keyPair.Private, privateFile, "test1234");
        await using var publicFile = new FileStream(Path.Combine(path, keyName + "_public.pem"), FileMode.Create, FileAccess.Write);
        PemUtils.SaveKey(keyPair.Public, publicFile);
    }
}