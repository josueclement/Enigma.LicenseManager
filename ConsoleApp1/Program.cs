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
        // OK:
        // try to sign with private key with RSA and ML-DSA
        // try to verify product 1.0.2 with license 1.*
        // try to verify any product with no expiration date
        // try to verify any product with expiration date in the future
        // save/load licenses (hash license data before and after)
        
        // ERRORS:
        // try to sign with public key with RSA and ML-DSA
        // try to verify product 2.0 with license 1.*
        // try to verify any product with expiration date in the past
        // try to verify any product with wrong key
        // try to verify any product with wrong signature (modified property in license file)
        
        
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
}