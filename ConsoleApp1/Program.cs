using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Enigma.LicenseManager;

namespace ConsoleApp1;

static class Program
{
    static async Task Main()
    {
        var rsa = new PublicKeyServiceFactory().CreateRsaService();

        var keyPair = rsa.GenerateKeyPair(4096);
        // await using var fsPub = new FileStream(@"C:\temp\public.pem", FileMode.Create, FileAccess.Write);
        // PemUtils.SaveKey(keyPair.Public, fsPub);
        // await using var fsPri = new FileStream(@"C:\temp\private.pem", FileMode.Create, FileAccess.Write);
        // PemUtils.SavePrivateKey(keyPair.Private, fsPri, "test1234567890");
        
        var testId = IdGenerator.GenerateAppId();
        
        var privateKeyPath = @"C:\temp\private.pem";
        var privateKeyPassword = "test1234567890";
        var publicKeyPath = @"C:\temp\public.pem";
        
        // await using var fsPrivateKey = new FileStream(privateKeyPath, FileMode.Open, FileAccess.Read);
        // var privateKey = PemUtils.LoadPrivateKey(fsPrivateKey, privateKeyPassword);
        //
        // await using var fsPublicKey = new FileStream(publicKeyPath, FileMode.Open, FileAccess.Read);
        // var publicKey = PemUtils.LoadKey(fsPublicKey);

        var license = new RsaSignedLicenseBuilder()
            .SetPrivateKey(keyPair.Private)
            .SetProductId("MyAppV1.0")
            .SetExpirationDate(DateTime.UtcNow.AddDays(2))
            .Build();

        await using var fs = new FileStream(@"D:\license.lic", FileMode.Create, FileAccess.Write);
        await license.SaveAsync(fs);

        
        
        // Console.WriteLine(isValid ? "Valid" : "Not valid");
    }
}