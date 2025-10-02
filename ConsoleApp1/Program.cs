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
        var privateKeyPath = @"";
        var privateKeyPassword = "";
        var publicKeyPath = @"";
        
        var rsa = new PublicKeyServiceFactory().CreateRsaService();
        await using var fsPrivateKey = new FileStream(privateKeyPath, FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(fsPrivateKey, privateKeyPassword);
        
        await using var fsPublicKey = new FileStream(publicKeyPath, FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(fsPublicKey);

        var license = new LicenseBuilder()
            .SetPrivateKey(privateKey)
            .SetType(LicenseType.Unlimited)
            .SetExpirationDate(DateTime.Now.AddDays(-2))
            .Build();

        var isValid = license.IsValid(publicKey);
    }
}