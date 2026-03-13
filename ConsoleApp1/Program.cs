using Enigma.Cryptography.PublicKey;
using Enigma.LicenseManager;
using System;
using System.IO;
using System.Threading.Tasks;

namespace ConsoleApp1;

static class Program
{
    static async Task Main()
    {
        // Generate an RSA key pair
        var rsaService = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = rsaService.GenerateKeyPair(2048);

        // Build a license
        var license = new LicenseBuilder()
            .SetProductId("MyApp 1.*")
            .SetOwner("John Doe")
            .SetExpirationDate(DateTime.UtcNow.AddDays(30))
            .SetDeviceId(LicenseUtils.GenerateDeviceId())
            .SignWithRsa(keyPair.Private)
            .Build();

        Console.WriteLine($"License created: {license.Id}");
        Console.WriteLine($"Product: {license.ProductId}");
        Console.WriteLine($"Owner: {license.Owner}");
        Console.WriteLine($"Expires: {license.ExpirationDate:O}");

        // Save and reload the license
        using var ms = new MemoryStream();
        await license.SaveAsync(ms);
        ms.Position = 0;
        var loaded = await License.LoadAsync(ms);

        Console.WriteLine($"\nLicense reloaded: {loaded?.Id}");

        // Validate the license
        var service = new LicenseService();
        var (isValid, message) = service.IsValid(
            loaded!, keyPair.Public, "MyApp 1.2.3", LicenseUtils.GenerateDeviceId());

        Console.WriteLine($"\nValidation result: {(isValid ? "VALID" : "INVALID")}");
        if (message is not null)
            Console.WriteLine($"Message: {message}");
    }
}
