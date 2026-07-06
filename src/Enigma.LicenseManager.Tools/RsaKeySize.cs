namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Supported RSA key sizes, in bits. The enum value equals the key size passed to the RSA key generator.
/// </summary>
public enum RsaKeySize
{
    /// <summary>2048-bit RSA key.</summary>
    Rsa2048 = 2048,

    /// <summary>3072-bit RSA key.</summary>
    Rsa3072 = 3072,

    /// <summary>4096-bit RSA key.</summary>
    Rsa4096 = 4096,

    /// <summary>8192-bit RSA key.</summary>
    Rsa8192 = 8192
}
