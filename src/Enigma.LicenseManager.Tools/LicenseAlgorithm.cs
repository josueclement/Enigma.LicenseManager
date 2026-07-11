namespace Enigma.LicenseManager.Tools;

/// <summary>
/// Identifies the signature algorithm used to sign a license.
/// </summary>
public enum LicenseAlgorithm
{
    /// <summary>RSA signatures (classical public-key cryptography).</summary>
    Rsa,

    /// <summary>
    /// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) post-quantum signatures. Restricted to
    /// level 87 — the only level the core <see cref="LicenseBuilder"/> and <see cref="LicenseService"/> support.
    /// </summary>
    MlDsa
}
