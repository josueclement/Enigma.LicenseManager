namespace Enigma.LicenseManager.Cli;

/// <summary>
/// Process exit codes returned by the CLI. <c>0</c> means success (and, for <c>license validate</c>, a
/// valid license); any non-zero value means failure — so the tool is usable in scripts and CI gates.
/// </summary>
internal static class ExitCodes
{
    /// <summary>The operation succeeded (and the license is valid, for validation).</summary>
    public const int Success = 0;

    /// <summary>The license was processed successfully but is not valid.</summary>
    public const int LicenseInvalid = 1;

    /// <summary>The operation failed (e.g. a bad password, a missing or unreadable file).</summary>
    public const int Error = 2;
}
