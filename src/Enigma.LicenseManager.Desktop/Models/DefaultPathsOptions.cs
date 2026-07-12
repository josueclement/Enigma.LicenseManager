namespace Enigma.LicenseManager.Desktop.Models;

public class DefaultPathsOptions
{
    public const string SectionName = "DefaultPaths";

    public string Keys { get; set; } = "";
    public string Licenses { get; set; } = "";

    /// <summary>The persisted UI theme ("Dark" or "Light"). Defaults to Dark.</summary>
    public string Theme { get; set; } = "Dark";
}
