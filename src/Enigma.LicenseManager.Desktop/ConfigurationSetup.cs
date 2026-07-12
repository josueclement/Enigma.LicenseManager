using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Enigma.LicenseManager.Desktop.Models;

namespace Enigma.LicenseManager.Desktop;

public static class ConfigurationSetup
{
    // Per-user config at ~/.config/EnigmaLicenseManager/ (Linux & Windows).
    public static string GetConfigFilePath()
    {
        var configDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".config", "EnigmaLicenseManager");
        return Path.Combine(configDir, "config.json");
    }

    public static void EnsureConfigFileExists(string path)
    {
        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        if (!File.Exists(path))
        {
            File.WriteAllText(path, """
                {
                  "DefaultPaths": {
                    "Keys": "",
                    "Licenses": "",
                    "Theme": "Dark"
                  }
                }
                """);
        }
    }

    /// <summary>
    /// Persists the chosen theme ("Dark" / "Light") to the config file, preserving all other settings.
    /// </summary>
    public static void SaveTheme(string theme)
    {
        var path = GetConfigFilePath();
        EnsureConfigFileExists(path);

        JsonObject root;
        try
        {
            root = JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? new JsonObject();
        }
        catch (JsonException)
        {
            root = new JsonObject();
        }

        if (root[DefaultPathsOptions.SectionName] is not JsonObject defaultPaths)
        {
            defaultPaths = new JsonObject();
            root[DefaultPathsOptions.SectionName] = defaultPaths;
        }

        defaultPaths["Theme"] = theme;

        File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}
