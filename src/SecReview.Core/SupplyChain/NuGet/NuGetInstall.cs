using System.Globalization;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.NuGet;

/// <summary>One package source NuGet would use.</summary>
/// <param name="Name">Its name (the key).</param>
/// <param name="Address">Its address: a URL, or a folder.</param>
/// <param name="SkipsTlsChecks">Certificate checks are switched off for it.</param>
/// <param name="MinimumAgeHours">The wait before a new version is picked; null if not set or not a number.</param>
/// <param name="Source">Where it is defined, for a finding.</param>
internal sealed record NuGetSource(string Name, string Address, bool SkipsTlsChecks, long? MinimumAgeHours, string Source)
{
    /// <summary>A source on the network, as opposed to a folder on this PC.</summary>
    public bool IsRemote =>
        Address.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || Address.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    public bool IsPlainHttp => Address.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// NuGet's settings for this user outside any project: the PC-wide files and the user's,
/// merged the way NuGet merges them. NuGet is never run. A project's own <c>nuget.config</c>
/// can add to or replace these; this is the baseline.
/// </summary>
/// <param name="Sources">The enabled sources.</param>
/// <param name="HasSourceMapping">Whether packages are tied to sources by pattern.</param>
/// <param name="PlainPasswords">Sources with a password stored as plain text, with where.</param>
/// <param name="Problem">The first file that exists but could not be read or understood; null if all were.</param>
/// <param name="SdkVersion">The newest .NET SDK found; null if none is.</param>
internal sealed record NuGetInstall(
    IReadOnlyList<NuGetSource> Sources,
    bool HasSourceMapping,
    IReadOnlyList<(string SourceName, string Where)> PlainPasswords,
    string? Problem,
    ToolVersion? SdkVersion);

internal static class NuGetLocator
{
    /// <summary>The first .NET SDK whose NuGet has a wait for new versions.</summary>
    public static readonly ToolVersion CooldownFrom = new(11, 0, 100);

    /// <summary>
    /// NuGet's settings; <paramref name="nuget"/> is null when no trace of NuGet or the .NET SDK
    /// is found. Returns the outcome when something needed to tell could not be read.
    /// </summary>
    public static CheckOutcome? Locate(SystemProbes probes, out NuGetInstall? nuget)
    {
        nuget = null;
        IFileProbe files = probes.Files;
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        ProbeResult<string> programFiles = probes.Environment.Folder(KnownFolder.ProgramFiles);
        ProbeResult<string> programFilesX86 = probes.Environment.Folder(KnownFolder.ProgramFilesX86);
        if (!roaming.IsOk || !programFiles.IsOk || !programFilesX86.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        // Lowest priority first: the PC's files, the user's extra files, the user's own file.
        var paths = new List<string>();
        foreach (string folder in (string[])[$@"{programFilesX86.Value}\NuGet\Config", $@"{roaming.Value}\NuGet\config"])
        {
            ProbeResult<IReadOnlyList<FileEntry>> listed = files.List(folder);
            if (listed.IsOk)
            {
                paths.AddRange(listed.Value!
                    .Where(e => !e.IsDirectory && e.Name.EndsWith(".config", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(e => $@"{folder}\{e.Name}"));
            }
            else if (listed.Status != ProbeStatus.NotFound)
            {
                return ProbeOutcomes.FromFailure(listed, "NuGet's settings folder");
            }
        }

        // More settings files than anyone has: reading stops being cheap, and is not attempted.
        const int MostFiles = 32;
        if (paths.Count > MostFiles)
        {
            return CheckOutcome.Error($"NuGet's settings folders hold {paths.Count} files, more than are read.");
        }

        string userPath = $@"{roaming.Value}\NuGet\NuGet.Config";
        paths.Add(userPath);

        var sources = new Dictionary<string, NuGetSource>(StringComparer.OrdinalIgnoreCase);
        var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var passwords = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        bool mapping = false;
        string? problem = null;
        bool anyFile = false;
        bool userFileExists = false;

        foreach (string path in paths)
        {
            if (XmlFiles.Load(files, path) is not { } file)
            {
                continue;
            }

            anyFile = true;
            userFileExists |= path == userPath;
            if (file.Root is not { } root)
            {
                problem ??= file.Problem;
                continue;
            }

            foreach (MarkupElement section in root.Children)
            {
                switch (section.Name.ToLowerInvariant())
                {
                    case "packagesources":
                        foreach (MarkupElement item in section.Children)
                        {
                            if (IsClear(item))
                            {
                                sources.Clear();
                            }
                            else if (IsAdd(item) && item.Attribute("key") is { Length: > 0 } key && item.Attribute("value") is { } address)
                            {
                                sources[key] = new NuGetSource(
                                    key,
                                    address.Trim(),
                                    IsTrue(item.Attribute("disableTLSCertificateValidation")),
                                    long.TryParse(item.Attribute("minPublishAgeHours"), NumberStyles.None, CultureInfo.InvariantCulture, out long hours) ? hours : null,
                                    file.At(item));
                            }
                        }

                        break;

                    case "disabledpackagesources":
                        foreach (MarkupElement item in section.Children)
                        {
                            if (IsClear(item))
                            {
                                disabled.Clear();
                            }
                            else if (IsAdd(item) && item.Attribute("key") is { Length: > 0 } key && IsTrue(item.Attribute("value")))
                            {
                                disabled.Add(key);
                            }
                        }

                        break;

                    case "packagesourcemapping":
                        foreach (MarkupElement item in section.Children)
                        {
                            if (IsClear(item))
                            {
                                mapping = false;
                            }
                            else if (item.Is("packageSource") && item.ChildrenNamed("package").Any())
                            {
                                mapping = true;
                            }
                        }

                        break;

                    case "packagesourcecredentials":
                        foreach (MarkupElement source in section.Children)
                        {
                            if (IsClear(source))
                            {
                                passwords.Clear();
                                continue;
                            }

                            // The element is named after the source, with spaces and the like encoded.
                            string name = MarkupReader.DecodeName(source.Name);
                            MarkupElement? plain = source.ChildrenNamed("add").FirstOrDefault(a =>
                                string.Equals(a.Attribute("key"), "ClearTextPassword", StringComparison.OrdinalIgnoreCase) &&
                                !string.IsNullOrEmpty(a.Attribute("value")));
                            if (plain is not null)
                            {
                                passwords[name] = file.At(plain);
                            }
                            else
                            {
                                passwords.Remove(name);
                            }
                        }

                        break;
                }
            }
        }

        // The newest .NET SDK: its folder name is its version.
        ToolVersion? sdk = null;
        if (files.List($@"{programFiles.Value}\dotnet\sdk") is { IsOk: true } sdks)
        {
            sdk = sdks.Value!.Where(e => e.IsDirectory).Select(e => ToolVersion.Parse(e.Name)).Where(v => v is not null).Max();
        }

        if (!anyFile && sdk is null)
        {
            return null;
        }

        // Without the user's own file, NuGet writes one on first use, with nuget.org in it.
        if (!userFileExists && !sources.ContainsKey("nuget.org"))
        {
            sources["nuget.org"] = new NuGetSource("nuget.org", "https://api.nuget.org/v3/index.json", false, null, "NuGet's default");
        }

        nuget = new NuGetInstall(
            [.. sources.Values.Where(s => !disabled.Contains(s.Name))],
            mapping,
            [.. passwords.Select(p => (p.Key, p.Value))],
            problem,
            sdk);
        return null;
    }

    private static bool IsClear(MarkupElement element) => element.Is("clear");

    private static bool IsAdd(MarkupElement element) => element.Is("add");

    private static bool IsTrue(string? value) => string.Equals(value?.Trim(), "true", StringComparison.OrdinalIgnoreCase);
}
