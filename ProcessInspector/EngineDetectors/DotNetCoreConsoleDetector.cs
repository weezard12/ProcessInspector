using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Linq;

namespace ProcessInspector.EngineDetectors
{
    public class DotNetCoreConsoleDetector : BaseEngineDetector
    {
        // Known .NET Core DLL hashes (MD5)
        private static readonly Dictionary<string, string> DotNetCoreFileHashes = new Dictionary<string, string>
        {
            ["E50BA4B77F2C02E3E6D0E29F71D88D9D"] = ".NET 6.0 Runtime",
            ["C8D59A5D9BB1D4C4B9718089EF923547"] = ".NET 5.0 Runtime",
            ["A24536090C94DFBDD61498FC943FAA8D"] = ".NET Core 3.1 Runtime",
            ["C79341FE7D3A2B91AE6D90F2AE287F3F"] = ".NET Core 3.0 Runtime",
            ["1B6B1A3B166A9BF7C2609D5F32269BFC"] = ".NET Core 2.2 Runtime",
            ["3C5F750BEC72F8F17F1CFED764C5A3C1"] = ".NET Core 2.1 Runtime",
            ["D8F46916E035B54AEB2A0D9F37C38F16"] = ".NET Core 2.0 Runtime"
        };

        // Regex patterns for .NET Core detection in file content
        private static readonly Dictionary<string, Regex> DotNetCorePatterns = new Dictionary<string, Regex>
        {
            ["CoreConsole"] = new Regex(@"System\.Console\.|Microsoft\.Extensions\.Hosting", RegexOptions.Compiled),
            ["CoreFramework"] = new Regex(@"Microsoft\.NETCore\.App|Microsoft\.AspNetCore\.App", RegexOptions.Compiled),
            ["CoreCSharp"] = new Regex(@"<TargetFramework>net\d\.\d|<TargetFramework>netcoreapp\d\.\d", RegexOptions.Compiled),
            ["CoreHeader"] = new Regex(@"#!\s*/usr/bin/env\s+dotnet", RegexOptions.Compiled),
            ["GlobalJson"] = new Regex(@"""sdk"":\s*{\s*""version"":", RegexOptions.Compiled),
            ["CoreConfigJson"] = new Regex(@"runtimeconfig\.json|deps\.json", RegexOptions.Compiled),
            ["CoreEntryPoint"] = new Regex(@"await\s+Host\.CreateDefaultBuilder|WebApplication\.Create", RegexOptions.Compiled),
            ["CoreLogger"] = new Regex(@"ILogger<|Microsoft\.Extensions\.Logging|LoggerFactory", RegexOptions.Compiled),
            ["CoreDI"] = new Regex(@"IServiceCollection|ServiceProvider|AddTransient|AddScoped|AddSingleton", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return ".NET Core/5+ Console Application";
        }

        public override double DetectEngineProbability(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return 0.0;

            try
            {
                double score = 0.0;
                string folder = Path.GetDirectoryName(exePath);

                // Hash-based detection
                score += DetectByHash(exePath, folder);
                
                // Directory structure and file analysis
                score += AnalyzeDirectory(folder);

                // Process modules analysis
                int? processId = GetProcessIdByExecutablePath(exePath);
                if (processId.HasValue)
                {
                    score += AnalyzeProcessModules(processId.Value);
                }

                // Content-based detection
                score += ScanForDotNetCoreSignatures(folder, exePath);

                // Check for competing frameworks or engines
                score -= CheckForCompetingFrameworks(folder, exePath);

                // Normalize score as a probability between 0.0 and 1.0
                return Math.Min(score / 10.0, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        private double DetectByHash(string exePath, string folder)
        {
            double score = 0.0;

            try
            {
                // Look for .NET Core runtime DLLs
                var dotNetCoreDlls = Directory.GetFiles(folder, "*.dll", SearchOption.AllDirectories)
                    .Where(f => Path.GetFileName(f).ToLower().Contains("system.runtime") || 
                                Path.GetFileName(f).ToLower().StartsWith("microsoft.netcore") ||
                                Path.GetFileName(f).ToLower().Contains("coreclr"))
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var dllPath in dotNetCoreDlls)
                {
                    string hash = CalculateMD5Hash(dllPath);
                    if (DotNetCoreFileHashes.ContainsKey(hash))
                    {
                        score += 3.0; // Strong evidence
                    }
                    else if (Path.GetFileName(dllPath).ToLower().Contains("system.runtime"))
                    {
                        // Any System.Runtime.dll is good evidence
                        score += 1.5;
                    }
                    else
                    {
                        score += 0.5;
                    }
                }

                // Check for the .NET Core header in the executable file
                if (HasDotNetCoreHeader(exePath))
                {
                    score += 4.0;
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return score;
        }

        private bool HasDotNetCoreHeader(string exePath)
        {
            try
            {
                // This is a simplified check for .NET Core executables
                byte[] fileBytes = File.ReadAllBytes(exePath);
                string fileContent = System.Text.Encoding.ASCII.GetString(fileBytes);
                
                return fileContent.Contains("Microsoft.NETCore.App") || 
                       fileContent.Contains("netcoreapp") || 
                       fileContent.Contains("System.Runtime.dll") ||
                       fileContent.Contains(".NET Core") ||
                       // .NET 5+ indicators
                       fileContent.Contains("net5.0") ||
                       fileContent.Contains("net6.0") ||
                       fileContent.Contains("net7.0") ||
                       fileContent.Contains("net8.0");
            }
            catch
            {
                return false;
            }
        }

        private double AnalyzeDirectory(string folder)
        {
            double score = 0.0;

            try
            {
                // Check for .NET Core specific files
                if (File.Exists(Path.Combine(folder, "global.json")))
                {
                    score += 2.0; // Strong indicator of .NET Core/5+
                }

                // Check for runtime config and deps files
                var runtimeConfigFiles = Directory.GetFiles(folder, "*.runtimeconfig.json");
                var depsFiles = Directory.GetFiles(folder, "*.deps.json");
                
                score += runtimeConfigFiles.Length > 0 ? 2.0 : 0.0;
                score += depsFiles.Length > 0 ? 2.0 : 0.0;

                // Check for .NET Core/5+ project files
                var projectFiles = Directory.GetFiles(folder, "*.csproj", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var projectFile in projectFiles)
                {
                    string content = File.ReadAllText(projectFile);
                    if (content.Contains("<TargetFramework>net") || 
                        content.Contains("<TargetFramework>netcoreapp") ||
                        content.Contains("<TargetFrameworks>net"))
                    {
                        score += 2.0;
                    }
                }

                // Check for assemblies likely to be used in .NET Core console apps
                string[] coreConsoleDlls = {
                    "Microsoft.Extensions.Hosting.dll",
                    "Microsoft.Extensions.Configuration.dll",
                    "Microsoft.Extensions.DependencyInjection.dll",
                    "Microsoft.Extensions.Logging.dll",
                    "System.CommandLine.dll",
                    "McMaster.Extensions.CommandLineUtils.dll",
                    "Spectre.Console.dll"
                };

                foreach (var dll in coreConsoleDlls)
                {
                    if (Directory.GetFiles(folder, dll, SearchOption.AllDirectories).Length > 0)
                    {
                        score += 0.5;
                    }
                }
            }
            catch
            {
                // Ignore directory access errors
            }

            return Math.Min(score, 5.0); // Cap at 5.0
        }

        private double AnalyzeProcessModules(int processId)
        {
            double score = 0.0;

            try
            {
                var process = Process.GetProcessById(processId);
                
                foreach (ProcessModule module in process.Modules)
                {
                    string moduleName = module.ModuleName.ToLower();
                    
                    // Check for .NET Core specific modules
                    if (moduleName.Contains("coreclr.dll") || 
                        moduleName == "hostpolicy.dll" || 
                        moduleName == "hostfxr.dll" ||
                        moduleName.Contains("system.runtime"))
                    {
                        score += 1.5;
                    }
                    else if (moduleName.StartsWith("microsoft.netcore") || 
                             moduleName.StartsWith("system.") ||
                             moduleName.StartsWith("microsoft.extensions"))
                    {
                        score += 0.5;
                    }
                }
            }
            catch
            {
                // Ignore process access errors
            }

            return Math.Min(score, 4.0); // Cap at 4.0
        }

        private double ScanForDotNetCoreSignatures(string folder, string exePath)
        {
            double score = 0.0;

            try
            {
                // Scan the executable
                if (File.Exists(exePath))
                {
                    score += ScanFileForEnginePatterns(exePath, DotNetCorePatterns);
                }

                // Scan for source code files that might be included
                var sourceFiles = Directory.GetFiles(folder, "*.cs", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "Program.cs", SearchOption.AllDirectories))
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var sourceFile in sourceFiles)
                {
                    if (Path.GetFileName(sourceFile).Equals("Program.cs", StringComparison.OrdinalIgnoreCase))
                    {
                        // Check if it's a modern .NET Core/5+ minimal hosting model
                        string content = File.ReadAllText(sourceFile);
                        if (content.Contains("CreateDefaultBuilder") || 
                            content.Contains("WebApplication.Create") || 
                            content.Contains("await Host.") ||
                            content.Contains("await WebApplication."))
                        {
                            score += 2.0; // Strong evidence of .NET Core hosting model
                        }
                        else
                        {
                            score += 0.5; // Just a generic Program.cs
                        }
                    }
                    
                    score += 0.5 * ScanFileForEnginePatterns(sourceFile, DotNetCorePatterns);
                }

                // Check config files
                var configFiles = Directory.GetFiles(folder, "appsettings.json", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var configFile in configFiles)
                {
                    score += 1.0; // appsettings.json is commonly used in .NET Core
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return Math.Min(score, 5.0); // Cap at 5.0
        }

        private double CheckForCompetingFrameworks(string folder, string exePath)
        {
            double competingScore = 0.0;
            
            try
            {
                // Check for presence of major UI frameworks or game engines
                string[] competingDlls = {
                    "UnityEngine.dll",      // Unity
                    "Godot.NET.dll",        // Godot
                    "MonoGame.Framework.dll", // MonoGame
                    "System.Windows.Forms.dll", // WinForms
                    "PresentationCore.dll", // WPF
                    "Microsoft.Xna.Framework.dll", // XNA
                    "Gtk-sharp.dll",        // GTK#
                    "Xamarin.Forms.Core.dll", // Xamarin
                    // .NET Framework specific DLLs that wouldn't be in .NET Core
                    "mscorlib.dll"
                };

                foreach (var dll in competingDlls)
                {
                    if (Directory.GetFiles(folder, dll, SearchOption.AllDirectories).Length > 0)
                    {
                        competingScore += 1.0;
                    }
                }

                // Look for ASP.NET Core indicators (not a console app, but a web app)
                var webHostingFound = Directory.GetFiles(folder, "Microsoft.AspNetCore.Hosting.dll", SearchOption.AllDirectories).Length > 0;
                var wwwrootExists = Directory.Exists(Path.Combine(folder, "wwwroot"));
                var viewsExists = Directory.Exists(Path.Combine(folder, "Views"));
                
                if (webHostingFound || wwwrootExists || viewsExists)
                {
                    competingScore += 2.0; // Likely an ASP.NET Core web app
                }
                
                // Check exe properties to see if it's a GUI app
                if (HasWindowsSubsystemFlag(exePath))
                {
                    competingScore += 2.0; // Likely a GUI app
                }
            }
            catch
            {
                // Ignore errors
            }

            return Math.Min(competingScore, 5.0); // Cap at 5.0
        }

        private bool HasWindowsSubsystemFlag(string exePath)
        {
            try
            {
                // This is a simplified check - a proper implementation would use PE header parsing
                // to check the subsystem flag (2 = GUI, 3 = Console)
                byte[] fileBytes = File.ReadAllBytes(exePath);
                
                // A very simple heuristic: GUI applications often contain these strings
                string fileContent = System.Text.Encoding.ASCII.GetString(fileBytes);
                return fileContent.Contains("System.Windows.Forms") || 
                       fileContent.Contains("System.Drawing") ||
                       fileContent.Contains("Microsoft.UI.Xaml") ||
                       fileContent.Contains("Avalonia") ||
                       fileContent.Contains("WPF");
            }
            catch
            {
                return false;
            }
        }
    }
} 