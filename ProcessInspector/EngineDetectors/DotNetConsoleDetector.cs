using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Linq;

namespace ProcessInspector.EngineDetectors
{
    public class DotNetConsoleDetector : BaseEngineDetector
    {
        // Known .NET Framework DLL hashes (MD5)
        private static readonly Dictionary<string, string> DotNetFileHashes = new Dictionary<string, string>
        {
            ["FF5B3E7EB7D55896F9C38BB39E317148"] = ".NET Framework 4.8",
            ["B6EBF712D3D99EF9D1466D5CB0181B81"] = ".NET Framework 4.7.2",
            ["9C815E1AC12F8B1F7658BF964B8D16C6"] = ".NET Framework 4.7.1",
            ["3C356F91BB0F7371E8F5E927C993C62A"] = ".NET Framework 4.7",
            ["AD2E168F248C8DF2344D84A1D31477D1"] = ".NET Framework 4.6.2",
            ["7B691B3E3695EDC5D82877DFA5F8EDFC"] = ".NET Framework 4.6.1",
            ["2FE7F7D5F27B23320F3EDB9C5E3AA0E3"] = ".NET Framework 4.6",
            ["7F208D8EF095D246A9ED3A64CD2BD8F9"] = ".NET Framework 4.5.2",
            ["97EE3190E064682C9C98B6C34D2F62E3"] = ".NET Framework 4.5.1",
            ["8A3C28AE268BF91E8B128E6BAE35D7E4"] = ".NET Framework 4.5",
            ["E7FADE13C3D3E9F554180FADCD3882FB"] = ".NET Framework 4.0"
        };

        // Self-contained deployment signatures - files that indicate a self-contained .NET app
        private static readonly string[] SelfContainedSignatureFiles = new string[]
        {
            "hostfxr.dll",
            "hostpolicy.dll",
            "sni.dll", 
            "coreclr.dll",
            "clrjit.dll",
            "dbgshim.dll",
            "mscordaccore.dll",
            "mscordbi.dll",
            "clrcompression.dll"
        };

        // Regex patterns for .NET detection in file content
        private static readonly Dictionary<string, Regex> DotNetPatterns = new Dictionary<string, Regex>
        {
            ["ConsoleApp"] = new Regex(@"System\.Console\.", RegexOptions.Compiled),
            ["Framework"] = new Regex(@"using System;|\.NET Framework|mscorlib\.dll", RegexOptions.Compiled),
            ["CSharp"] = new Regex(@"csc\.exe|csc\.dll|\.csproj", RegexOptions.Compiled),
            ["DotNetHeader"] = new Regex(@"#!\s*/usr/bin/env\s+dotnet", RegexOptions.Compiled),
            ["ConsoleWrite"] = new Regex(@"Console\.Write(?:Line)?", RegexOptions.Compiled),
            ["ConsoleRead"] = new Regex(@"Console\.Read(?:Line|Key)?", RegexOptions.Compiled),
            ["CommandLineArgs"] = new Regex(@"CommandLine(?:Parser|Arguments)|Args\[", RegexOptions.Compiled),
            ["SelfContained"] = new Regex(@"PublishSingleFile|SelfContained\s*=\s*true|PublishTrimmed", RegexOptions.Compiled),
            ["DependencyIsolation"] = new Regex(@"RuntimeIdentifier|RuntimeIdentifiers|RID|win-x64|linux-x64|osx-x64", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return ".NET Console Application";
        }

        public override double DetectEngineProbability(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return 0.0;

            try
            {
                double score = 0.0;
                string folder = Path.GetDirectoryName(exePath);

                // Self-contained app detection (first, as it's more specific)
                double selfContainedScore = DetectSelfContainedApp(exePath, folder);
                if (selfContainedScore > 0)
                {
                    score += selfContainedScore;
                }
                else
                {
                    // Standard .NET Framework detection
                    score += DetectByHash(exePath, folder);
                }
                
                // Directory structure and file analysis
                score += AnalyzeDirectory(folder);

                // Process modules analysis
                int? processId = GetProcessIdByExecutablePath(exePath);
                if (processId.HasValue)
                {
                    score += AnalyzeProcessModules(processId.Value);
                }

                // Content-based detection
                score += ScanForDotNetSignatures(folder, exePath);

                // Check for competing frameworks or engines
                score -= CheckForCompetingFrameworks(folder, exePath);

                // Check executable file size for self-contained apps
                if (IsPotentiallySelfContainedBySize(exePath))
                {
                    score += 1.5;
                }

                // Normalize score as a probability between 0.0 and 1.0
                return Math.Min(score / 10.0, 1.0);
            }
            catch
            {
                return 0.0;
            }
        }

        private double DetectSelfContainedApp(string exePath, string folder)
        {
            double score = 0.0;

            try
            {
                // Check for self-contained .NET app signatures
                int selfContainedSignaturesFound = 0;
                foreach (var signatureFile in SelfContainedSignatureFiles)
                {
                    if (File.Exists(Path.Combine(folder, signatureFile)))
                    {
                        selfContainedSignaturesFound++;
                        score += 0.5;
                    }
                }

                // If we found many signature files, this is very likely a self-contained app
                if (selfContainedSignaturesFound >= 3)
                {
                    score += 2.0; // Additional boost
                }

                // Check for single file deployment patterns in executable size
                if (IsPotentiallySelfContainedBySize(exePath))
                {
                    // If the exe is large, it might be a single-file published app
                    score += 1.0;
                    
                    // Check for .NET Core/5+ headers in the executable
                    if (HasDotNetCoreHeaders(exePath))
                    {
                        score += 2.0;
                    }
                }

                // Look for .deps.json or .runtimeconfig.json in the same folder
                // These can exist even with self-contained apps
                if (Directory.GetFiles(folder, "*.deps.json").Length > 0 ||
                    Directory.GetFiles(folder, "*.runtimeconfig.json").Length > 0)
                {
                    score += 1.5;
                }

                // Check for app.deps.json which often occurs with self-contained apps
                string appName = Path.GetFileNameWithoutExtension(exePath);
                if (File.Exists(Path.Combine(folder, $"{appName}.deps.json")))
                {
                    score += 1.0;
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return Math.Min(score, 6.0); // Cap at 6.0
        }

        private bool IsPotentiallySelfContainedBySize(string exePath)
        {
            try
            {
                // Self-contained apps are typically much larger than regular .NET exes
                // Single-file published apps are often 20MB+
                var fileInfo = new FileInfo(exePath);
                long sizeMB = fileInfo.Length / (1024 * 1024);
                
                return sizeMB >= 10; // 10MB+ suggests a self-contained app
            }
            catch
            {
                return false;
            }
        }

        private bool HasDotNetCoreHeaders(string exePath)
        {
            try
            {
                // Simplified check for .NET Core/5+ headers in a binary file
                // This helps identify self-contained apps created with newer .NET versions
                byte[] buffer = new byte[Math.Min(4 * 1024 * 1024, new FileInfo(exePath).Length)]; // Read max 4MB
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Read(buffer, 0, buffer.Length);
                }
                
                string content = System.Text.Encoding.ASCII.GetString(buffer);
                return content.Contains("Microsoft.NETCore.App") || 
                       content.Contains("System.Runtime") ||
                       content.Contains("hostfxr") ||
                       content.Contains("hostpolicy") ||
                       content.Contains("netstandard") ||
                       content.Contains(".NET Core") ||
                       content.Contains(".NET 5.0") ||
                       content.Contains(".NET 6.0") ||
                       content.Contains(".NET 7.0") ||
                       content.Contains(".NET 8.0");
            }
            catch
            {
                return false;
            }
        }

        private double DetectByHash(string exePath, string folder)
        {
            double score = 0.0;

            try
            {
                // Look for .NET Framework DLLs
                var dotNetDlls = Directory.GetFiles(folder, "*.dll", SearchOption.AllDirectories)
                    .Where(f => Path.GetFileName(f).ToLower() == "mscorlib.dll" || 
                                Path.GetFileName(f).ToLower() == "system.dll" || 
                                Path.GetFileName(f).ToLower() == "system.core.dll")
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var dllPath in dotNetDlls)
                {
                    string hash = CalculateMD5Hash(dllPath);
                    if (DotNetFileHashes.ContainsKey(hash))
                    {
                        score += 3.0; // Strong evidence
                    }
                    else if (Path.GetFileName(dllPath).ToLower() == "mscorlib.dll")
                    {
                        // Any mscorlib.dll is good evidence
                        score += 2.0;
                    }
                    else
                    {
                        score += 1.0;
                    }
                }

                // Check if the executable has a .NET PE header
                if (HasDotNetPeHeader(exePath))
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

        private bool HasDotNetPeHeader(string exePath)
        {
            try
            {
                // A more accurate check would use proper PE parsing
                // This is a simplified check for the "MSIL" string in the executable
                byte[] buffer = new byte[Math.Min(1024 * 1024, new FileInfo(exePath).Length)]; // Read max 1MB
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Read(buffer, 0, buffer.Length);
                }
                
                string fileContent = System.Text.Encoding.ASCII.GetString(buffer);
                
                return fileContent.Contains("mscoree.dll") || fileContent.Contains("mscorlib") || 
                       fileContent.Contains("System.Console") || fileContent.Contains(".NET Framework") ||
                       fileContent.Contains("MSIL") || fileContent.Contains("System.Runtime") ||
                       fileContent.Contains("hostfxr.dll") || fileContent.Contains("Microsoft.NETCore");
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
                // Check for .NET-specific files
                if (Directory.GetFiles(folder, "*.pdb").Length > 0)
                {
                    score += 1.0; // PDB files often indicate .NET
                }

                if (Directory.GetFiles(folder, "*.exe.config").Length > 0)
                {
                    score += 1.5; // App.config files are very common in .NET Framework
                }

                // Self-contained app patterns - looking for large numbers of DLLs
                int dllCount = Directory.GetFiles(folder, "*.dll").Length;
                if (dllCount > 30) // Self-contained apps often have many DLLs
                {
                    score += 2.0;
                    
                    // Look for System.*.dll files which are common in self-contained apps
                    int systemDllCount = Directory.GetFiles(folder, "System.*.dll").Length;
                    if (systemDllCount > 10)
                    {
                        score += 1.0; // Even stronger evidence
                    }
                }

                // Check for VS project files
                if (Directory.GetFiles(folder, "*.csproj", SearchOption.AllDirectories).Length > 0)
                {
                    score += 1.0;
                    
                    // Look for self-contained publish options in project files
                    var projectFiles = Directory.GetFiles(folder, "*.csproj", SearchOption.AllDirectories);
                    foreach (var projectFile in projectFiles)
                    {
                        string content = File.ReadAllText(projectFile);
                        if (content.Contains("<SelfContained>true</SelfContained>") ||
                            content.Contains("<PublishSingleFile>true</PublishSingleFile>") ||
                            content.Contains("<PublishTrimmed>true</PublishTrimmed>") ||
                            content.Contains("<RuntimeIdentifier>"))
                        {
                            score += 1.5; // Strong indicator of self-contained publishing intent
                        }
                    }
                }
                
                if (Directory.GetFiles(folder, "*.sln", SearchOption.AllDirectories).Length > 0)
                {
                    score += 0.5;
                }

                // Check for assemblies likely to be used in console apps
                string[] consoleDlls = {
                    "System.Console.dll",
                    "System.CommandLine.dll",
                    "CommandLine.dll",
                    "ConsoleTables.dll",
                    "Colorful.Console.dll",
                    "Spectre.Console.dll"
                };

                foreach (var dll in consoleDlls)
                {
                    if (Directory.GetFiles(folder, dll, SearchOption.AllDirectories).Length > 0)
                    {
                        score += 0.5;
                    }
                }

                // Check for .NET Core configuration files which might be present in self-contained apps
                if (Directory.GetFiles(folder, "*.runtimeconfig.json").Length > 0)
                {
                    score += 1.0;
                }
                
                if (Directory.GetFiles(folder, "*.deps.json").Length > 0)
                {
                    score += 1.0;
                }
            }
            catch
            {
                // Ignore directory access errors
            }

            return Math.Min(score, 6.0); // Increased cap for self-contained detection
        }

        private double AnalyzeProcessModules(int processId)
        {
            double score = 0.0;

            try
            {
                var process = Process.GetProcessById(processId);
                bool hasSelfContainedModules = false;
                
                foreach (ProcessModule module in process.Modules)
                {
                    string moduleName = module.ModuleName.ToLower();
                    
                    // Check for .NET-specific modules
                    if (moduleName == "mscorlib.dll" || 
                        moduleName == "clr.dll" || 
                        moduleName == "system.dll" ||
                        moduleName == "system.core.dll")
                    {
                        score += 1.0;
                    }
                    else if (moduleName.StartsWith("system.") || 
                             moduleName.Contains(".ni.") || // Native Image cache
                             moduleName.Contains("jit"))
                    {
                        score += 0.5;
                    }
                    
                    // Self-contained .NET Core/5+ app modules
                    if (moduleName == "hostfxr.dll" || 
                        moduleName == "hostpolicy.dll" || 
                        moduleName == "coreclr.dll" ||
                        moduleName == "clrjit.dll")
                    {
                        score += 1.0;
                        hasSelfContainedModules = true;
                    }
                }
                
                // Extra boost for having self-contained deployment modules
                if (hasSelfContainedModules)
                {
                    score += 2.0;
                }
            }
            catch
            {
                // Ignore process access errors
            }

            return Math.Min(score, 4.0); // Cap at 4.0
        }

        private double ScanForDotNetSignatures(string folder, string exePath)
        {
            double score = 0.0;

            try
            {
                // Scan the executable
                if (File.Exists(exePath))
                {
                    // For self-contained apps, the exe might be large, so limit scanning to avoid performance issues
                    if (new FileInfo(exePath).Length > 20 * 1024 * 1024) // > 20MB, likely self-contained
                    {
                        // Scan just the beginning and end of the file which often contain metadata
                        score += ScanLargeExecutable(exePath);
                    }
                    else
                    {
                        score += ScanFileForEnginePatterns(exePath, DotNetPatterns);
                    }
                }

                // Scan for source code files that might be included
                var sourceFiles = Directory.GetFiles(folder, "*.cs", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "Program.cs", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(folder, "*.vb", SearchOption.AllDirectories))
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var sourceFile in sourceFiles)
                {
                    if (Path.GetFileName(sourceFile).Equals("Program.cs", StringComparison.OrdinalIgnoreCase))
                    {
                        score += 1.0; // Classic console app entry point
                    }
                    
                    score += 0.5 * ScanFileForEnginePatterns(sourceFile, DotNetPatterns);
                }

                // Check if assembly info mentions Console application
                var assemblyFiles = Directory.GetFiles(folder, "AssemblyInfo.cs", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var assemblyFile in assemblyFiles)
                {
                    if (File.ReadAllText(assemblyFile).Contains("Console"))
                    {
                        score += 0.5;
                    }
                }

                // Check publish profiles and project files for self-contained deployment options
                var publishProfiles = Directory.GetFiles(folder, "*.pubxml", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE);
                
                foreach (var profileFile in publishProfiles)
                {
                    string content = File.ReadAllText(profileFile);
                    if (content.Contains("<SelfContained>true</SelfContained>") ||
                        content.Contains("<PublishSingleFile>true</PublishSingleFile>"))
                    {
                        score += 1.5; // Strong evidence of self-contained app
                    }
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return Math.Min(score, 5.0); // Cap at 5.0
        }

        private double ScanLargeExecutable(string exePath)
        {
            double score = 0.0;
            
            try
            {
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    // Scan first 1MB
                    byte[] headerBytes = new byte[Math.Min(1024 * 1024, fs.Length)];
                    fs.Read(headerBytes, 0, headerBytes.Length);
                    string headerContent = System.Text.Encoding.ASCII.GetString(headerBytes);
                    
                    // Look for .NET signatures in header
                    if (headerContent.Contains("mscorlib") || 
                        headerContent.Contains("System.Console") ||
                        headerContent.Contains("mscoree.dll") ||
                        headerContent.Contains(".NET Framework") ||
                        headerContent.Contains("MSIL"))
                    {
                        score += 2.0;
                    }
                    
                    // Check for .NET Core/5+ signatures
                    if (headerContent.Contains("Microsoft.NETCore.App") ||
                        headerContent.Contains("System.Runtime") ||
                        headerContent.Contains(".NET Core") ||
                        headerContent.Contains("coreclr") ||
                        headerContent.Contains("hostfxr"))
                    {
                        score += 2.0;
                    }
                    
                    // Check for "dotnet" strings which often appear in single-file apps
                    if (headerContent.Contains("dotnet.exe") ||
                        headerContent.Contains("/dotnet") ||
                        headerContent.Contains("dotnet publish"))
                    {
                        score += 1.0;
                    }
                    
                    // Check end of file if it's large enough
                    if (fs.Length > 2 * 1024 * 1024) // > 2MB
                    {
                        fs.Seek(-1024 * 1024, SeekOrigin.End);
                        byte[] footerBytes = new byte[1024 * 1024];
                        fs.Read(footerBytes, 0, footerBytes.Length);
                        string footerContent = System.Text.Encoding.ASCII.GetString(footerBytes);
                        
                        // Look for embedded resource signatures often found at the end of self-contained apps
                        if (footerContent.Contains(".resources") ||
                            footerContent.Contains(".pdb") ||
                            footerContent.Contains(".dll") ||
                            footerContent.Contains("System."))
                        {
                            score += 1.0;
                        }
                    }
                }
            }
            catch
            {
                // Ignore file access errors
            }
            
            return score;
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
                    "Avalonia.dll",         // Avalonia UI
                    "Xamarin.Forms.Core.dll", // Xamarin
                    "Microsoft.AspNetCore.dll" // ASP.NET Core (web)
                };

                foreach (var dll in competingDlls)
                {
                    if (Directory.GetFiles(folder, dll, SearchOption.AllDirectories).Length > 0)
                    {
                        competingScore += 1.0;
                    }
                }

                // Check exe properties
                if (HasWindowsSubsystemFlag(exePath))
                {
                    competingScore += 2.0; // Likely a GUI app
                }
                
                // For self-contained apps, many System.* DLLs doesn't necessarily mean it's not a console app
                // So we reduce the penalty if it looks like a self-contained deployment
                if (IsPotentiallySelfContainedBySize(exePath) && 
                    Directory.GetFiles(folder, "System.*.dll").Length > 20)
                {
                    competingScore -= 1.0; // Reduce the penalty
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
                byte[] fileBytes = new byte[Math.Min(1024 * 1024, new FileInfo(exePath).Length)];
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Read(fileBytes, 0, fileBytes.Length);
                }
                
                // A very simple heuristic: GUI applications often contain these strings
                string fileContent = System.Text.Encoding.ASCII.GetString(fileBytes);
                return fileContent.Contains("System.Windows.Forms") || 
                       fileContent.Contains("System.Drawing") ||
                       fileContent.Contains("PresentationCore") ||
                       fileContent.Contains("PresentationFramework");
            }
            catch
            {
                return false;
            }
        }
    }
} 