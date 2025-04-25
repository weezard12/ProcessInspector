using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class GodotEngineDetector : BaseEngineDetector
    {
        // Known Godot Engine file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> GodotFileHashes = new Dictionary<string, string>
        {
            ["27FDC21D1F2BC499EC6E577DD166E48C"] = "Godot Engine (4.x)",
            ["C2E4931C3E706860E4F9FB7D9C4C3B67"] = "Godot Engine (3.x)",
            ["8B9C6878507D4D60BF3C3D7C42F374C2"] = "Godot Engine (3.5.x)",
            ["F2C940D2F37A92C86F3C5516C33AB1D2"] = "Godot Engine (3.4.x)"
        };

        // Regex patterns for Godot Engine detection in file content
        private static readonly Dictionary<string, Regex> GodotPatterns = new Dictionary<string, Regex>
        {
            ["GodotEngine"] = new Regex(@"Godot Engine", RegexOptions.Compiled),
            ["godot::"] = new Regex(@"godot::", RegexOptions.Compiled),
            ["_ready()"] = new Regex(@"_ready\(\)", RegexOptions.Compiled),
            ["Node2D"] = new Regex(@"Node2D", RegexOptions.Compiled),
            ["extends"] = new Regex(@"extends\s+(Node|Spatial|Control)", RegexOptions.Compiled),
            ["get_node"] = new Regex(@"get_node\(", RegexOptions.Compiled),
            ["project.godot"] = new Regex(@"project\.godot", RegexOptions.Compiled),
            ["engine.cfg"] = new Regex(@"engine\.cfg", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "Godot Engine";
        }

        public override double DetectEngineProbability(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return 0.0;

            try
            {
                double score = 0.0;
                string folder = Path.GetDirectoryName(exePath);

                // First check if this might be a packed binary or .NET application
                if (IsPotentiallyPackedDotNetApp(exePath))
                {
                    // Apply stricter detection criteria for packed apps
                    if (!HasDefinitiveGodotEvidence(folder))
                    {
                        // Lower the base score for potentially packed apps
                        // unless we have definitive Godot evidence
                        return 0.0;
                    }
                }

                // Hash-based detection (strongest evidence)
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
                score += ScanForGodotSignatures(folder);
                
                // Check for evidence that contradicts Godot detection
                double conflictScore = CheckForConflictingEvidence(exePath, folder);
                score = Math.Max(0, score - conflictScore);

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
                // Look for Godot Engine files
                var godotFiles = new List<string>();
                godotFiles.AddRange(Directory.GetFiles(folder, "libgodot*.dll", SearchOption.AllDirectories));
                godotFiles.AddRange(Directory.GetFiles(folder, "godot*.dll", SearchOption.AllDirectories));
                godotFiles.AddRange(Directory.GetFiles(folder, "*.pck", SearchOption.TopDirectoryOnly)); // Godot PCK files
                godotFiles = godotFiles.Take(MAX_FILES_TO_ANALYZE).ToList();

                foreach (var filePath in godotFiles)
                {
                    string hash = CalculateMD5Hash(filePath);
                    if (GodotFileHashes.ContainsKey(hash))
                    {
                        score += 5.0; // Strong evidence
                    }
                    else
                    {
                        // Even if not exact hash match, finding Godot files is good evidence
                        score += 2.0;
                    }
                }

                // Check the executable itself
                string exeHash = CalculateMD5Hash(exePath);
                if (GodotFileHashes.ContainsKey(exeHash))
                {
                    score += 5.0;
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return score;
        }

        private double AnalyzeDirectory(string folder)
        {
            double score = 0.0;

            try
            {
                // Check for Godot Engine-specific files
                string[] godotFiles = { 
                    "project.godot",
                    "engine.cfg", // For older Godot versions
                    "project.binary", // Binary project files
                    "default_env.tres",
                    "icon.png"
                };

                foreach (var godotFile in godotFiles)
                {
                    if (File.Exists(Path.Combine(folder, godotFile)))
                    {
                        score += 1.0;
                    }
                }

                // Check for .tscn (scene) and .tres (resource) files - very specific to Godot
                var sceneFiles = Directory.GetFiles(folder, "*.tscn", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "*.tres", SearchOption.AllDirectories))
                    .Take(10);
                
                if (sceneFiles.Any())
                {
                    score += 3.0;
                }

                // Check for Godot-specific folders
                string[] godotFolders = { 
                    ".import", // Godot's import cache folder
                    "addons" // Godot plugins folder
                };

                foreach (var godotFolder in godotFolders)
                {
                    if (Directory.Exists(Path.Combine(folder, godotFolder)))
                    {
                        score += 1.0;
                    }
                }
            }
            catch
            {
                // Ignore directory access errors
            }

            return score;
        }

        private double AnalyzeProcessModules(int processId)
        {
            double score = 0.0;

            try
            {
                var process = System.Diagnostics.Process.GetProcessById(processId);
                
                foreach (System.Diagnostics.ProcessModule module in process.Modules)
                {
                    string moduleName = module.ModuleName.ToLower();
                    
                    // Check for Godot Engine-specific modules
                    if (moduleName.Contains("godot") || 
                        moduleName.Contains("libgodot"))
                    {
                        score += 0.5;
                    }
                }
            }
            catch
            {
                // Ignore process access errors
            }

            return Math.Min(score, 3.0); // Cap at 3.0
        }

        private double ScanForGodotSignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan for Godot-specific files
                var filesToScan = new List<string>();
                
                // Add executable
                string[] exeFiles = Directory.GetFiles(folder, "*.exe");
                filesToScan.AddRange(exeFiles);
                
                // Add Godot project files
                string projectFile = Path.Combine(folder, "project.godot");
                if (File.Exists(projectFile))
                {
                    filesToScan.Add(projectFile);
                }
                
                // Add scene files (sample a few)
                filesToScan.AddRange(Directory.GetFiles(folder, "*.tscn", SearchOption.AllDirectories).Take(5));
                
                // Add GDScript files
                filesToScan.AddRange(Directory.GetFiles(folder, "*.gd", SearchOption.AllDirectories).Take(10));
                
                // Scan limited number of files
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, GodotPatterns);
                }
            }
            catch
            {
                // Ignore scanning errors
            }

            return Math.Min(score, 3.0); // Cap at 3.0
        }

        /// <summary>
        /// Checks if the executable appears to be a packed or obfuscated .NET application
        /// </summary>
        private bool IsPotentiallyPackedDotNetApp(string exePath)
        {
            try
            {
                var fileInfo = new FileInfo(exePath);
                
                // Check file size - self-contained .NET apps or packed apps are typically larger
                bool isSuspiciousSize = fileInfo.Length > 5 * 1024 * 1024; // > 5MB is suspicious
                
                // Look for .NET metadata in the file
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] buffer = new byte[Math.Min(4096, fs.Length)];
                    fs.Read(buffer, 0, buffer.Length);
                    
                    // Convert to string to look for .NET indicators
                    string headerContent = System.Text.Encoding.ASCII.GetString(buffer);
                    
                    // Check for .NET metadata indicators
                    bool hasDotNetIndicators = headerContent.Contains("mscoree") || 
                                              headerContent.Contains("System.Runtime") ||
                                              headerContent.Contains("mscorlib");
                    
                    // Look for packer signatures in the header
                    bool hasPackerSignatures = headerContent.Contains("UPX") ||
                                              headerContent.Contains("Enigma") ||
                                              headerContent.Contains("Obfuscated") ||
                                              headerContent.Contains("Protected") ||
                                              headerContent.Contains("packed");
                    
                    return (isSuspiciousSize && hasDotNetIndicators) || hasPackerSignatures;
                }
            }
            catch
            {
                // If we can't analyze, assume it's not a packed .NET app
                return false;
            }
        }

        /// <summary>
        /// Checks for definitive Godot evidence - used to validate when we suspect a packed binary
        /// </summary>
        private bool HasDefinitiveGodotEvidence(string folder)
        {
            try
            {
                // These are 100% Godot-specific files that wouldn't exist in non-Godot projects
                string[] definitiveFiles = {
                    "project.godot",
                    "engine.cfg",
                    // Godot 4.x specific file
                    ".godot/editor/project_metadata.cfg"
                };
                
                foreach (var file in definitiveFiles)
                {
                    if (File.Exists(Path.Combine(folder, file)))
                    {
                        return true;
                    }
                }
                
                // Check for PCK files which are Godot-specific resource packs
                if (Directory.GetFiles(folder, "*.pck").Length > 0)
                {
                    return true;
                }
                
                // Check for scene files which are Godot-specific
                if (Directory.GetFiles(folder, "*.tscn", SearchOption.AllDirectories).Length > 0)
                {
                    return true;
                }
                
                // Check for GDScript files which are Godot-specific
                if (Directory.GetFiles(folder, "*.gd", SearchOption.AllDirectories).Length > 0)
                {
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks for evidence that contradicts a Godot engine identification
        /// </summary>
        private double CheckForConflictingEvidence(string exePath, string folder)
        {
            double conflictScore = 0.0;
            
            try
            {
                // Check for .NET-specific files that would indicate a console app rather than Godot
                string[] dotNetFiles = {
                    "*.runtimeconfig.json",    // .NET Core/5+ config
                    "*.deps.json",             // .NET dependencies
                    "appsettings.json",        // ASP.NET or console app settings
                    "App.config",              // .NET Framework config
                    "packages.config"          // NuGet packages
                };
                
                foreach (var pattern in dotNetFiles)
                {
                    int fileCount = Directory.GetFiles(folder, pattern, SearchOption.TopDirectoryOnly).Length;
                    if (fileCount > 0)
                    {
                        conflictScore += fileCount * 1.0; // Each file adds to conflict score
                    }
                }
                
                // Check for typical .NET libraries that aren't used in Godot
                string[] nonGodotLibraries = {
                    "System.Console.dll",
                    "CommandLine.dll",          // Common console app library
                    "Microsoft.Extensions.Configuration.dll",
                    "Microsoft.Extensions.Hosting.dll",
                    "Newtonsoft.Json.dll"       // Very common in .NET apps but rarely in Godot
                };
                
                foreach (var lib in nonGodotLibraries)
                {
                    if (Directory.GetFiles(folder, lib, SearchOption.AllDirectories).Length > 0)
                    {
                        conflictScore += 1.0;
                    }
                }
                
                // Look for Windows Forms or WPF libraries which conflict with Godot
                string[] guiLibraries = {
                    "System.Windows.Forms.dll", 
                    "PresentationCore.dll",
                    "PresentationFramework.dll"
                };
                
                foreach (var lib in guiLibraries)
                {
                    if (Directory.GetFiles(folder, lib, SearchOption.AllDirectories).Length > 0)
                    {
                        conflictScore += 2.0; // Stronger evidence against Godot
                    }
                }
                
                // Check for csproj files with no Godot references
                var csprojFiles = Directory.GetFiles(folder, "*.csproj", SearchOption.AllDirectories);
                foreach (var csprojFile in csprojFiles)
                {
                    string content = File.ReadAllText(csprojFile);
                    if (!content.Contains("Godot") && !content.Contains("godot"))
                    {
                        // Project file with no Godot references is strong evidence against
                        conflictScore += 2.0;
                    }
                }
                
                // Check for common command-line argument patterns in binary
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] buffer = new byte[Math.Min(1024 * 1024, fs.Length)];
                    fs.Read(buffer, 0, buffer.Length);
                    string content = System.Text.Encoding.ASCII.GetString(buffer);
                    
                    // Common console app patterns
                    if (content.Contains("--help") && content.Contains("-h") && 
                        content.Contains("--version") && content.Contains("-v"))
                    {
                        conflictScore += 1.5; // CLI argument pattern
                    }
                    
                    // Check for Console.WriteLine/ReadLine which are very unlikely in Godot games
                    if (content.Contains("Console.WriteLine") || content.Contains("Console.ReadLine"))
                    {
                        conflictScore += 2.0;
                    }
                }
            }
            catch
            {
                // Ignore errors
            }
            
            return Math.Min(conflictScore, 10.0); // Cap the conflict score at 10.0
        }
    }
} 