using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class UnrealEngineDetector : BaseEngineDetector
    {
        // Known Unreal Engine file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> UnrealFileHashes = new Dictionary<string, string>
        {
            ["F4EF26C7EF6D5E5E9FFF0EB02E51A972"] = "Unreal Engine 5",
            ["B936B2E1D45DB38E3670479A67E7B561"] = "Unreal Engine 4",
            ["9B92D0CAEB2E8BE1663B9EA31DA78166"] = "Unreal Engine 4.27",
            ["2BA67C0EE478ACA2D1C2D8127C751128"] = "Unreal Engine 4.26"
        };

        // Regex patterns for Unreal Engine detection in file content
        private static readonly Dictionary<string, Regex> UnrealPatterns = new Dictionary<string, Regex>
        {
            ["Unreal Engine"] = new Regex(@"Unreal Engine", RegexOptions.Compiled),
            ["Epic Games"] = new Regex(@"Epic Games", RegexOptions.Compiled),
            ["UE4"] = new Regex(@"UE4", RegexOptions.Compiled),
            ["UE5"] = new Regex(@"UE5", RegexOptions.Compiled),
            ["UObject"] = new Regex(@"UObject", RegexOptions.Compiled),
            ["GameplayStatics"] = new Regex(@"GameplayStatics", RegexOptions.Compiled),
            ["UWorld"] = new Regex(@"UWorld", RegexOptions.Compiled),
            ["UEngine"] = new Regex(@"UEngine", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "Unreal Engine";
        }

        public override double DetectEngineProbability(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return 0.0;

            try
            {
                double score = 0.0;
                string folder = Path.GetDirectoryName(exePath);

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
                score += ScanForUnrealSignatures(folder);

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
                // Look for Unreal Engine DLLs and binaries
                var unrealFiles = new List<string>();
                unrealFiles.AddRange(Directory.GetFiles(folder, "UE*.dll", SearchOption.AllDirectories));
                unrealFiles.AddRange(Directory.GetFiles(folder, "Engine.dll", SearchOption.AllDirectories));
                unrealFiles.AddRange(Directory.GetFiles(folder, "Core.dll", SearchOption.AllDirectories));
                unrealFiles.AddRange(Directory.GetFiles(folder, "CoreUObject.dll", SearchOption.AllDirectories));
                unrealFiles = unrealFiles.Take(MAX_FILES_TO_ANALYZE).ToList();

                foreach (var filePath in unrealFiles)
                {
                    string hash = CalculateMD5Hash(filePath);
                    if (UnrealFileHashes.ContainsKey(hash))
                    {
                        score += 5.0; // Strong evidence
                    }
                    else
                    {
                        // Even if not exact hash match, finding Unreal DLLs is strong evidence
                        score += 2.0;
                    }
                }

                // Check the executable itself
                string exeHash = CalculateMD5Hash(exePath);
                if (UnrealFileHashes.ContainsKey(exeHash))
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
                // Check for Unreal Engine-specific folders
                string[] unrealFolders = { 
                    "Engine",
                    "Content",
                    "Binaries",
                    "Saved",
                    "Config"
                };

                int foundFolders = 0;
                foreach (var unrealFolder in unrealFolders)
                {
                    if (Directory.Exists(Path.Combine(folder, unrealFolder)))
                    {
                        foundFolders++;
                    }
                }
                
                // If multiple Unreal folders are found, it's strong evidence
                if (foundFolders >= 3)
                {
                    score += 3.0;
                }
                else
                {
                    score += foundFolders * 0.5;
                }

                // Check for specific files
                string[] unrealFiles = {
                    "DefaultEngine.ini",
                    "DefaultGame.ini",
                    "DefaultInput.ini",
                    "BuildConfiguration.xml"
                };

                foreach (var unrealFile in unrealFiles)
                {
                    if (File.Exists(Path.Combine(folder, "Config", unrealFile)))
                    {
                        score += 0.5;
                    }
                }

                // Check for .uasset or .umap files (Unreal asset files)
                var assetFiles = Directory.GetFiles(folder, "*.uasset", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "*.umap", SearchOption.AllDirectories))
                    .Take(5);
                
                if (assetFiles.Any())
                {
                    score += 2.0;
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
                    
                    // Check for Unreal Engine-specific modules
                    if (moduleName.Contains("core.dll") || 
                        moduleName.Contains("engine.dll") || 
                        moduleName.Contains("unrealengine") ||
                        moduleName.Contains("coreuobject") ||
                        moduleName.StartsWith("ue4") ||
                        moduleName.StartsWith("ue5"))
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

        private double ScanForUnrealSignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan executable and config folders
                var filesToScan = new List<string>();
                
                // Add executable
                string[] exeFiles = Directory.GetFiles(folder, "*.exe");
                filesToScan.AddRange(exeFiles);
                
                // Add config files
                string configFolder = Path.Combine(folder, "Config");
                if (Directory.Exists(configFolder))
                {
                    filesToScan.AddRange(Directory.GetFiles(configFolder, "*.ini", SearchOption.TopDirectoryOnly));
                }
                
                // Look for log files which often contain engine identifiers
                string logsFolder = Path.Combine(folder, "Saved", "Logs");
                if (Directory.Exists(logsFolder))
                {
                    filesToScan.AddRange(Directory.GetFiles(logsFolder, "*.log", SearchOption.TopDirectoryOnly).Take(5));
                }
                
                // Scan limited number of files
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, UnrealPatterns);
                }
            }
            catch
            {
                // Ignore scanning errors
            }

            return Math.Min(score, 3.0); // Cap at 3.0
        }
    }
} 