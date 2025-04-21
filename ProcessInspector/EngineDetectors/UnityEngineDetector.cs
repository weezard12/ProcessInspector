using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class UnityEngineDetector : BaseEngineDetector
    {
        // Known Unity file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> UnityFileHashes = new Dictionary<string, string>
        {
            ["607A4C0356CD7CDF29594899D8C2E46D"] = "Unity Engine (2022.x)",
            ["A9721EBAA172AB24F47EF7B5272C1CB9"] = "Unity Engine (2021.x)",
            ["59C3FE609281AD35B8B3A99EFAE644D5"] = "Unity Engine (2020.x)",
            ["F3672821918F5E20A66A9F81F8AC8187"] = "Unity Engine (2019.x)",
            ["1A93C4CF91334D19B9915FE42BD0B2D5"] = "Unity Engine (2018.x)"
        };

        // Regex patterns for Unity detection in file content
        private static readonly Dictionary<string, Regex> UnityPatterns = new Dictionary<string, Regex>
        {
            ["UnityEngine"] = new Regex(@"UnityEngine", RegexOptions.Compiled),
            ["Unity Player"] = new Regex(@"Unity Player", RegexOptions.Compiled),
            ["Made with Unity"] = new Regex(@"Made with Unity", RegexOptions.Compiled),
            ["Unity Technologies"] = new Regex(@"Unity Technologies", RegexOptions.Compiled),
            ["UnityEditor"] = new Regex(@"UnityEditor", RegexOptions.Compiled),
            ["MonoBehaviour"] = new Regex(@"MonoBehaviour", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "Unity";
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
                score += ScanForUnitySignatures(folder);

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
                // Look for Unity DLLs
                var unityDlls = Directory.GetFiles(folder, "UnityEngine*.dll", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "UnityPlayer.dll", SearchOption.AllDirectories))
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var dllPath in unityDlls)
                {
                    string hash = CalculateMD5Hash(dllPath);
                    if (UnityFileHashes.ContainsKey(hash))
                    {
                        score += 5.0; // Strong evidence
                    }
                    else
                    {
                        // Even if not exact hash match, finding Unity DLLs is strong evidence
                        score += 3.0;
                    }
                }

                // Check the executable itself in case it's been built with IL2CPP
                string exeHash = CalculateMD5Hash(exePath);
                if (UnityFileHashes.ContainsKey(exeHash))
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
                // Check for Unity-specific folders
                string[] unityFolders = { 
                    "Data", 
                    "_Data", 
                    "IL2CPP_Data", 
                    "Resources"
                };

                foreach (var unityFolder in unityFolders)
                {
                    if (Directory.Exists(Path.Combine(folder, unityFolder)))
                    {
                        score += 1.0;
                    }
                }

                // Check for specific files
                string[] unityFiles = {
                    "globalgamemanagers",
                    "level0",
                    "resources.assets",
                    "sharedassets0.assets"
                };

                foreach (var unityFile in unityFiles)
                {
                    if (File.Exists(Path.Combine(folder, "Data", unityFile)) ||
                        File.Exists(Path.Combine(folder, $"{Path.GetFileNameWithoutExtension(folder)}_Data", unityFile)))
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
                    
                    // Check for Unity-specific modules
                    if (moduleName.Contains("unity") || 
                        moduleName.Contains("mono") || 
                        moduleName.StartsWith("unityplayer"))
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

        private double ScanForUnitySignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan executable and data folders
                var filesToScan = new List<string>();
                
                // Add executable
                string[] exeFiles = Directory.GetFiles(folder, "*.exe");
                filesToScan.AddRange(exeFiles);
                
                // Add data folder files
                string dataFolder = Path.Combine(folder, "Data");
                if (!Directory.Exists(dataFolder))
                {
                    string altDataFolder = Path.Combine(folder, $"{Path.GetFileNameWithoutExtension(folder)}_Data");
                    if (Directory.Exists(altDataFolder))
                    {
                        dataFolder = altDataFolder;
                    }
                }
                
                if (Directory.Exists(dataFolder))
                {
                    filesToScan.AddRange(Directory.GetFiles(dataFolder, "*.txt", SearchOption.TopDirectoryOnly));
                    filesToScan.AddRange(Directory.GetFiles(dataFolder, "*.dat", SearchOption.TopDirectoryOnly));
                    
                    // Look for Unity info files
                    string infoFile = Path.Combine(dataFolder, "app.info");
                    if (File.Exists(infoFile))
                    {
                        filesToScan.Add(infoFile);
                    }
                }
                
                // Scan limited number of files
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, UnityPatterns);
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