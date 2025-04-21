using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class MonoGameDetector : BaseEngineDetector
    {
        // Known MonoGame file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> MonoGameFileHashes = new Dictionary<string, string>
        {
            ["A4F7ECDE72A79B2C0C582A0FC1F0D3E8"] = "MonoGame (3.8.x)",
            ["7F5E7A16E1A02E85CEEFF5D92899F0F3"] = "MonoGame (3.7.x)",
            ["B689FD01CE67A23E46962DA8F8F798C5"] = "MonoGame (3.6.x)"
        };

        // Regex patterns for MonoGame detection in file content
        private static readonly Dictionary<string, Regex> MonoGamePatterns = new Dictionary<string, Regex>
        {
            ["MonoGame"] = new Regex(@"MonoGame", RegexOptions.Compiled),
            ["Microsoft.Xna"] = new Regex(@"Microsoft\.Xna", RegexOptions.Compiled),
            ["GameTime"] = new Regex(@"GameTime", RegexOptions.Compiled),
            ["SpriteBatch"] = new Regex(@"SpriteBatch", RegexOptions.Compiled),
            ["ContentManager"] = new Regex(@"ContentManager", RegexOptions.Compiled),
            ["Game1"] = new Regex(@"class\s+Game1\s+:\s+Game", RegexOptions.Compiled),
            ["LoadContent"] = new Regex(@"LoadContent\(\)", RegexOptions.Compiled),
            ["XnbContent"] = new Regex(@"\.xnb", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "MonoGame";
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
                score += ScanForMonoGameSignatures(folder);

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
                // Look for MonoGame DLLs
                var monoGameFiles = new List<string>();
                monoGameFiles.AddRange(Directory.GetFiles(folder, "MonoGame*.dll", SearchOption.AllDirectories));
                monoGameFiles.AddRange(Directory.GetFiles(folder, "Microsoft.Xna*.dll", SearchOption.AllDirectories));
                monoGameFiles = monoGameFiles.Take(MAX_FILES_TO_ANALYZE).ToList();

                foreach (var filePath in monoGameFiles)
                {
                    string hash = CalculateMD5Hash(filePath);
                    if (MonoGameFileHashes.ContainsKey(hash))
                    {
                        score += 5.0; // Strong evidence
                    }
                    else
                    {
                        // Even if not exact hash match, finding MonoGame DLLs is strong evidence
                        score += 2.0;
                    }
                }

                // Check the executable itself
                string exeHash = CalculateMD5Hash(exePath);
                if (MonoGameFileHashes.ContainsKey(exeHash))
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
                // Check for MonoGame-specific folders
                string[] monoGameFolders = { 
                    "Content",
                    "Effects",
                    "Graphics",
                    "Pipeline"
                };

                foreach (var monoGameFolder in monoGameFolders)
                {
                    if (Directory.Exists(Path.Combine(folder, monoGameFolder)))
                    {
                        score += 0.5;
                    }
                }

                // Check for .xnb files (MonoGame content)
                var xnbFiles = Directory.GetFiles(folder, "*.xnb", SearchOption.AllDirectories).Take(10);
                if (xnbFiles.Any())
                {
                    score += 2.0;
                }

                // Check for MonoGame config files
                string[] configFiles = {
                    "Content.mgcb",
                    ".mgcontent",
                    ".mgstats"
                };

                foreach (var configFile in configFiles)
                {
                    var files = Directory.GetFiles(folder, configFile, SearchOption.AllDirectories).Take(5);
                    if (files.Any())
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
                    
                    // Check for MonoGame-specific modules
                    if (moduleName.Contains("monogame") || 
                        moduleName.Contains("microsoft.xna"))
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

        private double ScanForMonoGameSignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan executable and source files
                var filesToScan = new List<string>();
                
                // Add executable
                string[] exeFiles = Directory.GetFiles(folder, "*.exe");
                filesToScan.AddRange(exeFiles);
                
                // Add C# source files that might contain MonoGame code
                filesToScan.AddRange(Directory.GetFiles(folder, "*.cs", SearchOption.AllDirectories)
                    .Where(f => !f.Contains("\\obj\\") && !f.Contains("\\bin\\"))
                    .Take(20));
                
                // Add config files
                filesToScan.AddRange(Directory.GetFiles(folder, "*.csproj", SearchOption.AllDirectories).Take(5));
                filesToScan.AddRange(Directory.GetFiles(folder, "*.config", SearchOption.AllDirectories).Take(5));
                
                // Scan limited number of files
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, MonoGamePatterns);
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