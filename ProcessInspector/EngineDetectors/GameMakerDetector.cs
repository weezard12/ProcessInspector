using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class GameMakerDetector : BaseEngineDetector
    {
        // Known GameMaker file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> GameMakerFileHashes = new Dictionary<string, string>
        {
            ["D849E115C9198C5A860C6F07A1B792DF"] = "GameMaker Studio 2",
            ["B5D382C80C8AD99A1F84EB4B502A8A67"] = "GameMaker Studio 2 Runtime",
            ["AC3F9BB2F368BEF4476D3BEE5CD3B6FF"] = "GameMaker Studio 1.4",
            ["2AC4C90467973C679AFD73CCB5315CF9"] = "GameMaker 8.1"
        };

        // Regex patterns for GameMaker detection in file content
        private static readonly Dictionary<string, Regex> GameMakerPatterns = new Dictionary<string, Regex>
        {
            ["GameMaker"] = new Regex(@"GameMaker|Game Maker|YoYo Games", RegexOptions.Compiled),
            ["GMVersion"] = new Regex(@"GM_version|GM_runtime|GM_build_date", RegexOptions.Compiled),
            ["GMEnumerator"] = new Regex(@"__yy|__gy|__gma_\d+", RegexOptions.Compiled),
            ["GMFunctionRef"] = new Regex(@"gml_|@@GameMaker@@", RegexOptions.Compiled),
            ["GMController"] = new Regex(@"YoYo\s+Games|YYG_", RegexOptions.Compiled),
            ["GMDatafiles"] = new Regex(@"\.win|\.gmk|\.gmz|\.gm81|\.yyp", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "GameMaker Studio";
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
                score += ScanForGameMakerSignatures(folder);

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
                // GameMaker games are typically single executables or main EXE with data files
                string exeHash = CalculateMD5Hash(exePath);
                if (GameMakerFileHashes.ContainsKey(exeHash))
                {
                    score += 5.0; // Strong evidence
                }

                // Look for GameMaker DLLs and support files
                var gmFiles = new List<string>();
                gmFiles.AddRange(Directory.GetFiles(folder, "*.dll", SearchOption.TopDirectoryOnly));
                gmFiles.AddRange(Directory.GetFiles(folder, "*.yydll", SearchOption.TopDirectoryOnly));
                gmFiles.AddRange(Directory.GetFiles(folder, "*.gml", SearchOption.TopDirectoryOnly));
                gmFiles = gmFiles.Take(MAX_FILES_TO_ANALYZE).ToList();

                foreach (var filePath in gmFiles)
                {
                    string hash = CalculateMD5Hash(filePath);
                    if (GameMakerFileHashes.ContainsKey(hash))
                    {
                        score += 3.0; // Strong evidence
                    }
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
                // Check for GameMaker-specific files
                string[] gameMakerFiles = { 
                    "data.win",
                    "game.ios",
                    "game.unx",
                    "game.droid",
                    "fmod.dll",
                    "steam_api.dll",
                    "options.ini",
                    "main.ini"
                };

                foreach (var gmFile in gameMakerFiles)
                {
                    if (File.Exists(Path.Combine(folder, gmFile)))
                    {
                        score += 1.0;
                    }
                }

                // Check for GameMaker directory structure
                string[] gameMakerDirs = {
                    "datafiles",
                    "assets",
                    "extensions",
                    "scripts",
                    "sprites"
                };

                foreach (var gmDir in gameMakerDirs)
                {
                    if (Directory.Exists(Path.Combine(folder, gmDir)))
                    {
                        score += 0.5;
                    }
                }

                // Check for .yy files (GameMaker Studio 2 files)
                var yyFiles = Directory.GetFiles(folder, "*.yy", SearchOption.AllDirectories).Take(10);
                if (yyFiles.Any())
                {
                    score += 2.0;
                }

                // Check for .yyp project file
                var yypFiles = Directory.GetFiles(folder, "*.yyp", SearchOption.AllDirectories).Take(3);
                if (yypFiles.Any())
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
                    
                    // Check for GameMaker-specific modules
                    if (moduleName.Contains("gamemaker") || 
                        moduleName.Contains("yoyo") || 
                        moduleName.Contains("fmod") || 
                        moduleName.StartsWith("gm_"))
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

        private double ScanForGameMakerSignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan executable and data files
                var filesToScan = new List<string>();
                
                // Add executable
                string[] exeFiles = Directory.GetFiles(folder, "*.exe");
                filesToScan.AddRange(exeFiles);
                
                // Add data files
                filesToScan.AddRange(Directory.GetFiles(folder, "data.win", SearchOption.TopDirectoryOnly));
                filesToScan.AddRange(Directory.GetFiles(folder, "*.ini", SearchOption.TopDirectoryOnly));
                
                // Look for game resource files
                filesToScan.AddRange(Directory.GetFiles(folder, "*.txt", SearchOption.TopDirectoryOnly));
                
                // Binary scan for specific GameMaker patterns
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, GameMakerPatterns);
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