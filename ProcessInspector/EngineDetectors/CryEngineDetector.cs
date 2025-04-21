using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class CryEngineDetector : BaseEngineDetector
    {
        // Known CryEngine file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> CryEngineFileHashes = new Dictionary<string, string>
        {
            ["E6D9F1BF08EED4EC27E8DA25ADB56F2C"] = "CryEngine 5",
            ["9A1F2DE8E1D8C347AC72A0D5DF2C3B9A"] = "CryEngine 3",
            ["F5B7ECE41ADC7468A19E9C9C4E2113E5"] = "CryEngine 2",
            ["B0ED8AF62B32B41D1BDE3ACF89A59FC1"] = "CryEngine 1"
        };

        // Regex patterns for CryEngine detection in file content
        private static readonly Dictionary<string, Regex> CryEnginePatterns = new Dictionary<string, Regex>
        {
            ["CryEngine"] = new Regex(@"CryEngine|CRYENGINE", RegexOptions.Compiled),
            ["CrySystem"] = new Regex(@"CrySystem|Cry System", RegexOptions.Compiled),
            ["CryRender"] = new Regex(@"CryRender|CryTek", RegexOptions.Compiled),
            ["CryHeaders"] = new Regex(@"IEntity|IEntityClass|ISystem|ICryPak", RegexOptions.Compiled),
            ["Schematyc"] = new Regex(@"Schematyc", RegexOptions.Compiled),
            ["SandboxEditor"] = new Regex(@"Sandbox|SandboxEditor", RegexOptions.Compiled),
            ["CryCG"] = new Regex(@"CryCommon|CryGame", RegexOptions.Compiled),
            ["CryPak"] = new Regex(@"\.pak$", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "CryEngine";
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
                score += ScanForCryEngineSignatures(folder);

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
                // Look for CryEngine DLLs and binaries
                var cryFiles = new List<string>();
                cryFiles.AddRange(Directory.GetFiles(folder, "Cry*.dll", SearchOption.AllDirectories));
                cryFiles.AddRange(Directory.GetFiles(folder, "CrySystem.dll", SearchOption.AllDirectories));
                cryFiles.AddRange(Directory.GetFiles(folder, "CryGame.dll", SearchOption.AllDirectories));
                cryFiles.AddRange(Directory.GetFiles(folder, "CryAction.dll", SearchOption.AllDirectories));
                cryFiles.AddRange(Directory.GetFiles(folder, "CryPhysics.dll", SearchOption.AllDirectories));
                cryFiles = cryFiles.Take(MAX_FILES_TO_ANALYZE).ToList();

                foreach (var filePath in cryFiles)
                {
                    string hash = CalculateMD5Hash(filePath);
                    if (CryEngineFileHashes.ContainsKey(hash))
                    {
                        score += 5.0; // Strong evidence
                    }
                    else
                    {
                        // Even if not exact hash match, finding CryEngine DLLs is good evidence
                        score += 2.0;
                    }
                }

                // Check the executable itself
                string exeHash = CalculateMD5Hash(exePath);
                if (CryEngineFileHashes.ContainsKey(exeHash))
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
                // Check for CryEngine-specific folders
                string[] cryEngineFolders = { 
                    "Game",
                    "Engine",
                    "Levels",
                    "Objects",
                    "Scripts",
                    "Config",
                    "Libs"
                };

                foreach (var cryFolder in cryEngineFolders)
                {
                    if (Directory.Exists(Path.Combine(folder, cryFolder)))
                    {
                        score += 0.5;
                    }
                }

                // Check for CryEngine-specific files
                string[] cryFiles = {
                    "system.cfg",
                    "editor.cfg",
                    "game.cfg",
                    "project.cfg",
                    "game.cryproject"
                };

                foreach (var cryFile in cryFiles)
                {
                    if (File.Exists(Path.Combine(folder, cryFile)))
                    {
                        score += 1.0;
                    }
                }

                // Check for .pak files (CryEngine data files)
                var pakFiles = Directory.GetFiles(folder, "*.pak", SearchOption.AllDirectories).Take(10);
                if (pakFiles.Any())
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
                    
                    // Check for CryEngine-specific modules
                    if (moduleName.Contains("cry") || 
                        moduleName.StartsWith("cry") ||
                        moduleName.Contains("cryengine") ||
                        moduleName.Contains("crysystem") ||
                        moduleName.Contains("cryaction") ||
                        moduleName.Contains("cryphysics"))
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

        private double ScanForCryEngineSignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan executable and config files
                var filesToScan = new List<string>();
                
                // Add executable
                string[] exeFiles = Directory.GetFiles(folder, "*.exe");
                filesToScan.AddRange(exeFiles);
                
                // Add config files
                filesToScan.AddRange(Directory.GetFiles(folder, "*.cfg", SearchOption.TopDirectoryOnly));
                filesToScan.AddRange(Directory.GetFiles(folder, "*.xml", SearchOption.TopDirectoryOnly));
                filesToScan.AddRange(Directory.GetFiles(folder, "*.cryproject", SearchOption.TopDirectoryOnly));
                
                // Look for log files
                string logFolder = Path.Combine(folder, "Logs");
                if (Directory.Exists(logFolder))
                {
                    filesToScan.AddRange(Directory.GetFiles(logFolder, "*.log", SearchOption.TopDirectoryOnly).Take(5));
                }
                
                // Scan limited number of files
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, CryEnginePatterns);
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