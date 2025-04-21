using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class ElectronDetector : BaseEngineDetector
    {
        // Known Electron file hashes (MD5) for specific versions
        private static readonly Dictionary<string, string> ElectronFileHashes = new Dictionary<string, string>
        {
            ["D6F8DBC5C2FDC51B705C55AAE8DC6C6F"] = "Electron 25.x",
            ["E90750A2A4B1F81F7D9DB6F920C7E668"] = "Electron 24.x",
            ["A7E3951FACA0D5409C9A86887AF15A3C"] = "Electron 23.x",
            ["5D38630BD45645CCCB2A0089A7B5FF1A"] = "Electron 22.x",
            ["C0944B4F07E3467750BEC2C3A571C1F0"] = "Electron 21.x",
            ["7D4C82A21148CD9A4F86B3458EF17BCA"] = "Electron 20.x"
        };

        // Regex patterns for Electron detection in file content
        private static readonly Dictionary<string, Regex> ElectronPatterns = new Dictionary<string, Regex>
        {
            ["ElectronApp"] = new Regex(@"Electron|electron\.asar", RegexOptions.Compiled),
            ["ElectronJS"] = new Regex(@"node_modules[/\\]electron", RegexOptions.Compiled),
            ["ElectronPackage"] = new Regex(@"""electron"":", RegexOptions.Compiled),
            ["NodeModules"] = new Regex(@"node_modules", RegexOptions.Compiled),
            ["AppAsar"] = new Regex(@"app\.asar", RegexOptions.Compiled),
            ["WebpackContext"] = new Regex(@"__webpack_require__|webpack", RegexOptions.Compiled),
            ["NodeIntegration"] = new Regex(@"nodeIntegration|contextIsolation", RegexOptions.Compiled),
            ["ChromiumFramework"] = new Regex(@"chrome-sandbox|libffmpeg|swiftshader", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "Electron";
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
                score += ScanForElectronSignatures(folder);

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
                // Check the executable itself
                string exeHash = CalculateMD5Hash(exePath);
                if (ElectronFileHashes.ContainsKey(exeHash))
                {
                    score += 5.0;
                }

                // Look for Electron-specific files
                var electronFiles = new List<string>();
                electronFiles.AddRange(Directory.GetFiles(folder, "electron.dll", SearchOption.AllDirectories));
                electronFiles.AddRange(Directory.GetFiles(folder, "libffmpeg.dll", SearchOption.AllDirectories));
                electronFiles.AddRange(Directory.GetFiles(folder, "chrome_*.dll", SearchOption.AllDirectories));
                electronFiles = electronFiles.Take(MAX_FILES_TO_ANALYZE).ToList();

                foreach (var filePath in electronFiles)
                {
                    string hash = CalculateMD5Hash(filePath);
                    if (ElectronFileHashes.ContainsKey(hash))
                    {
                        score += 3.0; // Strong evidence
                    }
                    else
                    {
                        // Even if not exact hash match, finding Electron DLLs is good evidence
                        score += 1.0;
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
                // Check for Electron-specific files
                string[] electronFiles = { 
                    "electron.exe",
                    "app.asar",
                    "electron.asar",
                    "package.json",
                    "chrome-sandbox",
                    "icudtl.dat",
                    "natives_blob.bin",
                    "snapshot_blob.bin",
                    "v8_context_snapshot.bin"
                };

                foreach (var file in electronFiles)
                {
                    if (File.Exists(Path.Combine(folder, file)))
                    {
                        score += 1.0;
                    }
                }

                // Check for Electron folder structure
                string[] electronDirs = {
                    "resources",
                    "locales",
                    "swiftshader",
                    "node_modules"
                };

                foreach (var dir in electronDirs)
                {
                    if (Directory.Exists(Path.Combine(folder, dir)))
                    {
                        score += 0.5;
                    }
                }

                // Check for package.json with electron dependency
                string packageJsonPath = Path.Combine(folder, "package.json");
                if (File.Exists(packageJsonPath))
                {
                    try
                    {
                        string content = File.ReadAllText(packageJsonPath);
                        if (content.Contains("\"electron\":") || content.Contains("\"electron-builder\":"))
                        {
                            score += 2.0;
                        }
                    }
                    catch
                    {
                        // Ignore file read errors
                    }
                }

                // Check for app.asar file (very specific to Electron apps)
                string resourcesFolder = Path.Combine(folder, "resources");
                if (Directory.Exists(resourcesFolder))
                {
                    if (File.Exists(Path.Combine(resourcesFolder, "app.asar")))
                    {
                        score += 3.0; // Very strong evidence
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
                    
                    // Check for Electron-specific modules
                    if (moduleName.Contains("electron") || 
                        moduleName.StartsWith("chrome_") ||
                        moduleName.Contains("node.dll") ||
                        moduleName.Contains("libffmpeg") ||
                        moduleName.Contains("libEGL.dll") ||
                        moduleName.Contains("libGLESv2.dll"))
                    {
                        score += 0.5;
                    }
                }

                // Also check the command line for Electron-specific flags
                string commandLine = GetProcessCommandLine(processId);
                if (!string.IsNullOrEmpty(commandLine))
                {
                    if (commandLine.Contains("--app=") || 
                        commandLine.Contains("--allow-file-access-from-files") ||
                        commandLine.Contains("--no-sandbox") ||
                        commandLine.Contains("app.asar"))
                    {
                        score += 1.0;
                    }
                }
            }
            catch
            {
                // Ignore process access errors
            }

            return Math.Min(score, 3.0); // Cap at 3.0
        }

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        return obj["CommandLine"]?.ToString() ?? string.Empty;
                    }
                }
                return string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private double ScanForElectronSignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan executable and resource files
                var filesToScan = new List<string>();
                
                // Add executable
                string[] exeFiles = Directory.GetFiles(folder, "*.exe");
                filesToScan.AddRange(exeFiles);
                
                // Check resources folder
                string resourcesFolder = Path.Combine(folder, "resources");
                if (Directory.Exists(resourcesFolder))
                {
                    // Add specific files that might contain Electron signatures
                    filesToScan.AddRange(Directory.GetFiles(resourcesFolder, "*.js", SearchOption.TopDirectoryOnly));
                    filesToScan.AddRange(Directory.GetFiles(resourcesFolder, "*.json", SearchOption.TopDirectoryOnly));
                    filesToScan.AddRange(Directory.GetFiles(resourcesFolder, "*.html", SearchOption.TopDirectoryOnly));
                }
                
                // Add root js and json files
                filesToScan.AddRange(Directory.GetFiles(folder, "*.js", SearchOption.TopDirectoryOnly));
                filesToScan.AddRange(Directory.GetFiles(folder, "*.json", SearchOption.TopDirectoryOnly));
                
                // Scan limited number of files
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, ElectronPatterns);
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