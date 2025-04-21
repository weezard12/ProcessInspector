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
    }
} 