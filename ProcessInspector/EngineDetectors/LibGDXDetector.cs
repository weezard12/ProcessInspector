using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public class LibGDXDetector : BaseEngineDetector
    {
        // Known LibGDX file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> LibGDXFileHashes = new Dictionary<string, string>
        {
            ["F7C356D3AE5FBDF5DF038D1E3E75B8F9"] = "LibGDX (1.12.x)",
            ["8DE4B7BF6BD38F56BE88E21BBF2C0953"] = "LibGDX (1.11.x)",
            ["2DA4AFE5338C01962B28144D48889900"] = "LibGDX (1.10.x)",
            ["C4C8F63FFE1951C3454B03630C11394A"] = "LibGDX (1.9.x)"
        };

        // Regex patterns for LibGDX detection in file content
        private static readonly Dictionary<string, Regex> LibGDXPatterns = new Dictionary<string, Regex>
        {
            ["LibGDX"] = new Regex(@"libgdx|com\.badlogic\.gdx", RegexOptions.Compiled),
            ["GDXApp"] = new Regex(@"ApplicationAdapter|Game\s+implements\s+ApplicationListener", RegexOptions.Compiled),
            ["GDXImports"] = new Regex(@"import\s+com\.badlogic\.gdx", RegexOptions.Compiled),
            ["GDXClasses"] = new Regex(@"SpriteBatch|OrthographicCamera|Stage|Texture|Sprite", RegexOptions.Compiled),
            ["GDXGraphics"] = new Regex(@"Gdx\.graphics|Gdx\.files|Gdx\.app|Gdx\.input", RegexOptions.Compiled),
            ["GDXMethods"] = new Regex(@"render\(\s*float\s*\)|create\(\s*\)|resize\(\s*int\s*,\s*int\s*\)", RegexOptions.Compiled),
            ["GDXConfig"] = new Regex(@"LwjglApplication|AndroidApplication|IOSApplication", RegexOptions.Compiled),
            ["GDXAssets"] = new Regex(@"\.atlas|\.pack|assetManager|AssetManager", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "LibGDX";
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
                score += ScanForLibGDXSignatures(folder);

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
                // Look for LibGDX JAR files and libraries
                var libgdxFiles = new List<string>();
                libgdxFiles.AddRange(Directory.GetFiles(folder, "gdx*.jar", SearchOption.AllDirectories));
                libgdxFiles.AddRange(Directory.GetFiles(folder, "libgdx*.jar", SearchOption.AllDirectories));
                libgdxFiles.AddRange(Directory.GetFiles(folder, "badlogic*.jar", SearchOption.AllDirectories));
                libgdxFiles = libgdxFiles.Take(MAX_FILES_TO_ANALYZE).ToList();

                foreach (var filePath in libgdxFiles)
                {
                    string hash = CalculateMD5Hash(filePath);
                    if (LibGDXFileHashes.ContainsKey(hash))
                    {
                        score += 5.0; // Strong evidence
                    }
                    else
                    {
                        // Even if not exact hash match, finding LibGDX JARs is strong evidence
                        score += 2.0;
                    }
                }

                // Also check DLLs for native libraries (Windows)
                var nativeFiles = Directory.GetFiles(folder, "*.dll", SearchOption.AllDirectories)
                    .Where(f => f.Contains("gdx") || f.Contains("lwjgl"))
                    .Take(10);
                
                foreach (var filePath in nativeFiles)
                {
                    score += 0.5;
                }

                // Check Java class files
                var classFiles = Directory.GetFiles(folder, "*.class", SearchOption.AllDirectories)
                    .Take(5);
                
                if (classFiles.Any())
                {
                    score += 0.5; // Potential Java application
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
                // Check for LibGDX-specific folders
                string[] libgdxFolders = { 
                    "assets",
                    "android",
                    "ios",
                    "desktop",
                    "core",
                    "html"
                };

                foreach (var gdxFolder in libgdxFolders)
                {
                    if (Directory.Exists(Path.Combine(folder, gdxFolder)))
                    {
                        score += 0.5;
                    }
                }

                // Check for standard LibGDX project structure
                if (Directory.Exists(Path.Combine(folder, "core", "src")) &&
                    Directory.Exists(Path.Combine(folder, "assets")))
                {
                    score += 2.0; // Very common LibGDX structure
                }

                // Check for LibGDX gradle files
                string[] gradleFiles = {
                    "build.gradle",
                    "settings.gradle",
                    "gradlew",
                    "gradlew.bat"
                };

                int gradleFilesFound = 0;
                foreach (var gradleFile in gradleFiles)
                {
                    if (File.Exists(Path.Combine(folder, gradleFile)))
                    {
                        gradleFilesFound++;
                    }
                }

                if (gradleFilesFound >= 2)
                {
                    // Check for LibGDX dependencies in build.gradle
                    string buildGradlePath = Path.Combine(folder, "build.gradle");
                    if (File.Exists(buildGradlePath))
                    {
                        try
                        {
                            string content = File.ReadAllText(buildGradlePath);
                            if (content.Contains("com.badlogicgames.gdx") || 
                                content.Contains("gdxVersion"))
                            {
                                score += 3.0; // Strong evidence
                            }
                        }
                        catch
                        {
                            // Ignore file read errors
                        }
                    }
                }

                // Check for texture atlases and other LibGDX asset formats
                var atlasFiles = Directory.GetFiles(folder, "*.atlas", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "*.pack", SearchOption.AllDirectories))
                    .Take(5);
                
                if (atlasFiles.Any())
                {
                    score += 1.0;
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
                    
                    // Check for Java VM and LibGDX related modules
                    if (moduleName.Contains("java") || 
                        moduleName.Contains("jvm") || 
                        moduleName.Contains("gdx") ||
                        moduleName.Contains("lwjgl") ||
                        moduleName.Contains("opengl") ||
                        moduleName.Contains("openal"))
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

        private double ScanForLibGDXSignatures(string folder)
        {
            double score = 0.0;

            try
            {
                // Scan Java source files and configurations
                var filesToScan = new List<string>();
                
                // Add Java source files
                filesToScan.AddRange(Directory.GetFiles(folder, "*.java", SearchOption.AllDirectories)
                    .Take(20));
                
                // Add Kotlin source files (also used with LibGDX)
                filesToScan.AddRange(Directory.GetFiles(folder, "*.kt", SearchOption.AllDirectories)
                    .Take(10));
                
                // Add Gradle files
                filesToScan.AddRange(Directory.GetFiles(folder, "*.gradle", SearchOption.AllDirectories)
                    .Take(5));
                
                // Add Android manifest (common for LibGDX Android projects)
                var manifestFiles = Directory.GetFiles(folder, "AndroidManifest.xml", SearchOption.AllDirectories)
                    .Take(2);
                filesToScan.AddRange(manifestFiles);
                
                // Scan limited number of files
                foreach (var file in filesToScan.Take(MAX_FILES_TO_ANALYZE))
                {
                    score += ScanFileForEnginePatterns(file, LibGDXPatterns);
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