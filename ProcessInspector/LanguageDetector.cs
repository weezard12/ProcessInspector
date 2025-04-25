using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using PeNet;
using ProcessInspector.Types;

namespace ProcessInspector
{
    public class LanguageDetector : ILanguageDetector
    {
        // Maximum file size to analyze (to prevent analyzing very large files)
        private const int MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB

        // Maximum number of files to analyze in a directory
        private const int MAX_FILES_TO_ANALYZE = 100;

        // Regex patterns for language detection in file content
        private static readonly Dictionary<string, List<Regex>> LanguagePatterns = new Dictionary<string, List<Regex>>
        {
            ["C#"] = new List<Regex>
            {
                new Regex(@"namespace\s+[\w\.]+\s*{", RegexOptions.Compiled),
                new Regex(@"using\s+[\w\.]+\s*;", RegexOptions.Compiled),
                new Regex(@"public\s+class\s+\w+", RegexOptions.Compiled),
                new Regex(@"static\s+void\s+Main\(", RegexOptions.Compiled)
            },
            ["C++"] = new List<Regex>
            {
                new Regex(@"#include\s*<[\w\.]+>", RegexOptions.Compiled),
                new Regex(@"std::", RegexOptions.Compiled),
                new Regex(@"template\s*<", RegexOptions.Compiled),
                new Regex(@"namespace\s+\w+\s*{", RegexOptions.Compiled)
            },
            ["Visual Basic"] = new List<Regex>
            {
                new Regex(@"Imports\s+[\w\.]+", RegexOptions.Compiled),
                new Regex(@"Public\s+Class\s+\w+", RegexOptions.Compiled),
                new Regex(@"Module\s+\w+", RegexOptions.Compiled),
                new Regex(@"End\s+(Class|Sub|Function)", RegexOptions.Compiled)
            },
            ["F#"] = new List<Regex>
            {
                new Regex(@"module\s+[\w\.]+", RegexOptions.Compiled),
                new Regex(@"open\s+[\w\.]+", RegexOptions.Compiled),
                new Regex(@"let\s+\w+", RegexOptions.Compiled),
                new Regex(@"type\s+\w+", RegexOptions.Compiled)
            },
            ["Java"] = new List<Regex>
            {
                new Regex(@"package\s+[\w\.]+;", RegexOptions.Compiled),
                new Regex(@"import\s+[\w\.]+;", RegexOptions.Compiled),
                new Regex(@"public\s+class\s+\w+", RegexOptions.Compiled),
                new Regex(@"@Override", RegexOptions.Compiled)
            },
            ["Python"] = new List<Regex>
            {
                new Regex(@"import\s+\w+", RegexOptions.Compiled),
                new Regex(@"from\s+[\w\.]+\s+import", RegexOptions.Compiled),
                new Regex(@"def\s+\w+\s*\(", RegexOptions.Compiled),
                new Regex(@"class\s+\w+\s*:", RegexOptions.Compiled)
            },
            ["JavaScript"] = new List<Regex>
            {
                new Regex(@"function\s+\w+\s*\(", RegexOptions.Compiled),
                new Regex(@"const\s+\w+\s*=", RegexOptions.Compiled),
                new Regex(@"let\s+\w+\s*=", RegexOptions.Compiled),
                new Regex(@"document\.getElementById", RegexOptions.Compiled)
            },
            ["TypeScript"] = new List<Regex>
            {
                new Regex(@"interface\s+\w+\s*{", RegexOptions.Compiled),
                new Regex(@":\s*\w+Type", RegexOptions.Compiled),
                new Regex(@"class\s+\w+\s+implements", RegexOptions.Compiled),
                new Regex(@"export\s+(class|interface|type)", RegexOptions.Compiled)
            },
            ["Rust"] = new List<Regex>
            {
                new Regex(@"fn\s+\w+\s*\(", RegexOptions.Compiled),
                new Regex(@"use\s+[\w\:]+;", RegexOptions.Compiled),
                new Regex(@"impl\s+\w+", RegexOptions.Compiled),
                new Regex(@"struct\s+\w+", RegexOptions.Compiled)
            },
            ["Go"] = new List<Regex>
            {
                new Regex(@"package\s+\w+", RegexOptions.Compiled),
                new Regex(@"import\s+\(", RegexOptions.Compiled),
                new Regex(@"func\s+\w+\s*\(", RegexOptions.Compiled),
                new Regex(@"type\s+\w+\s+struct", RegexOptions.Compiled)
            }
        };

        public LanguageDetectionResult DetectProgrammingLanguages(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                return new LanguageDetectionResult();
            }

            Dictionary<string, double> languageScores = InitializeLanguageScores();

            try
            {
                // Detect languages from PE file
                AnalyzePeFile(exePath, languageScores);

                // Analyze files in directory for additional clues
                AnalyzeDirectoryFiles(exePath, languageScores);

                // Deep scan selected source files for content-based detection
                DeepScanSourceFiles(exePath, languageScores);

                // Analyze embedded resources
                AnalyzeEmbeddedResources(exePath, languageScores);

                // Normalize scores to percentages
                return NormalizeScores(languageScores);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Language detection error: {ex.Message}");
                // If detection fails, return empty result
                return new LanguageDetectionResult();
            }
        }

        private Dictionary<string, double> InitializeLanguageScores()
        {
            return new Dictionary<string, double>
            {
                ["C#"] = 0,
                ["C++"] = 0,
                ["Visual Basic"] = 0,
                ["F#"] = 0,
                ["Java"] = 0,
                ["Python"] = 0,
                ["JavaScript"] = 0,
                ["TypeScript"] = 0,
                ["Rust"] = 0,
                ["Go"] = 0,
                ["Other/Native"] = 0
            };
        }

        private void AnalyzePeFile(string exePath, Dictionary<string, double> languageScores)
        {
            try
            {
                var peFile = new PeFile(exePath);

                // Check for .NET (MSIL)
                if (peFile.IsDotNet)
                {
                    AnalyzeDotNetAssembly(exePath, languageScores);
                }
                else
                {
                    // Native code - analyze deeper
                    AnalyzeNativeExecutable(peFile, languageScores);
                }

                // Check imported DLLs for clues
                AnalyzeImportedDlls(peFile, languageScores);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PE analysis error: {ex.Message}");
                // PeNet analysis failed, fall back to other detection methods
                languageScores["Other/Native"] += 3;
            }
        }

        private void AnalyzeDotNetAssembly(string exePath, Dictionary<string, double> languageScores)
        {
            try
            {
                // Look for language-specific metadata attributes
                using (var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    // First, try loading the assembly directly
                    try
                    {
                        var assembly = Assembly.LoadFile(exePath);

                        // Look for compiler generated attributes
                        foreach (var attribute in assembly.GetCustomAttributes(false))
                        {
                            string attributeType = attribute.GetType().FullName;

                            if (attributeType.Contains("CompilationRelaxations") ||
                                attributeType.Contains("RuntimeCompatibility"))
                            {
                                languageScores["C#"] += 3;
                            }
                            else if (attributeType.Contains("VBFixedString") ||
                                     attributeType.Contains("VBFixedArray"))
                            {
                                languageScores["Visual Basic"] += 5;
                            }
                            else if (attributeType.Contains("FSharp"))
                            {
                                languageScores["F#"] += 5;
                            }
                        }

                        // Check for language-specific namespaces within the assembly
                        var modules = assembly.GetModules();
                        foreach (var module in modules)
                        {
                            try
                            {
                                foreach (var type in module.GetTypes())
                                {
                                    string fullName = type.FullName ?? "";

                                    if (fullName.Contains("Microsoft.VisualBasic"))
                                    {
                                        languageScores["Visual Basic"] += 1;
                                    }
                                    else if (fullName.Contains("Microsoft.FSharp"))
                                    {
                                        languageScores["F#"] += 1;
                                    }
                                    else if (fullName.Contains("<PrivateImplementationDetails>"))
                                    {
                                        languageScores["C#"] += 0.5;
                                    }
                                }
                            }
                            catch (ReflectionTypeLoadException)
                            {
                                // Continue with next module if type loading fails
                                continue;
                            }
                        }
                    }
                    catch (Exception)
                    {
                        // If direct loading fails, do basic .NET detection
                        languageScores["C#"] += 3; // Default assumption for .NET
                    }

                    // If no specific language was strongly detected, slightly favor C#
                    if (languageScores["C#"] < 1 &&
                        languageScores["Visual Basic"] < 1 &&
                        languageScores["F#"] < 1)
                    {
                        languageScores["C#"] += 2;
                    }
                }
            }
            catch (Exception)
            {
                // If analysis fails, slightly favor C# as most common .NET language
                languageScores["C#"] += 2;
            }
        }

        private void AnalyzeNativeExecutable(PeFile peFile, Dictionary<string, double> languageScores)
        {
            // Check for C++ Runtime
            bool hasCppRuntime = false;
            bool hasRustSignatures = false;
            bool hasGoSignatures = false;

            // Try to find language-specific sections or signatures
            if (peFile.ExportedFunctions != null)
            {
                var exports = peFile.ExportedFunctions.Select(f => f.Name).ToList();

                // Check for Rust-specific name mangling patterns
                if (exports.Any(e => e != null && (e.Contains("rust") || e.StartsWith("_ZN"))))
                {
                    hasRustSignatures = true;
                    languageScores["Rust"] += 4;
                }

                // Check for Go-specific patterns
                if (exports.Any(e => e != null && (e.StartsWith("_cgo_") || e.Contains("_go_"))))
                {
                    hasGoSignatures = true;
                    languageScores["Go"] += 4;
                }

                // C++ specific exports
                if (exports.Any(e => e != null && (e.Contains("operator") || e.Contains("deleting") ||
                                                  e.StartsWith("??") || e.Contains("virtual"))))
                {
                    hasCppRuntime = true;
                    languageScores["C++"] += 3;
                }
            }

            // Check sections
            if (peFile.ImageSectionHeaders != null)
            {
                foreach (var section in peFile.ImageSectionHeaders)
                {
                    string sectionName = section.Name;

                    if (sectionName.Contains(".rdata") || sectionName.Contains(".data$r"))
                    {
                        // RTTI sections often present in C++ executables
                        hasCppRuntime = true;
                        languageScores["C++"] += 2;
                    }
                }
            }

            // If no specific language detected, assign generic native score
            if (!hasCppRuntime && !hasRustSignatures && !hasGoSignatures)
            {
                languageScores["C++"] += 2; // Default assumption for native code
                languageScores["Other/Native"] += 3;
            }
        }

        private void AnalyzeImportedDlls(PeFile peFile, Dictionary<string, double> languageScores)
        {
            if (peFile.ImportedFunctions == null)
                return;

            // Get all imported DLLs
            var importedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var importedFunction in peFile.ImportedFunctions)
            {
                if (!string.IsNullOrEmpty(importedFunction.DLL))
                {
                    importedDlls.Add(importedFunction.DLL.ToLower());
                }
            }

            // More comprehensive DLL analysis
            foreach (var dll in importedDlls)
            {
                if (dll.Contains("mscoree") || dll.Contains("mscorlib") || dll.Contains("clr"))
                {
                    languageScores["C#"] += 2;
                }
                else if (dll.Contains("vcruntime") || dll.Contains("msvcp") || dll.Contains("msvcr"))
                {
                    languageScores["C++"] += 3;
                }
                else if (dll.Contains("vbrun") || dll.Contains("vb6"))
                {
                    languageScores["Visual Basic"] += 3;
                }
                else if (dll.Contains("jvm") || dll.Contains("java") || dll.Contains("awt"))
                {
                    languageScores["Java"] += 4;
                }
                else if (dll.Contains("python") || dll.Contains("py"))
                {
                    languageScores["Python"] += 4;
                }
                else if (dll.Contains("node") || dll.Contains("v8") || dll.Contains("chrome"))
                {
                    languageScores["JavaScript"] += 2;
                    languageScores["TypeScript"] += 1.5;
                }
                else if (dll.Contains("rust"))
                {
                    languageScores["Rust"] += 4;
                }
                else if (dll.Contains("golang") || dll.Contains("go1"))
                {
                    languageScores["Go"] += 4;
                }
            }

            // Function-level analysis for more accuracy
            var importedFunctionNames = peFile.ImportedFunctions.Select(f => f.Name?.ToLower() ?? "").ToList();

            // Count occurrences of language-specific functions
            int cppFuncs = importedFunctionNames.Count(f =>
                f.Contains("_cxx") || f.Contains("malloc") || f.Contains("free") ||
                f.Contains("printf") || f.Contains("iostream"));

            int pythonFuncs = importedFunctionNames.Count(f =>
                f.Contains("py_") || f.Contains("python") || f.Contains("pyobject"));

            int rustFuncs = importedFunctionNames.Count(f =>
                f.Contains("rust_") || f.Contains("alloc::"));

            int goFuncs = importedFunctionNames.Count(f =>
                f.Contains("go_") || f.Contains("runtime."));

            // Assign additional scores based on function counts
            if (cppFuncs > 3) languageScores["C++"] += 2;
            if (pythonFuncs > 3) languageScores["Python"] += 2;
            if (rustFuncs > 3) languageScores["Rust"] += 2;
            if (goFuncs > 3) languageScores["Go"] += 2;
        }

        private void AnalyzeDirectoryFiles(string exePath, Dictionary<string, double> languageScores)
        {
            string folder = Path.GetDirectoryName(exePath);
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
                return;

            try
            {
                var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE)
                    .ToList();

                // Dictionary mapping file extensions to languages with weight
                var extensionMap = new Dictionary<string, (string language, double weight)>(StringComparer.OrdinalIgnoreCase)
                {
                    [".cs"] = ("C#", 1.5),
                    [".csproj"] = ("C#", 3),
                    [".xaml"] = ("C#", 1),
                    [".resx"] = ("C#", 0.8),

                    [".cpp"] = ("C++", 1.5),
                    [".cc"] = ("C++", 1.5),
                    [".hpp"] = ("C++", 1),
                    [".h"] = ("C++", 0.7),
                    [".c"] = ("C++", 1),
                    [".vcxproj"] = ("C++", 3),

                    [".vb"] = ("Visual Basic", 2),
                    [".vbproj"] = ("Visual Basic", 3),
                    [".bas"] = ("Visual Basic", 1.5),
                    [".frm"] = ("Visual Basic", 1.5),

                    [".fs"] = ("F#", 2),
                    [".fsi"] = ("F#", 1.5),
                    [".fsx"] = ("F#", 1.5),
                    [".fsproj"] = ("F#", 3),

                    [".java"] = ("Java", 2),
                    [".jar"] = ("Java", 3),
                    [".class"] = ("Java", 1.5),
                    [".gradle"] = ("Java", 2),
                    [".kt"] = ("Java", 1),  // Kotlin still suggests Java ecosystem

                    [".py"] = ("Python", 2),
                    [".pyc"] = ("Python", 1.5),
                    [".pyd"] = ("Python", 1.5),
                    [".pyx"] = ("Python", 1.5),
                    [".pyi"] = ("Python", 1),

                    [".js"] = ("JavaScript", 2),
                    [".jsx"] = ("JavaScript", 1.5),
                    [".mjs"] = ("JavaScript", 1.5),
                    [".cjs"] = ("JavaScript", 1.5),

                    [".ts"] = ("TypeScript", 2),
                    [".tsx"] = ("TypeScript", 1.5),
                    [".d.ts"] = ("TypeScript", 1.5),

                    [".rs"] = ("Rust", 2),
                    [".rlib"] = ("Rust", 2),
                    [".cargo"] = ("Rust", 1.5),

                    [".go"] = ("Go", 2),
                    [".mod"] = ("Go", 1.5),
                    [".sum"] = ("Go", 1)
                };

                // Dictionary mapping specific file names to languages
                var fileNameMap = new Dictionary<string, (string language, double weight)>(StringComparer.OrdinalIgnoreCase)
                {
                    ["tsconfig.json"] = ("TypeScript", 3),
                    ["package.json"] = ("JavaScript", 2),
                    ["package-lock.json"] = ("JavaScript", 1.5),
                    ["node_modules"] = ("JavaScript", 1),

                    ["requirements.txt"] = ("Python", 2.5),
                    ["setup.py"] = ("Python", 2.5),
                    ["pyproject.toml"] = ("Python", 2),
                    ["__pycache__"] = ("Python", 1.5),
                    ["Pipfile"] = ("Python", 2),

                    ["pom.xml"] = ("Java", 3),
                    ["build.gradle"] = ("Java", 2.5),
                    ["gradle.properties"] = ("Java", 1.5),
                    ["maven-wrapper.jar"] = ("Java", 2),

                    ["Cargo.toml"] = ("Rust", 3),
                    ["Cargo.lock"] = ("Rust", 2),

                    ["go.mod"] = ("Go", 3),
                    ["go.sum"] = ("Go", 2),

                    ["AssemblyInfo.cs"] = ("C#", 2),
                    [".sln"] = ("C#", 1.5),
                    ["app.config"] = ("C#", 1),
                    ["web.config"] = ("C#", 1.5),

                    ["CMakeLists.txt"] = ("C++", 2),
                    ["Makefile"] = ("C++", 1),

                    ["fsharp.core.dll"] = ("F#", 3),

                    ["vb.net.dll"] = ("Visual Basic", 3)
                };

                foreach (var file in files)
                {
                    string ext = Path.GetExtension(file).ToLower();
                    string fileName = Path.GetFileName(file).ToLower();

                    // Check file extension
                    if (extensionMap.TryGetValue(ext, out var extLanguageInfo))
                    {
                        languageScores[extLanguageInfo.language] += extLanguageInfo.weight;
                    }

                    // Check for specific files
                    foreach (var fileNameEntry in fileNameMap)
                    {
                        if (fileName.Contains(fileNameEntry.Key.ToLower()))
                        {
                            languageScores[fileNameEntry.Value.language] += fileNameEntry.Value.weight;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Directory analysis error: {ex.Message}");
                // Continue with other detection methods
            }
        }

        private void DeepScanSourceFiles(string exePath, Dictionary<string, double> languageScores)
        {
            string folder = Path.GetDirectoryName(exePath);
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
                return;

            try
            {
                // Define file extensions to analyze by content
                var contentScanExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ".cs", ".cpp", ".h", ".hpp", ".vb", ".fs", ".java", ".py", ".js", ".ts", ".rs", ".go"
                };

                // Get a limited number of files to prevent performance issues
                var filesToScan = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                    .Where(f => contentScanExtensions.Contains(Path.GetExtension(f)))
                    .Take(MAX_FILES_TO_ANALYZE)
                    .ToList();

                foreach (var file in filesToScan)
                {
                    try
                    {
                        // Skip large files
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.Length > MAX_FILE_SIZE_BYTES)
                            continue;

                        // Read file content
                        string content = File.ReadAllText(file);

                        // Apply pattern matching for each language
                        foreach (var language in LanguagePatterns.Keys)
                        {
                            int patternMatches = 0;

                            foreach (var pattern in LanguagePatterns[language])
                            {
                                patternMatches += pattern.Matches(content).Count;
                            }

                            // Add score based on pattern matches
                            if (patternMatches > 0)
                            {
                                double score = Math.Min(patternMatches * 0.2, 3.0);
                                languageScores[language] += score;
                            }
                        }
                    }
                    catch
                    {
                        // Skip files that can't be read
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Deep scan error: {ex.Message}");
            }
        }

        private void AnalyzeEmbeddedResources(string exePath, Dictionary<string, double> languageScores)
        {
            try
            {
                // Try to detect embedded resources which might indicate language
                if (File.Exists(exePath) && Path.GetExtension(exePath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    using (var stream = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);

                        string header = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                        // Look for specific language signatures in the binary
                        if (header.Contains("Python") || header.Contains("PyObject"))
                        {
                            languageScores["Python"] += 2;
                        }

                        if (header.Contains("java/lang") || header.Contains("JNI_"))
                        {
                            languageScores["Java"] += 2;
                        }

                        if (header.Contains("node_modules") || header.Contains("JavaScript"))
                        {
                            languageScores["JavaScript"] += 1.5;
                        }

                        if (header.Contains("TypeScript") || header.Contains("tslib"))
                        {
                            languageScores["TypeScript"] += 1.5;
                        }

                        if (header.Contains("rustc") || header.Contains("libcore"))
                        {
                            languageScores["Rust"] += 2;
                        }

                        if (header.Contains("golang") || header.Contains("cgo"))
                        {
                            languageScores["Go"] += 2;
                        }
                    }
                }
            }
            catch
            {
                // Continue if embedded resource analysis fails
            }
        }

        private LanguageDetectionResult NormalizeScores(Dictionary<string, double> languageScores)
        {
            var result = new LanguageDetectionResult();

            // Remove languages with very low scores (likely false positives)
            var significantScores = languageScores
                .Where(kv => kv.Value > 0.5)  // Threshold to eliminate noise
                .ToDictionary(kv => kv.Key, kv => kv.Value);

            if (significantScores.Count == 0)
            {
                // If all scores were removed, use the original scores
                significantScores = languageScores.ToDictionary(kv => kv.Key, kv => kv.Value);
            }

            // Normalize to percentages
            double total = significantScores.Values.Sum();

            // If total is 0, return empty result
            if (total == 0)
            {
                return result;
            }

            foreach (var score in significantScores)
            {
                double percentage = Math.Round((score.Value / total) * 100, 1);
                if (percentage >= 1.0) // Only include languages with at least 1%
                {
                    result.Scores.Add(new LanguageScore
                    {
                        Language = score.Key,
                        Percentage = percentage
                    });
                }
            }

            // Sort by percentage (descending)
            result.Scores = result.Scores.OrderByDescending(s => s.Percentage).ToList();

            return result;
        }
    }
}