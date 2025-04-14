using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using PeNet;
using ProcessInspector.Types;

namespace ProcessInspector
{
    public class LanguageDetector : ILanguageDetector
    {
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

                // Normalize scores to percentages
                return NormalizeScores(languageScores);
            }
            catch (Exception)
            {
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
                    // Try to load as .NET assembly to get more details
                    try
                    {
                        var assembly = Assembly.LoadFile(exePath);
                        var modules = assembly.GetModules();

                        foreach (var module in modules)
                        {
                            foreach (var type in module.GetTypes())
                            {
                                // Check for language-specific attributes
                                if (type.FullName.Contains("Microsoft.VisualBasic"))
                                    languageScores["Visual Basic"] += 0.5;
                                else if (type.FullName.Contains("Microsoft.FSharp"))
                                    languageScores["F#"] += 0.5;
                                else
                                    languageScores["C#"] += 0.2; // Default assumption for .NET
                            }
                        }
                    }
                    catch
                    {
                        // If we can't load the assembly, make an educated guess
                        languageScores["C#"] += 5;
                    }
                }
                else
                {
                    // Native code
                    languageScores["C++"] += 3;
                    languageScores["Other/Native"] += 2;
                }

                // Check imported DLLs for clues
                if (peFile.ImportedFunctions != null)
                {
                    // Get all imported DLLs
                    var importedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var importedFunction in peFile.ImportedFunctions)
                    {
                        if (!string.IsNullOrEmpty(importedFunction.DLL))
                        {
                            importedDlls.Add(importedFunction.DLL.ToLower());
                        }
                    }

                    foreach (var dll in importedDlls)
                    {
                        if (dll.Contains("mscoree") || dll.Contains("mscorlib"))
                            languageScores["C#"] += 2;
                        else if (dll.Contains("vcruntime") || dll.Contains("msvcp"))
                            languageScores["C++"] += 2;
                        else if (dll.Contains("jvm") || dll.Contains("java"))
                            languageScores["Java"] += 3;
                        else if (dll.Contains("python"))
                            languageScores["Python"] += 3;
                        else if (dll.Contains("node") || dll.Contains("v8"))
                        {
                            languageScores["JavaScript"] += 1.5;
                            languageScores["TypeScript"] += 1.5;
                        }
                    }
                }
            }
            catch
            {
                // PeNet analysis failed, fall back to other detection methods
                languageScores["Other/Native"] += 3;
            }
        }

        private void AnalyzeDirectoryFiles(string exePath, Dictionary<string, double> languageScores)
        {
            var folder = Path.GetDirectoryName(exePath);
            var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories);

            // Dictionary mapping file extensions to languages
            var extensionMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [".cs"] = "C#",
                [".cpp"] = "C++",
                [".hpp"] = "C++",
                [".h"] = "C++",
                [".cc"] = "C++",
                [".vb"] = "Visual Basic",
                [".fs"] = "F#",
                [".fsx"] = "F#",
                [".java"] = "Java",
                [".jar"] = "Java",
                [".py"] = "Python",
                [".pyc"] = "Python",
                [".js"] = "JavaScript",
                [".ts"] = "TypeScript"
            };

            // Dictionary mapping specific file names to languages
            var fileNameMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["tsconfig.json"] = "TypeScript",
                ["package.json"] = "JavaScript",
                ["requirements.txt"] = "Python",
                ["setup.py"] = "Python",
                ["pom.xml"] = "Java",
                ["build.gradle"] = "Java"
            };

            foreach (var file in files)
            {
                string ext = Path.GetExtension(file).ToLower();
                string fileName = Path.GetFileName(file).ToLower();

                // Check file extension
                if (extensionMap.TryGetValue(ext, out string language))
                {
                    languageScores[language] += 1;
                }

                // Check for specific files
                foreach (var fileNameEntry in fileNameMap)
                {
                    if (fileName.Contains(fileNameEntry.Key))
                    {
                        languageScores[fileNameEntry.Value] += 2;
                    }
                }
            }
        }

        private LanguageDetectionResult NormalizeScores(Dictionary<string, double> languageScores)
        {
            var result = new LanguageDetectionResult();

            // Remove languages with 0 score
            var nonZeroScores = languageScores.Where(kv => kv.Value > 0).ToDictionary(kv => kv.Key, kv => kv.Value);

            if (nonZeroScores.Count == 0)
            {
                return result;
            }

            // Normalize to percentages
            double total = nonZeroScores.Values.Sum();

            foreach (var score in nonZeroScores)
            {
                double percentage = Math.Round((score.Value / total) * 100, 1);
                result.Scores.Add(new LanguageScore
                {
                    Language = score.Key,
                    Percentage = percentage
                });
            }

            // Sort by percentage (descending)
            result.Scores = result.Scores.OrderByDescending(s => s.Percentage).ToList();

            return result;
        }
    }
}