using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Linq;

namespace ProcessInspector.EngineDetectors
{
    public class WPFDetector : BaseEngineDetector
    {
        // Known WPF DLL hashes (MD5)
        private static readonly Dictionary<string, string> WpfFileHashes = new Dictionary<string, string>
        {
            ["B9C9C7F32E7FC297C0D7A273DB9F3F46"] = "PresentationFramework.dll (.NET 4.8)",
            ["D2F1E4063A69A5843A4F2E7CF592D2FB"] = "PresentationCore.dll (.NET 4.8)",
            ["C5F221A8A4CE76E326A297C5BF463430"] = "WindowsBase.dll (.NET 4.8)",
            ["B674A53D551383D373887A4CC8054F8D"] = "PresentationFramework.dll (.NET 4.7.2)",
            ["4EC34D54FEA16A03A241B5E96F36AF2B"] = "PresentationCore.dll (.NET 4.7.2)",
            ["E6F1AD2A46A715B035991FE84FE48F50"] = "WindowsBase.dll (.NET 4.7.2)",
            ["2BA71BD09B208812F73BE535CCA15ADA"] = "System.Xaml.dll (.NET 4.8)"
        };

        // Regex patterns for WPF detection in file content
        private static readonly Dictionary<string, Regex> WpfPatterns = new Dictionary<string, Regex>
        {
            ["WpfCore"] = new Regex(@"System\.Windows\.|PresentationFramework|PresentationCore|WindowsBase", RegexOptions.Compiled),
            ["XamlNamespace"] = new Regex(@"xmlns=""http://schemas\.microsoft\.com/winfx/(?:2006|2009)/xaml", RegexOptions.Compiled),
            ["WpfApp"] = new Regex(@"<Application\s|StartupUri=", RegexOptions.Compiled),
            ["WpfWindow"] = new Regex(@"<Window\s|<Page\s|<UserControl\s", RegexOptions.Compiled),
            ["WpfControls"] = new Regex(@"<Grid\s|<StackPanel\s|<DockPanel\s|<Canvas\s|<WrapPanel\s", RegexOptions.Compiled),
            ["CodeBehind"] = new Regex(@"CodeBehind="".*\.xaml\.cs""", RegexOptions.Compiled),
            ["WpfBinding"] = new Regex(@"{Binding\s|{StaticResource\s|{DynamicResource\s", RegexOptions.Compiled),
            ["AppXaml"] = new Regex(@"App\.xaml|Application\.xaml", RegexOptions.Compiled),
            ["WpfCode"] = new Regex(@"InitializeComponent\(\)|Window_Loaded|Window_Closing", RegexOptions.Compiled),
            ["WpfStyles"] = new Regex(@"<Style\s|<Setter\s|<Trigger\s|<ControlTemplate\s", RegexOptions.Compiled)
        };

        public override string GetEngineName()
        {
            return "WPF Application";
        }

        public override double DetectEngineProbability(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return 0.0;

            try
            {
                double score = 0.0;
                string folder = Path.GetDirectoryName(exePath);

                // Hash-based detection
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
                score += ScanForWpfSignatures(folder, exePath);

                // Check for competing frameworks or engines
                score -= CheckForCompetingFrameworks(folder, exePath);

                // Check if the executable is a console app (which would decrease the probability)
                if (IsConsoleApplication(exePath))
                {
                    score -= 3.0;
                }

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
                // Look for WPF core assemblies
                var wpfDlls = Directory.GetFiles(folder, "*.dll", SearchOption.AllDirectories)
                    .Where(f => Path.GetFileName(f).ToLower() == "presentationframework.dll" || 
                                Path.GetFileName(f).ToLower() == "presentationcore.dll" || 
                                Path.GetFileName(f).ToLower() == "windowsbase.dll" ||
                                Path.GetFileName(f).ToLower() == "system.xaml.dll")
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var dllPath in wpfDlls)
                {
                    string hash = CalculateMD5Hash(dllPath);
                    if (WpfFileHashes.ContainsKey(hash))
                    {
                        score += 3.0; // Strong evidence
                    }
                    else
                    {
                        // Even without a hash match, finding these DLLs is good evidence
                        if (Path.GetFileName(dllPath).ToLower() == "presentationframework.dll")
                            score += 2.5;
                        else if (Path.GetFileName(dllPath).ToLower() == "presentationcore.dll")
                            score += 2.0;
                        else if (Path.GetFileName(dllPath).ToLower() == "windowsbase.dll")
                            score += 1.5;
                        else if (Path.GetFileName(dllPath).ToLower() == "system.xaml.dll")
                            score += 1.0;
                    }
                }

                // Check if the executable has WPF references
                if (HasWpfReferences(exePath))
                {
                    score += 3.0;
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return Math.Min(score, 5.0); // Cap at 5.0
        }

        private bool HasWpfReferences(string exePath)
        {
            try
            {
                byte[] fileBytes = File.ReadAllBytes(exePath);
                string fileContent = System.Text.Encoding.ASCII.GetString(fileBytes);
                
                return fileContent.Contains("PresentationFramework") || 
                       fileContent.Contains("PresentationCore") || 
                       fileContent.Contains("WindowsBase") ||
                       fileContent.Contains("System.Windows") ||
                       fileContent.Contains("System.Xaml");
            }
            catch
            {
                return false;
            }
        }

        private double AnalyzeDirectory(string folder)
        {
            double score = 0.0;

            try
            {
                // Check for XAML files which are distinctive to WPF
                var xamlFiles = Directory.GetFiles(folder, "*.xaml", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE);
                
                if (xamlFiles.Any())
                {
                    score += 2.0; // Basic XAML files found
                    
                    // Look for app.xaml specifically which is a strong WPF indicator
                    if (xamlFiles.Any(f => Path.GetFileName(f).ToLower() == "app.xaml" ||
                                           Path.GetFileName(f).ToLower() == "application.xaml"))
                    {
                        score += 1.0;
                    }
                    
                    // Look for window.xaml or similar
                    if (xamlFiles.Any(f => Path.GetFileName(f).ToLower().Contains("window.xaml") ||
                                           Path.GetFileName(f).ToLower().Contains("page.xaml")))
                    {
                        score += 1.0;
                    }

                    // Check for resource dictionaries
                    if (xamlFiles.Any(f => Path.GetFileName(f).ToLower().Contains("resources") ||
                                           Path.GetFileName(f).ToLower().Contains("styles") ||
                                           Path.GetFileName(f).ToLower().Contains("themes")))
                    {
                        score += 0.5;
                    }
                }

                // Check for compiled baml files in resources
                var bamlFiles = Directory.GetFiles(folder, "*.baml", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE);
                
                if (bamlFiles.Any())
                {
                    score += 2.0; // BAML files are a very strong indicator
                }

                // Check for project files that might reference WPF
                var projectFiles = Directory.GetFiles(folder, "*.csproj", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "*.vbproj", SearchOption.AllDirectories))
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var projectFile in projectFiles)
                {
                    string content = File.ReadAllText(projectFile);
                    if (content.Contains("<Project Sdk=\"Microsoft.NET.Sdk.WindowsDesktop\">") ||
                        content.Contains("<UseWPF>true</UseWPF>") ||
                        content.Contains("PresentationFramework") ||
                        content.Contains("WindowsFormsIntegration")) // WPF/WinForms interop
                    {
                        score += 1.0;
                    }
                }
            }
            catch
            {
                // Ignore directory access errors
            }

            return Math.Min(score, 5.0); // Cap at 5.0
        }

        private double AnalyzeProcessModules(int processId)
        {
            double score = 0.0;

            try
            {
                var process = Process.GetProcessById(processId);
                
                foreach (ProcessModule module in process.Modules)
                {
                    string moduleName = module.ModuleName.ToLower();
                    
                    // Check for WPF-specific modules
                    if (moduleName == "presentationframework.dll")
                    {
                        score += 2.0;
                    }
                    else if (moduleName == "presentationcore.dll")
                    {
                        score += 1.5;
                    }
                    else if (moduleName == "windowsbase.dll")
                    {
                        score += 1.0;
                    }
                    else if (moduleName == "system.xaml.dll")
                    {
                        score += 0.5;
                    }
                    else if (moduleName.Contains("wpf") || 
                             moduleName.Contains("presentation"))
                    {
                        score += 0.5;
                    }
                }
            }
            catch
            {
                // Ignore process access errors
            }

            return Math.Min(score, 4.0); // Cap at 4.0
        }

        private double ScanForWpfSignatures(string folder, string exePath)
        {
            double score = 0.0;

            try
            {
                // Scan the executable
                if (File.Exists(exePath))
                {
                    score += ScanFileForEnginePatterns(exePath, WpfPatterns);
                }

                // Scan XAML files
                var xamlFiles = Directory.GetFiles(folder, "*.xaml", SearchOption.AllDirectories)
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var xamlFile in xamlFiles)
                {
                    score += ScanFileForEnginePatterns(xamlFile, WpfPatterns) * 0.5;
                }

                // Scan code-behind files
                var codeBehindFiles = Directory.GetFiles(folder, "*.xaml.cs", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "*.xaml.vb", SearchOption.AllDirectories))
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var codeFile in codeBehindFiles)
                {
                    // Code-behind files are strong indicators
                    score += 0.5;
                    score += ScanFileForEnginePatterns(codeFile, WpfPatterns) * 0.3;
                }

                // Check for App.xaml.cs which is common in WPF apps
                var appCodeFiles = Directory.GetFiles(folder, "App.xaml.cs", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(folder, "Application.xaml.cs", SearchOption.AllDirectories))
                    .Take(MAX_FILES_TO_ANALYZE);

                foreach (var appCodeFile in appCodeFiles)
                {
                    score += 1.0; // Strong indicator
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return Math.Min(score, 4.0); // Cap at 4.0
        }

        private double CheckForCompetingFrameworks(string folder, string exePath)
        {
            double competingScore = 0.0;
            
            try
            {
                // Check for presence of major UI frameworks or game engines that wouldn't be WPF
                string[] competingDlls = {
                    "UnityEngine.dll",      // Unity
                    "Godot.NET.dll",        // Godot
                    "MonoGame.Framework.dll", // MonoGame
                    "Microsoft.Xna.Framework.dll", // XNA
                    "Gtk-sharp.dll",        // GTK#
                    "Eto.dll",              // Eto.Forms
                    "Avalonia.dll",         // Avalonia UI (might be using similar patterns but not WPF)
                    "Xamarin.Forms.Core.dll", // Xamarin
                    "Microsoft.AspNetCore.dll" // ASP.NET Core (web)
                };

                foreach (var dll in competingDlls)
                {
                    if (Directory.GetFiles(folder, dll, SearchOption.AllDirectories).Length > 0)
                    {
                        competingScore += 1.0;
                    }
                }

                // Check for WinForms which could be integrated with WPF, so less competing
                if (Directory.GetFiles(folder, "System.Windows.Forms.dll", SearchOption.AllDirectories).Length > 0)
                {
                    competingScore += 0.5; // Weaker penalty as WPF and WinForms can be mixed
                }
            }
            catch
            {
                // Ignore errors
            }

            return Math.Min(competingScore, 3.0); // Cap at 3.0
        }

        private bool IsConsoleApplication(string exePath)
        {
            try
            {
                // This is a simplified check - a proper implementation would use PE header parsing
                // to check the subsystem flag (2 = GUI, 3 = Console)
                byte[] fileBytes = File.ReadAllBytes(exePath);
                
                // Look for common Console app patterns
                string fileContent = System.Text.Encoding.ASCII.GetString(fileBytes);
                
                bool hasConsolePatterns = fileContent.Contains("Console.WriteLine") || 
                                         fileContent.Contains("Console.ReadLine") ||
                                         fileContent.Contains("Console.ReadKey") ||
                                         fileContent.Contains("ConsoleApplication");
                
                // Check for WPF patterns that override the console evidence
                bool hasStrongWpfPatterns = fileContent.Contains("InitializeComponent") &&
                                           (fileContent.Contains("Application.Current") ||
                                            fileContent.Contains("System.Windows.Application"));
                
                return hasConsolePatterns && !hasStrongWpfPatterns;
            }
            catch
            {
                return false;
            }
        }
    }
} 