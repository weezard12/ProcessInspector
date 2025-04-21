using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using PeNet;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ProcessInspector
{
    public class EngineDetector : IEngineDetector
    {
        // Maximum file size to analyze (to prevent analyzing very large files)
        private const int MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

        // Maximum number of files to analyze in a directory
        private const int MAX_FILES_TO_ANALYZE = 150;

        // Minimum score threshold for engine detection
        private const double MIN_ENGINE_SCORE = 5.0;

        // Known file hashes (MD5) for specific engine versions
        private static readonly Dictionary<string, string> EngineFileHashes = new Dictionary<string, string>
        {
            // Unity Engine DLLs
            ["607A4C0356CD7CDF29594899D8C2E46D"] = "Unity Engine (2022.x)",
            ["A9721EBAA172AB24F47EF7B5272C1CB9"] = "Unity Engine (2021.x)",
            ["59C3FE609281AD35B8B3A99EFAE644D5"] = "Unity Engine (2020.x)",

            // Unreal Engine DLLs
            ["F4EF26C7EF6D5E5E9FFF0EB02E51A972"] = "Unreal Engine 5",
            ["B936B2E1D45DB38E3670479A67E7B561"] = "Unreal Engine 4",

            // Godot Engine files
            ["27FDC21D1F2BC499EC6E577DD166E48C"] = "Godot Engine (4.x)",
            ["C2E4931C3E706860E4F9FB7D9C4C3B67"] = "Godot Engine (3.x)",

            // Qt Framework DLLs
            ["C7D56A6F3B5C4FCFAE828FA7FA8A4042"] = "Qt Framework (6.x)",
            ["A1F9CF341D9D9820E2B3C7C789F75489"] = "Qt Framework (5.x)"
        };

        // Regex patterns for engine detection in file content
        private static readonly Dictionary<string, Regex> EnginePatterns = new Dictionary<string, Regex>
        {
            ["Unity"] = new Regex(@"(UnityEngine|Unity Player|Made with Unity)", RegexOptions.Compiled),
            ["Unreal Engine"] = new Regex(@"(UnrealEngine|Epic Games|UE4|UE5)", RegexOptions.Compiled),
            ["Godot"] = new Regex(@"(Godot Engine|godot::)", RegexOptions.Compiled),
            ["MonoGame"] = new Regex(@"(MonoGame\.|Microsoft\.Xna\.|MonoGame Framework)", RegexOptions.Compiled),
            ["LibGDX"] = new Regex(@"(com\.badlogic\.gdx|libgdx)", RegexOptions.Compiled),
            ["Cocos2d"] = new Regex(@"(cocos2d|CCDirector|CC_DLL)", RegexOptions.Compiled),
            ["PyGame"] = new Regex(@"(pygame\.|import pygame)", RegexOptions.Compiled),
            ["Qt"] = new Regex(@"(QApplication|QWidget|QObject|QT_VERSION|QtCore)", RegexOptions.Compiled),
            ["GTK"] = new Regex(@"(gtk_|GTK\+|libgtk)", RegexOptions.Compiled),
            ["Electron"] = new Regex(@"(Electron|electron\.asar|app\.asar)", RegexOptions.Compiled),
            ["React Native"] = new Regex(@"(React Native|ReactNative|react-native)", RegexOptions.Compiled),
            ["Flutter"] = new Regex(@"(flutter_|io\.flutter\.|Flutter Engine)", RegexOptions.Compiled),
            ["SDL"] = new Regex(@"(SDL_Init|SDL_CreateWindow|SDL2\.dll)", RegexOptions.Compiled),
            ["SFML"] = new Regex(@"(sf::|\bSFML\b|sfml-)", RegexOptions.Compiled),
            ["JavaFX"] = new Regex(@"(javafx\.|com\.sun\.javafx|JavaFX Application)", RegexOptions.Compiled),
            ["OpenGL"] = new Regex(@"(glVertex|glBegin|OpenGL|glfw)", RegexOptions.Compiled),
            ["Vulkan"] = new Regex(@"(VkInstance|vkCreate|vulkan\.h)", RegexOptions.Compiled),
            ["DirectX"] = new Regex(@"(DirectX|D3D11|IDXGISwapChain)", RegexOptions.Compiled),
            ["CryEngine"] = new Regex(@"(CryEngine|CrySystem|CRYENGINE)", RegexOptions.Compiled),
            ["GameMaker"] = new Regex(@"(GameMaker|GM_runtime|YoYo Games)", RegexOptions.Compiled),
            ["RPG Maker"] = new Regex(@"(RPG Maker|RGSS|RPGMaker)", RegexOptions.Compiled),
            ["Construct"] = new Regex(@"(Construct 2|Construct 3|c2runtime|c3runtime)", RegexOptions.Compiled),
            ["XNA Framework"] = new Regex(@"(Microsoft\.Xna\.|XNA Framework)", RegexOptions.Compiled),
            ["jMonkeyEngine"] = new Regex(@"(jMonkeyEngine|com\.jme3\.|jME3)", RegexOptions.Compiled),
            ["Panda3D"] = new Regex(@"(Panda3D|libpanda|p3d)", RegexOptions.Compiled)
        };

        public string DetectEngine(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return "Unknown (Cannot access executable)";

            try
            {
                // Create a scoring system for different engines
                var engineScores = InitializeEngineScores();

                // Get directory information
                string folder = Path.GetDirectoryName(exePath);

                // First try hash-based detection for fastest and most accurate results
                string hashBasedEngine = DetectEngineByHash(exePath, folder);
                if (!string.IsNullOrEmpty(hashBasedEngine))
                {
                    return hashBasedEngine;
                }

                // Get the process if it's running
                int? processId = GetProcessIdByExecutablePath(exePath);
                if (processId.HasValue)
                {
                    AnalyzeRunningProcess(processId.Value, engineScores);
                }

                // Directory-based detection
                AnalyzeDirectory(folder, engineScores);

                // PE file-based detection
                AnalyzePeFile(exePath, engineScores);

                // Deep content scanning
                DeepScanFiles(folder, engineScores);

                // Process the scores to determine the most likely engine
                string detectedEngine = DetermineTopEngine(engineScores);

                // If a specific engine was detected with high confidence
                if (!string.IsNullOrEmpty(detectedEngine))
                {
                    return detectedEngine;
                }

                // Fallback to UI framework detection if no game engine was detected
                string uiFramework = DetectUIFramework(exePath, folder);
                if (!string.IsNullOrEmpty(uiFramework))
                {
                    return uiFramework;
                }

                return "Unknown or Custom Engine";
            }
            catch (Exception ex)
            {
                return $"Engine detection error: {ex.Message}";
            }
        }

        private Dictionary<string, double> InitializeEngineScores()
        {
            return new Dictionary<string, double>
            {
                // Game engines
                ["Unity"] = 0,
                ["Unreal Engine"] = 0,
                ["Godot"] = 0,
                ["MonoGame"] = 0,
                ["LibGDX"] = 0,
                ["Cocos2d"] = 0,
                ["PyGame"] = 0,
                ["LÖVE"] = 0,
                ["Phaser"] = 0,
                ["SDL"] = 0,
                ["SFML"] = 0,
                ["XNA Framework"] = 0,
                ["jMonkeyEngine"] = 0,
                ["Panda3D"] = 0,
                ["CryEngine"] = 0,
                ["GameMaker"] = 0,
                ["Construct"] = 0,
                ["RPG Maker"] = 0,

                // UI frameworks
                ["Qt"] = 0,
                ["GTK"] = 0,
                ["WPF"] = 0,
                ["Windows Forms"] = 0,
                ["Electron"] = 0,
                ["JavaFX"] = 0,
                ["Avalonia"] = 0,
                ["Flutter"] = 0,
                ["React Native"] = 0,
                ["MFC"] = 0
            };
        }

        private string DetectEngineByHash(string exePath, string folder)
        {
            try
            {
                // Check files that are commonly associated with engines
                var engineFilePatterns = new Dictionary<string, List<string>>
                {
                    ["Unity"] = new List<string> { "UnityPlayer.dll", "UnityEngine*.dll" },
                    ["Unreal Engine"] = new List<string> { "UE*.dll", "Core.dll", "Engine.dll" },
                    ["Godot"] = new List<string> { "godot*.dll", "libgodot*.so" },
                    ["MonoGame"] = new List<string> { "MonoGame*.dll" },
                    ["Qt"] = new List<string> { "Qt*.dll", "QtCore*.dll" },
                    ["Electron"] = new List<string> { "electron.dll", "chrome_*.dll" }
                };

                // Search for engine-specific files
                foreach (var engineEntry in engineFilePatterns)
                {
                    foreach (var pattern in engineEntry.Value)
                    {
                        // Look for files matching the pattern in the main folder and immediate subfolders
                        foreach (var file in Directory.GetFiles(folder, pattern, SearchOption.AllDirectories)
                                             .Take(20)) // Limit search to prevent performance issues
                        {
                            // Calculate hash and check against known hashes
                            string hash = CalculateMD5Hash(file);
                            if (EngineFileHashes.TryGetValue(hash, out string knownEngine))
                            {
                                return knownEngine; // We found a precise match!
                            }
                        }
                    }
                }

                return null; // No hash-based match found
            }
            catch
            {
                return null; // Error in hash detection, continue with other methods
            }
        }

        private string CalculateMD5Hash(string filePath)
        {
            try
            {
                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "");
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private int? GetProcessIdByExecutablePath(string exePath)
        {
            try
            {
                foreach (Process process in Process.GetProcesses())
                {
                    try
                    {
                        // Skip system processes where we don't have access
                        if (process.MainModule == null)
                            continue;

                        if (string.Equals(process.MainModule.FileName, exePath, StringComparison.OrdinalIgnoreCase))
                        {
                            return process.Id;
                        }
                    }
                    catch
                    {
                        // Skip processes we can't access
                        continue;
                    }
                }
            }
            catch
            {
                // Process enumeration failed
            }

            return null;
        }

        private void AnalyzeRunningProcess(int processId, Dictionary<string, double> engineScores)
        {
            try
            {
                var process = Process.GetProcessById(processId);

                // Check process name for clues
                string processName = process.ProcessName.ToLower();
                if (processName.Contains("unity"))
                    engineScores["Unity"] += 3.0;
                if (processName.Contains("ue4") || processName.Contains("ue5") || processName.Contains("unreal"))
                    engineScores["Unreal Engine"] += 3.0;
                if (processName.Contains("godot"))
                    engineScores["Godot"] += 3.0;

                // Get all loaded modules
                try
                {
                    ProcessModuleCollection modules = process.Modules;
                    foreach (ProcessModule module in modules)
                    {
                        string moduleName = module.ModuleName.ToLower();
                        string fileName = Path.GetFileName(module.FileName).ToLower();

                        // Check module names for engine signatures
                        CheckModuleForEngineSignatures(moduleName, engineScores);
                        CheckModuleForEngineSignatures(fileName, engineScores);
                    }
                }
                catch
                {
                    // Failed to access modules
                }

                // Get command line arguments (Windows only)
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    string commandLine = GetProcessCommandLine(processId);
                    if (!string.IsNullOrEmpty(commandLine))
                    {
                        foreach (var enginePattern in EnginePatterns)
                        {
                            if (enginePattern.Value.IsMatch(commandLine))
                            {
                                engineScores[enginePattern.Key] += 2.0;
                            }
                        }
                    }
                }
            }
            catch
            {
                // Process analysis failed
            }
        }

        private void CheckModuleForEngineSignatures(string moduleName, Dictionary<string, double> engineScores)
        {
            if (moduleName.Contains("unity"))
                engineScores["Unity"] += 4.0;
            else if (moduleName.Contains("ue4") || moduleName.Contains("ue5") || moduleName.Contains("unreal"))
                engineScores["Unreal Engine"] += 4.0;
            else if (moduleName.Contains("godot"))
                engineScores["Godot"] += 4.0;
            else if (moduleName.Contains("monogame"))
                engineScores["MonoGame"] += 4.0;
            else if (moduleName.Contains("libgdx"))
                engineScores["LibGDX"] += 4.0;
            else if (moduleName.Contains("cocos2d"))
                engineScores["Cocos2d"] += 4.0;
            else if (moduleName.Contains("pygame"))
                engineScores["PyGame"] += 4.0;
            else if (moduleName.Contains("love"))
                engineScores["LÖVE"] += 4.0;
            else if (moduleName.Contains("phaser"))
                engineScores["Phaser"] += 4.0;
            else if (moduleName.Contains("sdl2") || moduleName.Contains("sdl.dll"))
                engineScores["SDL"] += 4.0;
            else if (moduleName.Contains("sfml"))
                engineScores["SFML"] += 4.0;
            else if (moduleName.Contains("xna"))
                engineScores["XNA Framework"] += 4.0;
            else if (moduleName.Contains("jmonkey"))
                engineScores["jMonkeyEngine"] += 4.0;
            else if (moduleName.Contains("panda3d"))
                engineScores["Panda3D"] += 4.0;
            else if (moduleName.Contains("cryengine"))
                engineScores["CryEngine"] += 4.0;
            else if (moduleName.Contains("gamemaker"))
                engineScores["GameMaker"] += 4.0;
            else if (moduleName.Contains("construct"))
                engineScores["Construct"] += 4.0;
            else if (moduleName.Contains("rpgmaker") || moduleName.Contains("rgss"))
                engineScores["RPG Maker"] += 4.0;
            else if (moduleName.Contains("qt") || moduleName.Contains("qtcore"))
                engineScores["Qt"] += 4.0;
            else if (moduleName.Contains("gtk"))
                engineScores["GTK"] += 4.0;
            else if (moduleName.Contains("electron"))
                engineScores["Electron"] += 4.0;
            else if (moduleName.Contains("javafx"))
                engineScores["JavaFX"] += 4.0;
            else if (moduleName.Contains("flutter"))
                engineScores["Flutter"] += 4.0;
            else if (moduleName.Contains("react-native"))
                engineScores["React Native"] += 4.0;
            else if (moduleName.Contains("opengl"))
                engineScores["OpenGL"] += 2.0;
            else if (moduleName.Contains("vulkan"))
                engineScores["Vulkan"] += 2.0;
            else if (moduleName.Contains("d3d") || moduleName.Contains("directx"))
                engineScores["DirectX"] += 2.0;
            else if (moduleName.Contains("metal"))
                engineScores["Metal"] += 2.0;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public IntPtr[] Reserved2;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;

        private string GetProcessCommandLine(int processId)
        {
            try
            {
                var processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
                if (processHandle == IntPtr.Zero)
                    return string.Empty;

                try
                {
                    // This is a simplified version - getting the actual command line requires more complex code
                    // For a complete implementation, you would need to read the PEB structure
                    return $"Process ID: {processId}"; // Placeholder
                }
                finally
                {
                    CloseHandle(processHandle);
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private void AnalyzeDirectory(string folder, Dictionary<string, double> engineScores)
        {
            try
            {
                var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                    .Select(Path.GetFileName)
                    .Take(MAX_FILES_TO_ANALYZE)
                    .ToList();

                var allFolders = Directory.GetDirectories(folder, "*", SearchOption.AllDirectories)
                    .Select(Path.GetFileName)
                    .Take(MAX_FILES_TO_ANALYZE)
                    .ToList();

                // Dictionary mapping file patterns to engines with weight scores
                var filePatterns = new Dictionary<string, (string Engine, double Weight)>
                {
                    // Unity Engine
                    ["UnityPlayer.dll"] = ("Unity", 10.0),
                    ["UnityEngine"] = ("Unity", 8.0),
                    ["Assembly-CSharp.dll"] = ("Unity", 7.0),
                    ["Unity.*.dll"] = ("Unity", 5.0),
                    ["Resources.assets"] = ("Unity", 4.0),
                    ["globalgamemanagers"] = ("Unity", 6.0),
                    ["level*"] = ("Unity", 2.0),

                    // Unreal Engine
                    ["UE"] = ("Unreal Engine", 5.0),
                    ["Unreal"] = ("Unreal Engine", 8.0),
                    [".uasset"] = ("Unreal Engine", 6.0),
                    [".umap"] = ("Unreal Engine", 6.0),
                    ["Engine.dll"] = ("Unreal Engine", 4.0),
                    ["UnrealEd.dll"] = ("Unreal Engine", 7.0),

                    // Godot
                    ["godot"] = ("Godot", 9.0),
                    [".godot"] = ("Godot", 7.0),
                    [".tscn"] = ("Godot", 6.0),
                    [".gd"] = ("Godot", 5.0),
                    ["project.godot"] = ("Godot", 10.0),

                    // MonoGame
                    ["MonoGame"] = ("MonoGame", 9.0),
                    [".mgcb"] = ("MonoGame", 7.0),

                    // LibGDX
                    ["gdx"] = ("LibGDX", 7.0),
                    ["libgdx"] = ("LibGDX", 8.0),

                    // Cocos2d
                    ["cocos2d"] = ("Cocos2d", 8.0),
                    [".cocos"] = ("Cocos2d", 7.0),

                    // LÖVE
                    ["love.dll"] = ("LÖVE", 9.0),
                    [".love"] = ("LÖVE", 7.0),

                    // Phaser
                    ["phaser"] = ("Phaser", 8.0),
                    ["phaser.min.js"] = ("Phaser", 10.0),

                    // PyGame
                    ["pygame"] = ("PyGame", 9.0),

                    // SDL
                    ["SDL2.dll"] = ("SDL", 9.0),
                    ["libSDL2"] = ("SDL", 8.0),

                    // SFML
                    ["sfml"] = ("SFML", 8.0),
                    ["sfml-graphics"] = ("SFML", 9.0),

                    // XNA
                    ["XNA"] = ("XNA Framework", 8.0),
                    ["Microsoft.Xna"] = ("XNA Framework", 9.0),

                    // CryEngine
                    ["CryEngine"] = ("CryEngine", 9.0),
                    [".cry"] = ("CryEngine", 7.0),

                    // GameMaker
                    ["GameMaker"] = ("GameMaker", 8.0),
                    [".gmk"] = ("GameMaker", 7.0),
                    [".gmx"] = ("GameMaker", 7.0),
                    [".yyp"] = ("GameMaker", 7.0),

                    // Construct
                    ["construct"] = ("Construct", 7.0),
                    [".capx"] = ("Construct", 9.0),
                    [".c2"] = ("Construct", 8.0),
                    [".c3"] = ("Construct", 8.0),

                    // RPG Maker
                    ["RPG Maker"] = ("RPG Maker", 8.0),
                    [".rpgproject"] = ("RPG Maker", 9.0),
                    [".rxproj"] = ("RPG Maker", 9.0),

                    // Qt
                    ["Qt"] = ("Qt", 7.0),
                    ["QtCore"] = ("Qt", 9.0),
                    ["QtWidgets"] = ("Qt", 8.0),
                    ["QtGui"] = ("Qt", 8.0),
                    [".qml"] = ("Qt", 6.0),

                    // GTK
                    ["gtk"] = ("GTK", 7.0),
                    ["libgtk"] = ("GTK", 8.0),

                    // WPF
                    ["PresentationCore.dll"] = ("WPF", 9.0),
                    ["PresentationFramework.dll"] = ("WPF", 9.0),
                    ["WindowsBase.dll"] = ("WPF", 8.0),
                    [".xaml"] = ("WPF", 6.0),

                    // Windows Forms
                    ["System.Windows.Forms.dll"] = ("Windows Forms", 9.0),

                    // Electron
                    ["electron.exe"] = ("Electron", 10.0),
                    ["electron.dll"] = ("Electron", 9.0),
                    ["app.asar"] = ("Electron", 8.0),

                    // JavaFX
                    ["javafx"] = ("JavaFX", 8.0),
                    ["jfx"] = ("JavaFX", 7.0),

                    // Avalonia
                    ["Avalonia"] = ("Avalonia", 8.0),
                    [".avalonia"] = ("Avalonia", 7.0),

                    // Flutter
                    ["flutter"] = ("Flutter", 8.0),
                    [".dart"] = ("Flutter", 6.0),
                    ["flutter_assets"] = ("Flutter", 9.0),

                    // React Native
                    ["react-native"] = ("React Native", 8.0),

                    // Graphics APIs
                    ["opengl32.dll"] = ("OpenGL", 7.0),
                    ["glew"] = ("OpenGL", 6.0),
                    ["glfw"] = ("OpenGL", 6.0),

                    ["vulkan"] = ("Vulkan", 7.0),
                    ["vk_layer"] = ("Vulkan", 6.0),

                    ["d3d11.dll"] = ("DirectX", 7.0),
                    ["d3dx"] = ("DirectX", 6.0),
                    ["dxgi.dll"] = ("DirectX", 6.0),

                    ["metal"] = ("Metal", 7.0),

                    // MFC
                    ["mfc"] = ("MFC", 8.0),
                    ["afxwin"] = ("MFC", 7.0)
                };

                // Check files against patterns
                foreach (var file in files)
                {
                    foreach (var patternEntry in filePatterns)
                    {
                        if (StringContainsWildcard(file, patternEntry.Key))
                        {
                            engineScores[patternEntry.Value.Engine] += patternEntry.Value.Weight;
                        }
                    }
                }

                // Check folders against patterns
                foreach (var subFolder in allFolders) // Renamed variable to avoid conflict
                {
                    foreach (var patternEntry in filePatterns)
                    {
                        if (StringContainsWildcard(subFolder, patternEntry.Key))
                        {
                            engineScores[patternEntry.Value.Engine] += patternEntry.Value.Weight;
                        }
                    }
                }

                // Special folder checks for more accuracy
                foreach (var subFolder in allFolders) // Renamed variable to avoid conflict
                {
                    // Unity uses Assets folder prominently
                    if (subFolder.Equals("Assets", StringComparison.OrdinalIgnoreCase))
                    {
                        engineScores["Unity"] += 3.0;
                    }

                    // Unreal uses Content folder prominently
                    if (subFolder.Equals("Content", StringComparison.OrdinalIgnoreCase))
                    {
                        engineScores["Unreal Engine"] += 2.0;
                    }

                    // Godot specific folders
                    if (subFolder.Equals("res://", StringComparison.OrdinalIgnoreCase) ||
                        subFolder.Equals("addons", StringComparison.OrdinalIgnoreCase))
                    {
                        engineScores["Godot"] += 3.0;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Directory analysis error: {ex.Message}");
            }
        }

        private bool StringContainsWildcard(string source, string pattern)
        {
            if (pattern.Contains("*"))
            {
                // Convert wildcard pattern to regex
                string regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
                return Regex.IsMatch(source, regexPattern, RegexOptions.IgnoreCase);
            }
            else
            {
                // Simple contains check
                return source.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0;
            }
        }

        private void AnalyzePeFile(string exePath, Dictionary<string, double> engineScores)
        {
            try
            {
                var peFile = new PeFile(exePath);

                // Check if the file is a .NET assembly
                if (peFile.IsDotNet)
                {
                    engineScores["WPF"] += 2.0;
                    engineScores["Windows Forms"] += 2.0;
                    engineScores["MonoGame"] += 1.0;
                    engineScores["XNA Framework"] += 1.0;
                    engineScores["Unity"] += 1.0; // Unity uses .NET but needs more evidence
                }

                // Check imported DLLs and functions
                if (peFile.ImportedFunctions != null)
                {
                    // Extract all imported DLLs
                    var importedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var importedFunction in peFile.ImportedFunctions)
                    {
                        if (!string.IsNullOrEmpty(importedFunction.DLL))
                        {
                            string dll = importedFunction.DLL.ToLower();
                            importedDlls.Add(dll);

                            // Check function names for additional clues
                            string funcName = importedFunction.Name?.ToLower() ?? "";

                            if (funcName.Contains("unity") || funcName.Contains("mono"))
                            {
                                engineScores["Unity"] += 2.0;
                            }

                            if (funcName.Contains("unreal") || funcName.Contains("ue4") || funcName.Contains("ue5"))
                            {
                                engineScores["Unreal Engine"] += 2.0;
                            }

                            if (funcName.Contains("sdl_"))
                            {
                                engineScores["SDL2"] += 2.0;
                            }

                            if (funcName.Contains("sfml"))
                            {
                                engineScores["SFML"] += 2.0;
                            }

                            if (funcName.Contains("opengl") || funcName.Contains("gl"))
                            {
                                engineScores["OpenGL"] += 1.0;
                            }

                            if (funcName.Contains("d3d") || funcName.Contains("directx"))
                            {
                                engineScores["DirectX"] += 1.0;
                            }

                            if (funcName.Contains("vulkan") || funcName.Contains("vk"))
                            {
                                engineScores["Vulkan"] += 1.0;
                            }
                        }
                    }

                    // Check for specific engine DLLs
                    foreach (var dll in importedDlls)
                    {
                        if (dll.Contains("unity"))
                        {
                            engineScores["Unity"] += 5.0;
                        }
                        else if (dll.Contains("unreal") || dll.Contains("ue4") || dll.Contains("ue5"))
                        {
                            engineScores["Unreal Engine"] += 5.0;
                        }
                        else if (dll.Contains("godot"))
                        {
                            engineScores["Godot"] += 5.0;
                        }
                        else if (dll.Contains("monogame"))
                        {
                            engineScores["MonoGame"] += 5.0;
                        }
                        else if (dll.Contains("xna"))
                        {
                            engineScores["XNA Framework"] += 5.0;
                        }
                        else if (dll.Contains("sdl2"))
                        {
                            engineScores["SDL2"] += 4.0;
                        }
                        else if (dll.Contains("sfml"))
                        {
                            engineScores["SFML"] += 4.0;
                        }
                        else if (dll.Contains("qt") || dll.Contains("qtcore"))
                        {
                            engineScores["Qt"] += 5.0;
                        }
                        else if (dll.Contains("gtk"))
                        {
                            engineScores["GTK"] += 5.0;
                        }
                        else if (dll.Contains("windowsbase") || dll.Contains("presentationcore"))
                        {
                            engineScores["WPF"] += 5.0;
                        }
                        else if (dll.Contains("system.windows.forms"))
                        {
                            engineScores["Windows Forms"] += 5.0;
                        }
                        else if (dll.Contains("electron") || dll.Contains("node"))
                        {
                            engineScores["Electron"] += 5.0;
                        }
                        else if (dll.Contains("javafx") || dll.Contains("jfrt"))
                        {
                            engineScores["JavaFX"] += 5.0;
                        }
                        else if (dll.Contains("avalonia"))
                        {
                            engineScores["Avalonia"] += 5.0;
                        }
                        else if (dll.Contains("flutter"))
                        {
                            engineScores["Flutter"] += 5.0;
                        }
                        else if (dll.Contains("opengl32") || dll.Contains("glew") || dll.Contains("glfw"))
                        {
                            engineScores["OpenGL"] += 3.0;
                        }
                        else if (dll.Contains("vulkan") || dll.Contains("vk_layer"))
                        {
                            engineScores["Vulkan"] += 3.0;
                        }
                        else if (dll.Contains("d3d11") || dll.Contains("dxgi") || dll.Contains("d3dx"))
                        {
                            engineScores["DirectX"] += 3.0;
                        }
                    }
                }

                // Check PE sections for engine-specific patterns
                if (peFile.ImageSectionHeaders != null)
                {
                    foreach (var section in peFile.ImageSectionHeaders)
                    {
                        string sectionName = section.Name?.ToLower() ?? "";

                        if (sectionName.Contains("unity"))
                        {
                            engineScores["Unity"] += 3.0;
                        }

                        if (sectionName.Contains("unreal"))
                        {
                            engineScores["Unreal Engine"] += 3.0;
                        }

                        if (sectionName.Contains("godot"))
                        {
                            engineScores["Godot"] += 3.0;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PE analysis error: {ex.Message}");
            }
        }

        private void DeepScanFiles(string folder, Dictionary<string, double> engineScores)
        {
            try
            {
                // Look for specific file types that might contain engine information
                var filesToScan = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                    .Where(f => {
                        string ext = Path.GetExtension(f).ToLower();
                        return ext == ".dll" || ext == ".exe" || ext == ".xml" || ext == ".json" ||
                               ext == ".txt" || ext == ".ini" || ext == ".config" || ext == ".manifest";
                    })
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

                        // Check if it's a binary or text file
                        bool isBinary = IsBinaryFile(file);

                        if (isBinary)
                        {
                            // For binary files, just look for strings
                            ScanBinaryFileForEngineSignatures(file, engineScores);
                        }
                        else
                        {
                            // For text files, read and analyze content
                            ScanTextFileForEngineSignatures(file, engineScores);
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
        private void ScanTextFileForEngineSignatures(string filePath, Dictionary<string, double> engineScores)
        {
            string content = File.ReadAllText(filePath);

            // Check for engine signatures
            foreach (var enginePattern in EnginePatterns)
            {
                int matches = enginePattern.Value.Matches(content).Count;
                if (matches > 0)
                {
                    double score = Math.Min(matches * 1.0, 5.0);
                    engineScores[enginePattern.Key] += score;
                }
            }

            // Additional check for specific configuration file markers
            string fileName = Path.GetFileName(filePath).ToLower();

            if (fileName == "project.godot" || fileName.EndsWith(".godot"))
            {
                engineScores["Godot"] += 10.0;
            }

            if (fileName == "assembly-csharp.dll.mdb" || fileName == "assembly-csharp.dll")
            {
                engineScores["Unity"] += 8.0;
            }

            if (fileName == "unrealengineobjectversion.txt" || fileName.EndsWith(".uproject"))
            {
                engineScores["Unreal Engine"] += 10.0;
            }

            if (fileName == "monogame.framework.dll.config")
            {
                engineScores["MonoGame"] += 8.0;
            }

            if (fileName == "app.asar")
            {
                engineScores["Electron"] += 8.0;
            }
        }

        private bool IsBinaryFile(string filePath)
        {
            // Simple check - read the first 4KB and look for nulls
            const int checkLength = 4096;

            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[Math.Min(checkLength, (int)stream.Length)];
                stream.Read(buffer, 0, buffer.Length);

                // If we find null bytes or non-ASCII characters in the first 4KB, consider it binary
                return buffer.Any(b => b == 0 || b > 127);
            }
        }

        private void ScanBinaryFileForEngineSignatures(string filePath, Dictionary<string, double> engineScores)
        {
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[Math.Min(MAX_FILE_SIZE_BYTES, (int)stream.Length)];
                stream.Read(buffer, 0, buffer.Length);

                // Extract potential ASCII strings from binary
                string content = Encoding.ASCII.GetString(buffer);

                // Check for engine signatures
                foreach (var enginePattern in EnginePatterns)
                {
                    int matches = enginePattern.Value.Matches(content).Count;
                    if (matches > 0)
                    {
                        double score = Math.Min(matches * 0.5, 3.0);
                        engineScores[enginePattern.Key] += score;
                    }
                }
            }
        }

        private string DetermineTopEngine(Dictionary<string, double> engineScores)
        {
            // Get the engine with the highest score
            var topEngine = engineScores.OrderByDescending(pair => pair.Value).FirstOrDefault();

            // If the top score is below the threshold, it's not conclusive
            if (topEngine.Value < MIN_ENGINE_SCORE)
            {
                return null;
            }

            // Check if the top engine is a game engine
            var gameEngines = new HashSet<string>
            {
                "Unity", "Unreal Engine", "Godot", "MonoGame", "LibGDX", "Cocos2d",
                "PyGame", "LÖVE", "Phaser", "SDL", "SFML", "XNA Framework",
                "jMonkeyEngine", "Panda3D", "CryEngine", "GameMaker", "Construct", "RPG Maker"
            };

            if (gameEngines.Contains(topEngine.Key))
            {
                // Check for graphics API usage
                string graphicsApi = DetectGraphicsApi();
                if (!string.IsNullOrEmpty(graphicsApi))
                {
                    return $"{topEngine.Key} Game Engine (using {graphicsApi})";
                }
                return $"{topEngine.Key} Game Engine";
            }

            // Check if it's a UI framework
            var uiFrameworks = new HashSet<string>
            {
                "Qt", "GTK", "WPF", "Windows Forms", "Electron", "JavaFX",
                "Avalonia", "Flutter", "React Native", "MFC"
            };

            if (uiFrameworks.Contains(topEngine.Key))
            {
                // Check for graphics API usage
                string graphicsApi = DetectGraphicsApi();
                if (!string.IsNullOrEmpty(graphicsApi))
                {
                    return $"{topEngine.Key} UI Framework (using {graphicsApi})";
                }
                return $"{topEngine.Key} UI Framework";
            }

            // If we got here, it's something else with a high score
            return topEngine.Key;
        }

        private string DetectGraphicsApi()
        {
            try
            {
                var graphicsApiScores = new Dictionary<string, double>
                {
                    ["OpenGL"] = 0,
                    ["Vulkan"] = 0,
                    ["DirectX"] = 0,
                    ["Metal"] = 0
                };

                // Check loaded modules for graphics API DLLs
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    string moduleName = module.ModuleName.ToLower();
                    
                    if (moduleName.Contains("opengl32") || moduleName.Contains("glew") || moduleName.Contains("glfw"))
                    {
                        graphicsApiScores["OpenGL"] += 3.0;
                    }
                    else if (moduleName.Contains("vulkan") || moduleName.Contains("vk_layer"))
                    {
                        graphicsApiScores["Vulkan"] += 3.0;
                    }
                    else if (moduleName.Contains("d3d11") || moduleName.Contains("dxgi") || moduleName.Contains("d3dx"))
                    {
                        graphicsApiScores["DirectX"] += 3.0;
                    }
                    else if (moduleName.Contains("metal"))
                    {
                        graphicsApiScores["Metal"] += 3.0;
                    }
                }

                // Get the highest scoring graphics API
                var topGraphicsApi = graphicsApiScores.OrderByDescending(pair => pair.Value).FirstOrDefault();
                if (topGraphicsApi.Value >= 3.0) // Minimum threshold for graphics API detection
                {
                    return topGraphicsApi.Key;
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        private string DetectUIFramework(string exePath, string folder)
        {
            try
            {
                var peFile = new PeFile(exePath);

                // Check for .NET assembly
                if (peFile.IsDotNet)
                {
                    if (Directory.GetFiles(folder, "*.xaml", SearchOption.AllDirectories).Any())
                    {
                        return "WPF UI Framework";
                    }

                    // Check for Windows Forms references
                    if (peFile.ImportedFunctions != null)
                    {
                        string allFunctionNames = string.Join(" ", peFile.ImportedFunctions.Select(f => f.Name?.ToLower() ?? ""));
                        if (allFunctionNames.Contains("system.windows.forms"))
                        {
                            return "Windows Forms UI Framework";
                        }
                    }

                    return ".NET UI Framework";
                }

                // Check for QtWidgets references
                if (peFile.ImportedFunctions != null)
                {
                    var importedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var importedFunction in peFile.ImportedFunctions)
                    {
                        if (!string.IsNullOrEmpty(importedFunction.DLL))
                        {
                            importedDlls.Add(importedFunction.DLL.ToLower());
                        }
                    }

                    if (importedDlls.Any(dll => dll.Contains("qtcore") || dll.Contains("qtwidgets") || dll.Contains("qtgui")))
                    {
                        return "Qt UI Framework";
                    }

                    if (importedDlls.Any(dll => dll.Contains("gtk")))
                    {
                        return "GTK UI Framework";
                    }

                    if (importedDlls.Any(dll => dll.Contains("electron") || dll.Contains("node")))
                    {
                        return "Electron Framework";
                    }

                    if (importedDlls.Any(dll => dll.Contains("mfc")))
                    {
                        return "MFC UI Framework";
                    }
                }

                // Check for web-based applications
                if (Directory.GetFiles(folder, "*.html", SearchOption.TopDirectoryOnly).Any() ||
                    Directory.GetFiles(folder, "*.js", SearchOption.TopDirectoryOnly).Any())
                {
                    if (File.Exists(Path.Combine(folder, "package.json")))
                    {
                        string packageJson = File.ReadAllText(Path.Combine(folder, "package.json"));
                        if (packageJson.Contains("\"react-native\""))
                        {
                            return "React Native Framework";
                        }
                        if (packageJson.Contains("\"electron\""))
                        {
                            return "Electron Framework";
                        }
                    }

                    return "Web-based Application";
                }

                // Check for Flutter
                if (Directory.GetFiles(folder, "*.dart", SearchOption.AllDirectories).Any())
                {
                    return "Flutter UI Framework";
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        public double DetectEngineProbability(string exePath)
        {
            throw new NotImplementedException();
        }

        public string GetEngineName()
        {
            throw new NotImplementedException();
        }
    }
}