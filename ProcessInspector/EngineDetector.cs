using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PeNet;

namespace ProcessInspector
{
    public class EngineDetector : IEngineDetector
    {
        public string DetectEngine(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return "Unknown (Cannot access executable)";

            string folder = Path.GetDirectoryName(exePath);

            try
            {
                var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                    .Select(Path.GetFileName)
                    .ToList();

                var allFolders = Directory.GetDirectories(folder, "*", SearchOption.AllDirectories)
                    .Select(Path.GetFileName)
                    .ToList();

                // Game engines
                if (CheckForGameEngine(files, allFolders, out string gameEngine))
                    return gameEngine;

                // UI frameworks and other engines
                if (CheckForUIFramework(exePath, out string uiFramework))
                    return uiFramework;

                return "Unknown or Custom Engine";
            }
            catch (Exception ex)
            {
                return $"Engine detection error: {ex.Message}";
            }
        }

        private bool CheckForGameEngine(List<string> files, List<string> folders, out string engine)
        {
            // Dictionary of game engines and their identification files/folders
            var engineIdentifiers = new Dictionary<string, Func<List<string>, List<string>, bool>>
            {
                { "Unity", (f, d) => f.Any(file => file.Contains("UnityPlayer.dll", StringComparison.OrdinalIgnoreCase)) },
                { "Unreal Engine", (f, d) => f.Any(file => file.Contains("UE4", StringComparison.OrdinalIgnoreCase) ||
                                                    file.Contains("Unreal", StringComparison.OrdinalIgnoreCase)) },
                { "Godot", (f, d) => f.Any(file => file.Contains("godot", StringComparison.OrdinalIgnoreCase)) },
                { "MonoGame", (f, d) => f.Any(file => file.Contains("MonoGame", StringComparison.OrdinalIgnoreCase)) },
                { "LibGDX", (f, d) => f.Any(file => file.Contains("gdx", StringComparison.OrdinalIgnoreCase)) ||
                                     d.Any(dir => dir.Contains("libgdx", StringComparison.OrdinalIgnoreCase)) },
                { "Cocos2d", (f, d) => f.Any(file => file.Contains("cocos2d", StringComparison.OrdinalIgnoreCase)) },
                { "LÖVE", (f, d) => f.Any(file => file.Contains("love", StringComparison.OrdinalIgnoreCase) &&
                                                 !file.Contains("glove", StringComparison.OrdinalIgnoreCase)) },
                { "Phaser", (f, d) => f.Any(file => file.Contains("phaser", StringComparison.OrdinalIgnoreCase)) },
                { "PyGame", (f, d) => f.Any(file => file.Contains("pygame", StringComparison.OrdinalIgnoreCase)) },
                { "SDL2", (f, d) => f.Any(file => file.Contains("SDL2", StringComparison.OrdinalIgnoreCase)) },
                { "SFML", (f, d) => f.Any(file => file.Contains("sfml", StringComparison.OrdinalIgnoreCase)) },
                { "XNA Framework", (f, d) => f.Any(file => file.Contains("Microsoft.Xna", StringComparison.OrdinalIgnoreCase)) },
                { "jMonkeyEngine", (f, d) => f.Any(file => file.Contains("jMonkeyEngine", StringComparison.OrdinalIgnoreCase) ||
                                                          file.Contains("jME", StringComparison.OrdinalIgnoreCase)) },
                { "Panda3D", (f, d) => f.Any(file => file.Contains("panda3d", StringComparison.OrdinalIgnoreCase)) },
                { "OpenGL-based", (f, d) => f.Any(file => file.Contains("opengl32", StringComparison.OrdinalIgnoreCase) ||
                                                         file.Contains("glew", StringComparison.OrdinalIgnoreCase) ||
                                                         file.Contains("glfw", StringComparison.OrdinalIgnoreCase)) },
            };

            foreach (var engineEntry in engineIdentifiers)
            {
                if (engineEntry.Value(files, folders))
                {
                    engine = engineEntry.Key;
                    return true;
                }
            }

            engine = string.Empty;
            return false;
        }

        private bool CheckForUIFramework(string exePath, out string framework)
        {
            try
            {
                var peFile = new PeFile(exePath);

                // Check for web/desktop frameworks
                if (peFile.IsDotNet)
                {
                    var importedFunctions = peFile.ImportedFunctions ?? Array.Empty<PeNet.Header.Pe.ImportFunction>();
                    var importedNames = string.Join(" ", importedFunctions.Select(f => f.Name ?? ""));

                    if (importedNames.Contains("WindowsBase") || importedNames.Contains("PresentationCore"))
                    {
                        framework = "WPF (.NET)";
                        return true;
                    }

                    if (importedNames.Contains("System.Windows.Forms"))
                    {
                        framework = "Windows Forms (.NET)";
                        return true;
                    }

                    if (importedNames.Contains("Microsoft.AspNetCore"))
                    {
                        framework = "ASP.NET Core";
                        return true;
                    }

                    if (importedNames.Contains("System.Web"))
                    {
                        framework = "ASP.NET";
                        return true;
                    }

                    // Check for other frameworks
                    var importedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var importedFunction in importedFunctions)
                    {
                        if (!string.IsNullOrEmpty(importedFunction.DLL))
                        {
                            importedDlls.Add(importedFunction.DLL.ToLower());
                        }
                    }

                    if (importedDlls.Any(dll => dll.Contains("mono")))
                    {
                        framework = "Mono/.NET";
                        return true;
                    }

                    framework = ".NET Framework/Core";
                    return true;
                }

                // Check for other UI frameworks
                if (peFile.ImportedFunctions != null)
                {
                    var dlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var importedFunction in peFile.ImportedFunctions)
                    {
                        if (!string.IsNullOrEmpty(importedFunction.DLL))
                        {
                            dlls.Add(importedFunction.DLL.ToLower());
                        }
                    }

                    if (dlls.Any(d => d.Contains("qt")))
                    {
                        framework = "Qt";
                        return true;
                    }

                    if (dlls.Any(d => d.Contains("gtk")))
                    {
                        framework = "GTK";
                        return true;
                    }

                    if (dlls.Any(d => d.Contains("mfc")))
                    {
                        framework = "MFC";
                        return true;
                    }

                    if (dlls.Any(d => d.Contains("javaw") || d.Contains("jvm")))
                    {
                        framework = "Java";
                        return true;
                    }

                    if (dlls.Any(d => d.Contains("python")))
                    {
                        framework = "Python";
                        return true;
                    }

                    // Check for web frameworks
                    if (dlls.Any(d => d.Contains("electron") || d.Contains("node")))
                    {
                        framework = "Electron";
                        return true;
                    }
                }
            }
            catch
            {
                // PE analysis failed
            }

            framework = string.Empty;
            return false;
        }
    }
}