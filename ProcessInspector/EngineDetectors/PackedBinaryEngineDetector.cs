using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ProcessInspector.BinaryAnalysis;

namespace ProcessInspector.EngineDetectors
{
    public class PackedBinaryEngineDetector : BaseEngineDetector
    {
        // Mapping of packer names to more detailed information
        private static readonly Dictionary<string, string> PackerDetails = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["UPX"] = "UPX (Ultimate Packer for eXecutables)",
            ["ASPack"] = "ASPack (Advanced Software Protection)",
            ["Themida"] = "Themida (Advanced Windows Software Protection)",
            ["VMProtect"] = "VMProtect (Virtualization-based Protection)",
            ["Enigma"] = "Enigma Protector",
            ["MPress"] = "MPRESS (MATCODE Compressor)",
            ["PECompact"] = "PECompact (PE File Compressor)",
            ["Obsidium"] = "Obsidium (Software Protection System)",
            ["Petite"] = "Petite (PE Compression Tool)",
            ["FSG"] = "FSG (Fast Small Good)",
            ["ExeCryptor"] = "ExeCryptor (Executable Protection System)",
            ["Molebox"] = "Molebox (Application Wrapper)",
            ["Armadillo"] = "Armadillo (Software Protection System)",
            ["WinLicense"] = "WinLicense (Software Licensing & Protection)",
            ["Safengine"] = "Safengine Shielden",
            ["ACProtect"] = "ACProtect",
            ["EXECryptor"] = "EXECryptor (Executable Encryption)",
            ["PKLITE"] = "PKLITE (Executable Compressor)",
            ["NsPack"] = "NsPack (PE Compression Tool)",
            ["BoxedApp"] = "BoxedApp (Application Virtualization)"
        };

        // Additional patterns to improve detection
        private static readonly Dictionary<string, Regex> AdditionalPackerPatterns = new Dictionary<string, Regex>
        {
            ["UPX"] = new Regex(@"UPX\s*\d\.\d+", RegexOptions.Compiled),
            ["FSG"] = new Regex(@"FSG\s*\d\.\d+", RegexOptions.Compiled),
            ["ASPack"] = new Regex(@"ASPack\s*\d\.\d+", RegexOptions.Compiled),
            ["PECompact"] = new Regex(@"PEC2|\bPECompact\b", RegexOptions.Compiled),
            ["NSIS"] = new Regex(@"Nullsoft.+Install", RegexOptions.Compiled),
            ["Inno Setup"] = new Regex(@"Inno\s*Setup", RegexOptions.Compiled),
            ["WinRAR SFX"] = new Regex(@"WinRAR\s*SFX", RegexOptions.Compiled),
            ["InstallShield"] = new Regex(@"InstallShield", RegexOptions.Compiled),
            ["7-Zip SFX"] = new Regex(@"7-Zip\s*SFX", RegexOptions.Compiled),
            ["WISE Installer"] = new Regex(@"WISE\s*Installation", RegexOptions.Compiled),
        };

        // Detection confidence thresholds
        private const double HIGH_CONFIDENCE = 0.8;
        private const double MEDIUM_CONFIDENCE = 0.5;
        private const double LOW_CONFIDENCE = 0.3;

        // Secondary characteristics to improve detection
        private static readonly Dictionary<string, List<string>> SecondaryCharacteristics = new Dictionary<string, List<string>>
        {
            ["UPX"] = new List<string> { "UPX!", "UPX0", "UPX1", "UPX2" },
            ["ASPack"] = new List<string> { ".aspack", ".adata", "ASPack" },
            ["Themida"] = new List<string> { "themida", "SecureEngine", "WinLicense" },
            ["VMProtect"] = new List<string> { ".vmp0", ".vmp1", ".vmp2", "VMProtect" },
            ["Enigma"] = new List<string> { ".enigma", "Enigma", "Software Enigma" },
            ["MPress"] = new List<string> { ".MPRESS1", ".MPRESS2" },
            ["PECompact"] = new List<string> { "PECompact2", "PEC2", "PEC2MO" },
            ["Obsidium"] = new List<string> { "Obsidium", ".obsidium" },
        };

        public override string GetEngineName()
        {
            return "Packed Binary";
        }

        public override double DetectEngineProbability(string exePath)
        {
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                return 0.0;

            try
            {
                double score = 0.0;

                // Use the PackedExecutableDetector from BinaryAnalysis
                var detector = new PackedExecutableDetector();
                var (isPacked, packerName, confidence) = detector.AnalyzeExecutable(exePath);

                if (isPacked)
                {
                    // Start with the base confidence from the packer detection
                    score = confidence * 10.0; // Scale up to match our score system

                    // Run secondary analysis tasks in parallel
                    var analysisResults = new ConcurrentBag<double>();
                    Parallel.Invoke(
                        // Task 1: Perform secondary binary analysis
                        () => {
                            double secondaryScore = PerformSecondaryAnalysis(exePath, packerName);
                            analysisResults.Add(secondaryScore);
                        },
                        // Task 2: Analyze environment (directory structure, related files)
                        () => {
                            double envScore = AnalyzeEnvironment(exePath, packerName);
                            analysisResults.Add(envScore);
                        },
                        // Task 3: Check for structural indicators if needed
                        () => {
                            if (confidence < 0.5) // Only run this if confidence is lower
                            {
                                bool hasIndicators = HasPackerStructuralIndicators(exePath);
                                if (hasIndicators)
                                {
                                    analysisResults.Add(2.0);
                                }
                            }
                        }
                    );

                    // Add all analysis results to the score
                    score += analysisResults.Sum();
                }

                return Math.Min(score / 10.0, 1.0); // Normalize to 0.0-1.0
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in PackedBinaryEngineDetector: {ex.Message}");
                return 0.0;
            }
        }

        /// <summary>
        /// Performs deeper analysis of the binary to strengthen detection
        /// </summary>
        private double PerformSecondaryAnalysis(string exePath, string detectedPackerName)
        {
            double additionalScore = 0.0;

            try
            {
                // Read a portion of the file for analysis
                byte[] fileBytes = new byte[Math.Min(new FileInfo(exePath).Length, 5 * 1024 * 1024)]; // Read up to 5MB
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Read(fileBytes, 0, fileBytes.Length);
                }

                // Convert to string for pattern matching
                string fileContent = System.Text.Encoding.ASCII.GetString(fileBytes);

                // Parallel pattern matching for better performance
                var patternScores = new ConcurrentBag<double>();
                Parallel.ForEach(AdditionalPackerPatterns, new ParallelOptions { MaxDegreeOfParallelism = OptimalParallelism }, patternEntry =>
                {
                    string packerKey = patternEntry.Key;
                    Regex pattern = patternEntry.Value;
                    
                    if (pattern.IsMatch(fileContent))
                    {
                        double matchScore = 0.0;
                        // Higher score if this matches our initially detected packer
                        if (string.Equals(packerKey, detectedPackerName, StringComparison.OrdinalIgnoreCase))
                        {
                            matchScore = 3.0; // Confirming evidence
                        }
                        else
                        {
                            matchScore = 1.5; // Additional packer evidence
                        }
                        patternScores.Add(matchScore);
                    }
                });
                
                // Add all pattern match scores
                additionalScore += patternScores.Sum();

                // Check for specific string patterns related to the detected packer
                if (!string.IsNullOrEmpty(detectedPackerName) && 
                    SecondaryCharacteristics.TryGetValue(detectedPackerName, out var characteristics))
                {
                    var characteristicMatches = new ConcurrentBag<bool>();
                    Parallel.ForEach(characteristics, characteristic =>
                    {
                        if (fileContent.Contains(characteristic, StringComparison.OrdinalIgnoreCase))
                        {
                            characteristicMatches.Add(true);
                        }
                    });
                    
                    additionalScore += characteristicMatches.Count;

                    // Bonus for multiple matching characteristics
                    if (characteristicMatches.Count >= 3)
                    {
                        additionalScore += 1.0; // Bonus for strong evidence
                    }
                }
            }
            catch
            {
                // Ignore analysis errors
            }

            return Math.Min(additionalScore, 5.0); // Cap additional score
        }

        /// <summary>
        /// Analyzes the environment (directory structure, related files) for packer evidence
        /// </summary>
        private double AnalyzeEnvironment(string exePath, string detectedPackerName)
        {
            double score = 0.0;

            try
            {
                string directory = Path.GetDirectoryName(exePath);
                string fileName = Path.GetFileNameWithoutExtension(exePath);

                // Check for typical packer artifacts in the directory
                string[] packerArtifacts = {
                    $"{fileName}.bak", // Common backup created by packers
                    $"{fileName}.~",   // Temporary file
                    $"{fileName}.packed", // Explicit indicator
                    $"{fileName}.backup" // Backup during packing
                };

                foreach (var artifact in packerArtifacts)
                {
                    if (File.Exists(Path.Combine(directory, artifact)))
                    {
                        score += 1.0;
                    }
                }

                // Look for specific installer/unpacker tools in the same directory
                if (!string.IsNullOrEmpty(detectedPackerName))
                {
                    string[] relatedTools = {
                        $"unpack_{detectedPackerName.ToLowerInvariant()}.exe",
                        $"{detectedPackerName.ToLowerInvariant()}_config.dat",
                        $"{detectedPackerName.ToLowerInvariant()}.sig"
                    };

                    foreach (var tool in relatedTools)
                    {
                        if (File.Exists(Path.Combine(directory, tool)))
                        {
                            score += 2.0; // Strong evidence
                        }
                    }
                }
            }
            catch
            {
                // Ignore environment analysis errors
            }

            return Math.Min(score, 3.0); // Cap environment score
        }

        /// <summary>
        /// Checks for structural indicators of packed binaries
        /// </summary>
        private bool HasPackerStructuralIndicators(string exePath)
        {
            try
            {
                var fileInfo = new FileInfo(exePath);
                
                // Small executable size but with high entropy is suspicious
                bool isSmall = fileInfo.Length < 100 * 1024; // Less than 100KB
                
                // Check the file header (read first 4 bytes)
                using (var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] header = new byte[4];
                    fs.Read(header, 0, 4);
                    
                    // MZ header (valid PE file)
                    if (header[0] == 0x4D && header[1] == 0x5A)
                    {
                        // Jump to PE header offset location (at 0x3C)
                        fs.Seek(0x3C, SeekOrigin.Begin);
                        byte[] peOffsetBytes = new byte[4];
                        fs.Read(peOffsetBytes, 0, 4);
                        
                        int peOffset = BitConverter.ToInt32(peOffsetBytes, 0);
                        
                        // Unusual PE header offset can indicate packing
                        bool unusualPEOffset = peOffset > 1024; // Typical PE offset is much smaller
                        
                        return isSmall || unusualPEOffset;
                    }
                }
            }
            catch
            {
                // Ignore analysis errors
            }
            
            return false;
        }
        
        /// <summary>
        /// Gets detailed information about the detected packer
        /// </summary>
        public string GetPackerDetails(string packerName)
        {
            if (string.IsNullOrEmpty(packerName))
                return "Unknown Packer";
                
            if (PackerDetails.TryGetValue(packerName, out string details))
                return details;
                
            return packerName;
        }
    }
}
