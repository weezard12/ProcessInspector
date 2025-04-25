using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ProcessInspector.BinaryAnalysis
{
    public class PackedExecutableDetector
    {
        // PE Header signatures and constants
        private const uint MZ_SIGNATURE = 0x5A4D;        // "MZ"
        private const uint PE_SIGNATURE = 0x00004550;    // "PE\0\0"
        private const int MAX_SECTIONS = 96;             // Maximum number of sections to consider
        private const double ENTROPY_THRESHOLD = 7.0;    // High entropy threshold indicating encryption/packing
        private const double PACKED_SECTION_THRESHOLD = 0.6; // % of sections that need to be identified as packed

        // Known packer section names
        private static readonly HashSet<string> KnownPackerSectionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // UPX
            "UPX0", "UPX1", "UPX2", "UPX3",
            // ASPack
            ".aspack", ".adata", "ASPack",
            // Themida
            ".themida", "themida",
            // VMProtect
            ".vmp0", ".vmp1", ".vmp2", "vmp0",
            // Enigma
            ".enigma", ".enigma1", ".enigma2",
            // Other common packers
            "pebundle", ".pklstb", ".perplex", ".petite", ".nsp0", ".nsp1", ".nsp2",
            ".MPRESS1", ".MPRESS2", ".winapi",
            ".ccg", ".mackt", ".shrink", "ProCrypt", "PELock", ".MEW",
            ".PEPACK", ".Upack", ".ByDwing"
        };

        // Common packer signatures in binary content
        private static readonly Dictionary<string, byte[]> PackerSignatures = new Dictionary<string, byte[]>
        {
            ["UPX"] = Encoding.ASCII.GetBytes("UPX!"),
            ["Themida"] = Encoding.ASCII.GetBytes("Themida"),
            ["ASPack"] = Encoding.ASCII.GetBytes("ASPack"),
            ["VMProtect"] = Encoding.ASCII.GetBytes("VMProtect"),
            ["Enigma"] = Encoding.ASCII.GetBytes("Enigma"),
            ["MPress"] = Encoding.ASCII.GetBytes("MPRESS"),
            ["PECompact"] = Encoding.ASCII.GetBytes("PEC2"),
            ["FSG"] = Encoding.ASCII.GetBytes("FSG!"),
            ["ExeCryptor"] = Encoding.ASCII.GetBytes("ExeCryptor")
        };

        // Identify specific packers by regex patterns in strings
        private static readonly Dictionary<string, Regex> PackerRegexPatterns = new Dictionary<string, Regex>
        {
            ["UPX"] = new Regex(@"UPX\s*\d+\.\d+", RegexOptions.Compiled),
            ["Themida"] = new Regex(@"Themida\s*\d+\.\d+", RegexOptions.Compiled),
            ["ASPack"] = new Regex(@"ASPack\s*\d+\.\d+", RegexOptions.Compiled),
            ["VMProtect"] = new Regex(@"VMProtect\s*\d+\.\d+", RegexOptions.Compiled),
            ["PECompact"] = new Regex(@"PECompact\s*\d+\.\d+", RegexOptions.Compiled),
            ["Obsidium"] = new Regex(@"Obsidium\s*\d+\.\d+", RegexOptions.Compiled),
            ["Enigma"] = new Regex(@"Enigma\s*Protector", RegexOptions.Compiled)
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res;
            public ushort e_oemid;
            public ushort e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint PhysicalAddress;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;

            public string SectionName => Encoding.ASCII.GetString(Name).TrimEnd('\0');
        }

        // This struct represents the PE signature and machine-specific fields
        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_NT_HEADERS
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
        }

        /// <summary>
        /// Analyzes a PE file to determine if it's packed and identify the packer if possible
        /// </summary>
        /// <param name="filePath">Path to the executable file</param>
        /// <returns>Tuple containing: isPacked, packerName, confidence (0.0-1.0)</returns>
        public (bool IsPacked, string PackerName, double Confidence) AnalyzeExecutable(string filePath)
        {
            if (!File.Exists(filePath))
                return (false, string.Empty, 0.0);

            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    // Check if the file is a valid PE file
                    if (!IsValidPeFile(fs))
                        return (false, string.Empty, 0.0);

                    // Analyze PE header sections
                    var peHeaderResult = AnalyzePeHeader(fs);
                    
                    // Analyze entropy of the file sections
                    var entropyResult = AnalyzeSectionEntropy(fs);
                    
                    // Look for packer signatures in the file
                    var signatureResult = AnalyzeForPackerSignatures(fs);

                    // Extract strings from the file and look for packer patterns
                    var stringAnalysisResult = AnalyzeStrings(fs);

                    // Combine the results to get a final assessment
                    return CombineAnalysisResults(
                        peHeaderResult, 
                        entropyResult, 
                        signatureResult,
                        stringAnalysisResult);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error analyzing {filePath}: {ex.Message}");
                return (false, string.Empty, 0.0);
            }
        }

        private bool IsValidPeFile(FileStream fs)
        {
            try
            {
                fs.Seek(0, SeekOrigin.Begin);
                
                // Read and check DOS header
                byte[] dosBuffer = new byte[Marshal.SizeOf<IMAGE_DOS_HEADER>()];
                if (fs.Read(dosBuffer, 0, dosBuffer.Length) != dosBuffer.Length)
                    return false;

                IMAGE_DOS_HEADER dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dosBuffer);
                if (dosHeader.e_magic != MZ_SIGNATURE)
                    return false;

                // Check for PE signature
                fs.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                uint peSignature = 0;
                byte[] peBuffer = new byte[4];
                if (fs.Read(peBuffer, 0, 4) != 4)
                    return false;

                peSignature = BitConverter.ToUInt32(peBuffer, 0);
                return peSignature == PE_SIGNATURE;
            }
            catch
            {
                return false;
            }
        }

        private (bool IsPacked, string PackerName, double Confidence) AnalyzePeHeader(FileStream fs)
        {
            try
            {
                fs.Seek(0, SeekOrigin.Begin);
                
                // Read DOS header
                byte[] dosBuffer = new byte[Marshal.SizeOf<IMAGE_DOS_HEADER>()];
                fs.Read(dosBuffer, 0, dosBuffer.Length);
                IMAGE_DOS_HEADER dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dosBuffer);
                
                // Jump to PE header
                fs.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                
                // Read NT headers
                byte[] ntBuffer = new byte[Marshal.SizeOf<IMAGE_NT_HEADERS>()];
                fs.Read(ntBuffer, 0, ntBuffer.Length);
                IMAGE_NT_HEADERS ntHeaders = ByteArrayToStructure<IMAGE_NT_HEADERS>(ntBuffer);
                
                // Read section headers
                ushort numberOfSections = ntHeaders.FileHeader.NumberOfSections;
                if (numberOfSections > MAX_SECTIONS || numberOfSections == 0)
                    return (false, string.Empty, 0.0);
                
                int secHeaderSize = Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                byte[] secBuffer = new byte[secHeaderSize * numberOfSections];
                fs.Read(secBuffer, 0, secBuffer.Length);
                
                // Count of suspicious section names
                int suspiciousSections = 0;
                List<string> detectedPackers = new List<string>();
                
                // Analyze each section
                for (int i = 0; i < numberOfSections; i++)
                {
                    byte[] secData = new byte[secHeaderSize];
                    Array.Copy(secBuffer, i * secHeaderSize, secData, 0, secHeaderSize);
                    IMAGE_SECTION_HEADER sectionHeader = ByteArrayToStructure<IMAGE_SECTION_HEADER>(secData);
                    
                    string sectionName = sectionHeader.SectionName;
                    
                    // Check for known packer section names
                    if (KnownPackerSectionNames.Contains(sectionName))
                    {
                        suspiciousSections++;
                        
                        // Try to identify the specific packer from the section name
                        if (sectionName.StartsWith("UPX", StringComparison.OrdinalIgnoreCase))
                            detectedPackers.Add("UPX");
                        else if (sectionName.StartsWith(".aspack", StringComparison.OrdinalIgnoreCase) || 
                                 sectionName.Equals("ASPack", StringComparison.OrdinalIgnoreCase))
                            detectedPackers.Add("ASPack");
                        else if (sectionName.Contains("themida"))
                            detectedPackers.Add("Themida");
                        else if (sectionName.StartsWith(".vmp", StringComparison.OrdinalIgnoreCase) ||
                                 sectionName.StartsWith("vmp", StringComparison.OrdinalIgnoreCase))
                            detectedPackers.Add("VMProtect");
                        else if (sectionName.Contains("enigma"))
                            detectedPackers.Add("Enigma");
                        else if (sectionName.StartsWith(".MPRESS", StringComparison.OrdinalIgnoreCase))
                            detectedPackers.Add("MPress");
                        else if (sectionName.Equals(".petite", StringComparison.OrdinalIgnoreCase))
                            detectedPackers.Add("Petite");
                    }
                    
                    // Check for suspicious section characteristics
                    uint characteristics = sectionHeader.Characteristics;
                    const uint IMAGE_SCN_MEM_WRITE = 0x80000000;
                    const uint IMAGE_SCN_MEM_READ = 0x40000000;
                    const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
                    
                    // Sections that are writable + executable are suspicious
                    if ((characteristics & IMAGE_SCN_MEM_WRITE) != 0 &&
                        (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                    {
                        suspiciousSections++;
                    }
                }
                
                // Calculate confidence based on section analysis
                double sectionRatio = (double)suspiciousSections / numberOfSections;
                bool isPacked = sectionRatio >= PACKED_SECTION_THRESHOLD;
                double confidence = Math.Min(1.0, sectionRatio);
                
                string packerName = string.Empty;
                if (detectedPackers.Count > 0)
                {
                    // Count occurrences of each packer name
                    var packerCounts = detectedPackers
                        .GroupBy(p => p)
                        .OrderByDescending(g => g.Count())
                        .ThenBy(g => g.Key)
                        .First();
                    
                    packerName = packerCounts.Key;
                    confidence = Math.Max(confidence, 0.7); // Boost confidence if we found specific packer
                }
                
                return (isPacked, packerName, confidence);
            }
            catch
            {
                return (false, string.Empty, 0.0);
            }
        }

        private (bool IsPacked, string PackerName, double Confidence) AnalyzeSectionEntropy(FileStream fs)
        {
            try
            {
                fs.Seek(0, SeekOrigin.Begin);
                
                // Read DOS header
                byte[] dosBuffer = new byte[Marshal.SizeOf<IMAGE_DOS_HEADER>()];
                fs.Read(dosBuffer, 0, dosBuffer.Length);
                IMAGE_DOS_HEADER dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dosBuffer);
                
                // Jump to PE header
                fs.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                
                // Read NT headers
                byte[] ntBuffer = new byte[Marshal.SizeOf<IMAGE_NT_HEADERS>()];
                fs.Read(ntBuffer, 0, ntBuffer.Length);
                IMAGE_NT_HEADERS ntHeaders = ByteArrayToStructure<IMAGE_NT_HEADERS>(ntBuffer);
                
                // Read section headers
                ushort numberOfSections = ntHeaders.FileHeader.NumberOfSections;
                if (numberOfSections > MAX_SECTIONS || numberOfSections == 0)
                    return (false, string.Empty, 0.0);
                
                int secHeaderSize = Marshal.SizeOf<IMAGE_SECTION_HEADER>();
                byte[] secBuffer = new byte[secHeaderSize * numberOfSections];
                fs.Read(secBuffer, 0, secBuffer.Length);
                
                int highEntropyCount = 0;
                
                // Analyze entropy for each section
                for (int i = 0; i < numberOfSections; i++)
                {
                    byte[] secData = new byte[secHeaderSize];
                    Array.Copy(secBuffer, i * secHeaderSize, secData, 0, secHeaderSize);
                    IMAGE_SECTION_HEADER sectionHeader = ByteArrayToStructure<IMAGE_SECTION_HEADER>(secData);
                    
                    // Skip empty sections
                    if (sectionHeader.SizeOfRawData == 0 || sectionHeader.PointerToRawData == 0)
                        continue;
                    
                    // Read section content
                    fs.Seek(sectionHeader.PointerToRawData, SeekOrigin.Begin);
                    byte[] sectionContent = new byte[Math.Min(sectionHeader.SizeOfRawData, 1024 * 1024)]; // Limit to 1MB
                    int bytesRead = fs.Read(sectionContent, 0, sectionContent.Length);
                    
                    if (bytesRead > 0)
                    {
                        // Calculate Shannon entropy
                        double entropy = CalculateShannonEntropy(sectionContent, bytesRead);
                        
                        // High entropy is a strong indicator of encryption/packing
                        if (entropy > ENTROPY_THRESHOLD)
                        {
                            highEntropyCount++;
                        }
                    }
                }
                
                double entropyRatio = (double)highEntropyCount / numberOfSections;
                bool isPacked = entropyRatio >= PACKED_SECTION_THRESHOLD;
                double confidence = Math.Min(1.0, entropyRatio);
                
                return (isPacked, "Unknown Packer (High Entropy)", confidence);
            }
            catch
            {
                return (false, string.Empty, 0.0);
            }
        }

        private (bool IsPacked, string PackerName, double Confidence) AnalyzeForPackerSignatures(FileStream fs)
        {
            try
            {
                fs.Seek(0, SeekOrigin.Begin);
                
                // Read the file content (limit to first 10MB for large files)
                byte[] fileContent = new byte[Math.Min(fs.Length, 10 * 1024 * 1024)];
                fs.Read(fileContent, 0, fileContent.Length);
                
                foreach (var signature in PackerSignatures)
                {
                    byte[] pattern = signature.Value;
                    
                    // Search for the pattern in the file content
                    for (int i = 0; i <= fileContent.Length - pattern.Length; i++)
                    {
                        bool found = true;
                        for (int j = 0; j < pattern.Length; j++)
                        {
                            if (fileContent[i + j] != pattern[j])
                            {
                                found = false;
                                break;
                            }
                        }
                        
                        if (found)
                        {
                            return (true, signature.Key, 0.9); // High confidence
                        }
                    }
                }
                
                return (false, string.Empty, 0.0);
            }
            catch
            {
                return (false, string.Empty, 0.0);
            }
        }

        private (bool IsPacked, string PackerName, double Confidence) AnalyzeStrings(FileStream fs)
        {
            try
            {
                fs.Seek(0, SeekOrigin.Begin);
                
                // Read file content (limited to 10MB for large files)
                byte[] fileContent = new byte[Math.Min(fs.Length, 10 * 1024 * 1024)];
                int bytesRead = fs.Read(fileContent, 0, fileContent.Length);
                
                // Extract ASCII strings (crude but effective)
                List<string> strings = new List<string>();
                StringBuilder currentString = new StringBuilder();
                
                for (int i = 0; i < bytesRead; i++)
                {
                    byte b = fileContent[i];
                    if (b >= 32 && b <= 126) // Printable ASCII
                    {
                        currentString.Append((char)b);
                    }
                    else if (currentString.Length >= 4) // Only collect strings of a certain length
                    {
                        strings.Add(currentString.ToString());
                        currentString.Clear();
                    }
                    else
                    {
                        currentString.Clear();
                    }
                }
                
                // Add the last string if it meets the length requirement
                if (currentString.Length >= 4)
                {
                    strings.Add(currentString.ToString());
                }
                
                // Look for packer signatures in the strings
                foreach (var pattern in PackerRegexPatterns)
                {
                    foreach (string str in strings)
                    {
                        if (pattern.Value.IsMatch(str))
                        {
                            return (true, pattern.Key, 0.95); // Very high confidence
                        }
                    }
                }
                
                return (false, string.Empty, 0.0);
            }
            catch
            {
                return (false, string.Empty, 0.0);
            }
        }

        private (bool IsPacked, string PackerName, double Confidence) CombineAnalysisResults(
            (bool IsPacked, string PackerName, double Confidence) peHeaderResult,
            (bool IsPacked, string PackerName, double Confidence) entropyResult,
            (bool IsPacked, string PackerName, double Confidence) signatureResult,
            (bool IsPacked, string PackerName, double Confidence) stringAnalysisResult)
        {
            // Prioritize results in this order:
            // 1. String analysis (most reliable)
            // 2. Signature detection
            // 3. PE header analysis
            // 4. Entropy analysis (least reliable alone)
            
            if (stringAnalysisResult.IsPacked)
                return stringAnalysisResult;
            
            if (signatureResult.IsPacked)
                return signatureResult;
            
            if (peHeaderResult.IsPacked)
                return peHeaderResult;
            
            if (entropyResult.IsPacked)
                return entropyResult;
            
            // If none of the individual methods detected packing, calculate a combined confidence
            double combinedConfidence = Math.Max(
                Math.Max(peHeaderResult.Confidence, entropyResult.Confidence),
                Math.Max(signatureResult.Confidence, stringAnalysisResult.Confidence));
            
            // If combined confidence exceeds a threshold, consider it packed
            if (combinedConfidence >= 0.5)
            {
                // Determine the most likely packer name
                string packerName = string.Empty;
                double highestConfidence = 0;
                
                var results = new[] 
                { 
                    peHeaderResult, 
                    entropyResult, 
                    signatureResult, 
                    stringAnalysisResult 
                };
                
                foreach (var result in results)
                {
                    if (!string.IsNullOrEmpty(result.PackerName) && result.Confidence > highestConfidence)
                    {
                        packerName = result.PackerName;
                        highestConfidence = result.Confidence;
                    }
                }
                
                return (true, !string.IsNullOrEmpty(packerName) ? packerName : "Unknown Packer", combinedConfidence);
            }
            
            return (false, string.Empty, 0.0);
        }

        private double CalculateShannonEntropy(byte[] data, int length)
        {
            if (length == 0)
                return 0;
            
            var frequencies = new int[256];
            for (int i = 0; i < length; i++)
            {
                frequencies[data[i]]++;
            }
            
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] == 0)
                    continue;
                
                double probability = (double)frequencies[i] / length;
                entropy -= probability * Math.Log(probability, 2);
            }
            
            return entropy;
        }

        private T ByteArrayToStructure<T>(byte[] bytes) where T : struct
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }
        }
    }
}
