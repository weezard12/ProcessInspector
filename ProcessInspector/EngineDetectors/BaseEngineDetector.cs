using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace ProcessInspector.EngineDetectors
{
    public abstract class BaseEngineDetector : IEngineDetector
    {
        // Maximum file size to analyze
        protected const int MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

        // Maximum number of files to analyze in a directory
        protected const int MAX_FILES_TO_ANALYZE = 150;

        // Minimum score threshold for engine detection
        protected const double MIN_ENGINE_SCORE = 5.0;

        public abstract string GetEngineName();

        public abstract double DetectEngineProbability(string exePath);

        protected string CalculateMD5Hash(string filePath)
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

        protected int? GetProcessIdByExecutablePath(string exePath)
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
                // Ignore errors in process enumeration
            }

            return null;
        }

        protected bool IsBinaryFile(string filePath)
        {
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] buffer = new byte[Math.Min(4096, fs.Length)];
                    fs.Read(buffer, 0, buffer.Length);

                    // Check for null bytes in the first 4KB, which typically indicates a binary file
                    return Array.IndexOf(buffer, (byte)0) != -1;
                }
            }
            catch
            {
                return true; // Assume binary if we can't read the file
            }
        }

        protected double ScanFileForEnginePatterns(string filePath, IDictionary<string, Regex> patterns)
        {
            double score = 0;
            
            try
            {
                if (!File.Exists(filePath))
                    return score;

                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > MAX_FILE_SIZE_BYTES)
                    return score;

                if (IsBinaryFile(filePath))
                {
                    // For binary files, just check for string patterns
                    byte[] fileBytes = File.ReadAllBytes(filePath);
                    string fileContent = System.Text.Encoding.ASCII.GetString(fileBytes);

                    foreach (var pattern in patterns.Values)
                    {
                        if (pattern.IsMatch(fileContent))
                        {
                            score += 1.0;
                        }
                    }
                }
                else
                {
                    // For text files, scan line by line
                    using (StreamReader reader = new StreamReader(filePath))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            foreach (var pattern in patterns.Values)
                            {
                                if (pattern.IsMatch(line))
                                {
                                    score += 1.0;
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                // Ignore file access errors
            }

            return score;
        }
    }
} 