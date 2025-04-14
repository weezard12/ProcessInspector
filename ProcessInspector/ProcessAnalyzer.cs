using ProcessInspector.Types;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace ProcessInspector
{
    public class ProcessAnalyzer : IProcessAnalyzer
    {
        private readonly IEngineDetector _engineDetector;
        private readonly ILanguageDetector _languageDetector;

        public ProcessAnalyzer(IEngineDetector engineDetector, ILanguageDetector languageDetector)
        {
            _engineDetector = engineDetector;
            _languageDetector = languageDetector;
        }

        public ProcessInfo FindProcess(string processName)
        {
            var processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                return null;
            }

            if (processes.Length > 1)
            {
                // Choose a process - in a real implementation, this would involve UI
                // For simplicity, just pick the first one here
                return new ProcessInfo(processes[0]);
            }

            return new ProcessInfo(processes[0]);
        }

        public IEnumerable<ProcessInfo> GetRunningProcesses()
        {
            return Process.GetProcesses()
                .OrderBy(p => p.ProcessName)
                .Select(p => new ProcessInfo(p))
                .ToList();
        }

        public ProcessDetails GetProcessDetails(ProcessInfo process)
        {
            var details = new ProcessDetails
            {
                PID = process.Id,
                Path = process.MainModulePath,
                CpuUsage = GetCpuUsage(process.UnderlyingProcess),
                MemoryUsage = $"{Math.Round(process.UnderlyingProcess.WorkingSet64 / 1024.0 / 1024.0, 2)} MB",
                StartTime = process.UnderlyingProcess.StartTime.ToString(),
                ThreadCount = process.UnderlyingProcess.Threads.Count,
                DetectedEngine = _engineDetector.DetectEngine(process.MainModulePath)
            };

            // Get additional details from version info
            if (process.MainModulePath != null && File.Exists(process.MainModulePath))
            {
                var versionInfo = FileVersionInfo.GetVersionInfo(process.MainModulePath);
                details.Publisher = versionInfo.CompanyName;
                details.ProductName = versionInfo.ProductName;
                details.Version = versionInfo.FileVersion;
            }

            return details;
        }

        public IEnumerable<ModuleInfo> GetProcessModules(ProcessInfo process)
        {
            var modules = new List<ModuleInfo>();

            foreach (ProcessModule module in process.UnderlyingProcess.Modules)
            {
                try
                {
                    modules.Add(new ModuleInfo
                    {
                        Name = module.ModuleName,
                        Path = module.FileName,
                        SizeKB = Math.Round(module.ModuleMemorySize / 1024.0, 2)
                    });
                }
                catch
                {
                    // Skip modules we can't access
                }
            }

            return modules;
        }

        public LanguageDetectionResult DetectProgrammingLanguages(string exePath)
        {
            return _languageDetector.DetectProgrammingLanguages(exePath);
        }

        public IEnumerable<ThreadInfo> GetProcessThreads(ProcessInfo process)
        {
            var threads = new List<ThreadInfo>();

            foreach (ProcessThread thread in process.UnderlyingProcess.Threads)
            {
                try
                {
                    threads.Add(new ThreadInfo
                    {
                        Id = thread.Id,
                        StartTime = thread.StartTime.ToString(),
                        Priority = thread.PriorityLevel.ToString(),
                        State = thread.ThreadState.ToString()
                    });
                }
                catch
                {
                    // Skip threads we can't access
                }
            }

            return threads;
        }

        private string GetCpuUsage(Process process)
        {
            try
            {
                var startTime = DateTime.UtcNow;
                var startCpuUsage = process.TotalProcessorTime;

                Thread.Sleep(500);

                var endTime = DateTime.UtcNow;
                var endCpuUsage = process.TotalProcessorTime;

                var cpuUsedMs = (endCpuUsage - startCpuUsage).TotalMilliseconds;
                var totalMsPassed = (endTime - startTime).TotalMilliseconds;
                var cpuUsageTotal = cpuUsedMs / (Environment.ProcessorCount * totalMsPassed);

                return $"{Math.Round(cpuUsageTotal * 100, 1)}%";
            }
            catch
            {
                return "N/A";
            }
        }
    }
}