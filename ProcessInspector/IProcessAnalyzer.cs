using ProcessInspector.Types;

namespace ProcessInspector
{
    public interface IProcessAnalyzer
    {
        ProcessInfo FindProcess(string processName);
        IEnumerable<ProcessInfo> GetRunningProcesses();
        ProcessDetails GetProcessDetails(ProcessInfo process);
        IEnumerable<ModuleInfo> GetProcessModules(ProcessInfo process);
        LanguageDetectionResult DetectProgrammingLanguages(string exePath);
        IEnumerable<ThreadInfo> GetProcessThreads(ProcessInfo process);
    }
}