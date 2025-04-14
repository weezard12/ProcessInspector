using ProcessInspector.Enums;
using ProcessInspector.Types;

namespace ProcessInspector
{
    public interface IUIManager
    {
        MenuOption ShowMainMenu();
        string AskForProcessName();
        void ShowProcessNotFoundMessage();
        void DisplayProcessList(IEnumerable<ProcessInfo> processes);
        bool AskToInspectProcess();
        ProcessDetailOption ShowProcessDetails(ProcessDetails processDetails);
        void DisplayModules(IEnumerable<ModuleInfo> modules);
        void DisplayLanguageResults(LanguageDetectionResult languageResults);
        void DisplayThreads(IEnumerable<ThreadInfo> threads);
        void DisplayNavigationHistory(IEnumerable<string> history);
        void DisplayAboutInfo();
        void ShowExitMessage();
    }
}