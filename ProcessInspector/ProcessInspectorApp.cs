using ProcessInspector.Enums;
using ProcessInspector.Types;
using System.Text;

namespace ProcessInspector
{
    public class ProcessInspectorApp
    {
        private readonly IUIManager _uiManager;
        private readonly IHistoryManager _historyManager;
        private readonly IProcessAnalyzer _processAnalyzer;

        public ProcessInspectorApp(
            IUIManager uiManager,
            IHistoryManager historyManager,
            IProcessAnalyzer processAnalyzer)
        {
            _uiManager = uiManager;
            _historyManager = historyManager;
            _processAnalyzer = processAnalyzer;
        }

        public void Run()
        {
            Console.Title = "Process Inspector - weezard12";
            Console.OutputEncoding = Encoding.UTF8;
            ShowMainMenu();
        }

        private void ShowMainMenu()
        {
            bool exitRequested = false;

            while (!exitRequested)
            {
                var choice = _uiManager.ShowMainMenu();

                switch (choice)
                {
                    case MenuOption.FindAndInspectProcess:
                        FindAndInspectProcess();
                        break;
                    case MenuOption.ListRunningProcesses:
                        ListRunningProcesses();
                        break;
                    case MenuOption.ViewNavigationHistory:
                        ViewNavigationHistory();
                        break;
                    case MenuOption.About:
                        ShowAbout();
                        break;
                    case MenuOption.Exit:
                        exitRequested = true;
                        _uiManager.ShowExitMessage();
                        break;
                }
            }
        }

        private void FindAndInspectProcess()
        {
            string processName = _uiManager.AskForProcessName();

            var process = _processAnalyzer.FindProcess(processName);
            if (process == null)
            {
                _uiManager.ShowProcessNotFoundMessage();
                return;
            }

            _historyManager.AddToHistory($"Process: {process.ProcessName} (PID: {process.Id})");
            InspectProcess(process);
        }

        private void ListRunningProcesses()
        {
            var processes = _processAnalyzer.GetRunningProcesses();
            _uiManager.DisplayProcessList(processes);

            if (_uiManager.AskToInspectProcess())
            {
                string processName = _uiManager.AskForProcessName();
                var process = _processAnalyzer.FindProcess(processName);

                if (process == null)
                {
                    _uiManager.ShowProcessNotFoundMessage();
                    return;
                }

                _historyManager.AddToHistory($"Process: {process.ProcessName} (PID: {process.Id})");
                InspectProcess(process);
            }
        }

        private void InspectProcess(ProcessInfo process)
        {
            bool continueInspection = true;

            while (continueInspection)
            {
                var processDetails = _processAnalyzer.GetProcessDetails(process);
                var option = _uiManager.ShowProcessDetails(processDetails);

                switch (option)
                {
                    case ProcessDetailOption.ViewModules:
                        var modules = _processAnalyzer.GetProcessModules(process);
                        _uiManager.DisplayModules(modules);
                        break;
                    case ProcessDetailOption.DetectProgrammingLanguages:
                        var languageResults = _processAnalyzer.DetectProgrammingLanguages(process.MainModulePath);
                        _uiManager.DisplayLanguageResults(languageResults);
                        break;
                    case ProcessDetailOption.ViewThreads:
                        var threads = _processAnalyzer.GetProcessThreads(process);
                        _uiManager.DisplayThreads(threads);
                        break;
                    case ProcessDetailOption.BackToMainMenu:
                        continueInspection = false;
                        break;
                }
            }
        }

        private void ViewNavigationHistory()
        {
            var history = _historyManager.GetHistory();
            _uiManager.DisplayNavigationHistory(history);
        }

        private void ShowAbout()
        {
            _uiManager.DisplayAboutInfo();
        }
    }
}