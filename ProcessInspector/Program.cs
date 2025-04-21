using ProcessInspector.EngineDetectors;
using System;

namespace ProcessInspector
{
    class Program
    {
        static void Main(string[] args)
        {
            // Set up dependency injection
            IUIManager uiManager = new ConsoleUIManager();
            IHistoryManager historyManager = new NavigationHistoryManager();
            IEngineDetector engineDetector = new EngineDetectorManager();
            ILanguageDetector languageDetector = new LanguageDetector();
            IProcessAnalyzer processAnalyzer = new ProcessAnalyzer(engineDetector, languageDetector);

            // Create and run the application
            var app = new ProcessInspectorApp(uiManager, historyManager, processAnalyzer);
            app.Run();
        }
    }
}
