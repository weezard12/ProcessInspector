using ProcessInspector.Types;

namespace ProcessInspector
{
    public interface ILanguageDetector
    {
        LanguageDetectionResult DetectProgrammingLanguages(string exePath);
    }
}