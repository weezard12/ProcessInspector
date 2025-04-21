namespace ProcessInspector
{
    public interface IEngineDetector
    {
        double DetectEngineProbability(string exePath);
        string GetEngineName();
    }
}