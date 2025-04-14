namespace ProcessInspector
{
    public interface IEngineDetector
    {
        string DetectEngine(string exePath);
    }
}