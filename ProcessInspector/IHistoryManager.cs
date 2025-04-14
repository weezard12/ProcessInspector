namespace ProcessInspector
{
    public interface IHistoryManager
    {
        void AddToHistory(string entry);
        IEnumerable<string> GetHistory();
    }
}