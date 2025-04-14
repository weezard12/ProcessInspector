using System;
using System.Collections.Generic;
using System.Linq;

namespace ProcessInspector
{
    public class NavigationHistoryManager : IHistoryManager
    {
        private readonly List<string> _history = new List<string>();

        public void AddToHistory(string entry)
        {
            _history.Add(entry);
        }

        public IEnumerable<string> GetHistory()
        {
            return _history.AsReadOnly();
        }
    }
}