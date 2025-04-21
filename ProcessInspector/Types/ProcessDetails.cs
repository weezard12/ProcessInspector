using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInspector.Types
{
    public class ProcessDetails
    {
        public int PID { get; set; }
        public string Path { get; set; }
        public string Publisher { get; set; }
        public string ProductName { get; set; }
        public string Version { get; set; }
        public string CpuUsage { get; set; }
        public string MemoryUsage { get; set; }
        public string StartTime { get; set; }
        public int ThreadCount { get; set; }
        public string DetectedEngine { get; set; }
        public Dictionary<string, double> EngineProbabilities { get; set; } = new Dictionary<string, double>();
    }
}
