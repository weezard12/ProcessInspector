using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInspector.Types
{
    public class ProcessInfo
    {
        public int Id { get; set; }
        public string ProcessName { get; set; }
        public string MainModulePath { get; set; }
        public Process UnderlyingProcess { get; set; } // For direct access when needed

        public ProcessInfo(Process process)
        {
            Id = process.Id;
            ProcessName = process.ProcessName;

            try
            {
                MainModulePath = process.MainModule?.FileName;
            }
            catch
            {
                MainModulePath = null;
            }

            UnderlyingProcess = process;
        }
    }
}
