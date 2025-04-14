using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInspector.Types
{
    public class ModuleInfo
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public double SizeKB { get; set; }
    }
}
