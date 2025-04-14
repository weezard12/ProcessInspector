using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProcessInspector.Types
{
    public class LanguageDetectionResult
    {
        public List<LanguageScore> Scores { get; set; } = new List<LanguageScore>();
    }
}
