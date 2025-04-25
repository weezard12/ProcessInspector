using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ProcessInspector.EngineDetectors
{
    public class EngineDetectorManager : IEngineDetector
    {
        private readonly List<IEngineDetector> _engineDetectors;
        private const double PROBABILITY_THRESHOLD = 0.25; // Minimum probability to consider a detection valid

        public EngineDetectorManager()
        {
            // Initialize all engine detectors
            _engineDetectors = new List<IEngineDetector>
            {
                // Game Engines
                new UnityEngineDetector(),
                new UnrealEngineDetector(),
                new GodotEngineDetector(),
                new MonoGameDetector(),
                new GameMakerDetector(),
                new CryEngineDetector(),
                new LibGDXDetector(),
                
                // Application Frameworks
                new ElectronDetector(),
                new WPFDetector(),         // Windows Presentation Foundation
                
                // .NET Frameworks and Platforms
                new DotNetConsoleDetector(),     // For detecting .NET Framework Console Applications
                new DotNetCoreConsoleDetector(),  // For detecting .NET Core/5+ Console Applications
                
                // Packer Detection
                new PackedBinaryEngineDetector()  // For detecting packed/protected executables
                
                // Add other engine detectors here as they are implemented
            };
        }

        public double DetectEngineProbability(string exePath)
        {
            // This method will return the highest probability found by any detector
            // Used for implementing the IEngineDetector interface
            if (string.IsNullOrEmpty(exePath))
                return 0.0;

            var results = GetAllEngineProbabilities(exePath);
            return results.Any() ? results.Max(r => r.Value) : 0.0;
        }

        public string GetEngineName()
        {
            // This is called when this detector is the one with the highest probability
            // Should not happen as we'll always return the specific engine detector's name
            return "Unknown Engine";
        }

        public string DetectEngine(string exePath)
        {
            if (string.IsNullOrEmpty(exePath))
                return "Unknown Engine";

            // Get all probabilities from all engine detectors
            var results = GetAllEngineProbabilities(exePath);

            // Find the engine with the highest probability
            var mostLikelyEngine = results
                .OrderByDescending(r => r.Value)
                .FirstOrDefault();

            if (mostLikelyEngine.Key != null && mostLikelyEngine.Value >= PROBABILITY_THRESHOLD)
            {
                return $"{mostLikelyEngine.Key} ({Math.Round(mostLikelyEngine.Value * 100)}% confidence)";
            }

            return "Unknown Engine";
        }

        public Dictionary<string, double> GetAllEngineProbabilities(string exePath)
        {
            // Use ConcurrentDictionary for thread-safe operations
            var resultsDictionary = new ConcurrentDictionary<string, double>();

            // Execute all detectors in parallel
            Parallel.ForEach(_engineDetectors, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, detector =>
            {
                try
                {
                    double probability = detector.DetectEngineProbability(exePath);
                    if (probability > 0)
                    {
                        resultsDictionary.TryAdd(detector.GetEngineName(), probability);
                    }
                }
                catch
                {
                    // Ignore errors in individual detectors
                }
            });

            // Convert to regular Dictionary for API compatibility
            return new Dictionary<string, double>(resultsDictionary);
        }
    }
} 