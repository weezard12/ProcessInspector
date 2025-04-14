using System;
using System.Collections.Generic;
using System.Linq;
using ProcessInspector.Enums;
using ProcessInspector.Types;
using Spectre.Console;

namespace ProcessInspector
{
    public class ConsoleUIManager : IUIManager
    {
        public MenuOption ShowMainMenu()
        {
            Console.Clear();
            AnsiConsole.Write(
                new FigletText("Process Inspector")
                    .LeftJustified()
                    .Color(Color.Blue));

            var option = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("📋 [blue]Main Menu[/]")
                    .PageSize(10)
                    .MoreChoicesText("[grey](Move up and down to reveal more options)[/]")
                    .AddChoices(new[] {
                        "1. Find and Inspect Process",
                        "2. Inspect Running Processes List",
                        "3. View Navigation History",
                        "4. About",
                        "5. Exit"
                    }));

            return option switch
            {
                "1. Find and Inspect Process" => MenuOption.FindAndInspectProcess,
                "2. Inspect Running Processes List" => MenuOption.ListRunningProcesses,
                "3. View Navigation History" => MenuOption.ViewNavigationHistory,
                "4. About" => MenuOption.About,
                "5. Exit" => MenuOption.Exit,
                _ => MenuOption.Exit
            };
        }

        public string AskForProcessName()
        {
            Console.Clear();
            return AnsiConsole.Ask<string>("Enter the [green]name of the process[/] to inspect:");
        }

        public void ShowProcessNotFoundMessage()
        {
            AnsiConsole.MarkupLine("[red]❌ Process not found.[/]");
            PressAnyKeyToContinue();
        }

        public void DisplayProcessList(IEnumerable<ProcessInfo> processes)
        {
            Console.Clear();
            AnsiConsole.Status()
                .Start("Loading processes...", ctx =>
                {
                    var table = new Table()
                        .Title("[yellow]Running Processes[/]")
                        .Border(TableBorder.Rounded)
                        .AddColumn(new TableColumn("Process Name").Centered())
                        .AddColumn(new TableColumn("PID").Centered())
                        .AddColumn(new TableColumn("Memory (MB)").Centered());

                    foreach (var process in processes)
                    {
                        table.AddRow(
                            process.ProcessName,
                            process.Id.ToString(),
                            Math.Round(process.UnderlyingProcess.WorkingSet64 / 1024.0 / 1024.0, 2).ToString()
                        );
                    }

                    AnsiConsole.Write(table);
                });
        }

        public bool AskToInspectProcess()
        {
            AnsiConsole.MarkupLine("\n[blue]Would you like to inspect one of these processes?[/]");
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .AddChoices(new[] { "Yes", "No" }));

            return choice == "Yes";
        }

        public ProcessDetailOption ShowProcessDetails(ProcessDetails details)
        {
            Console.Clear();
            AnsiConsole.Write(new Rule($"[blue]Process Details: {details.Path}[/]").RuleStyle("blue").LeftJustified());

            var table = new Table().Border(TableBorder.Rounded);
            table.AddColumn("Property").AddColumn("Value");

            table.AddRow("[yellow]PID[/]", details.PID.ToString());
            table.AddRow("[yellow]Path[/]", details.Path ?? "Unknown");
            table.AddRow("[yellow]Publisher[/]", details.Publisher ?? "Unknown");
            table.AddRow("[yellow]Product Name[/]", details.ProductName ?? "Unknown");
            table.AddRow("[yellow]Version[/]", details.Version ?? "Unknown");
            table.AddRow("[yellow]CPU Usage[/]", details.CpuUsage);
            table.AddRow("[yellow]Memory Usage[/]", details.MemoryUsage);
            table.AddRow("[yellow]Start Time[/]", details.StartTime);
            table.AddRow("[yellow]Threads[/]", details.ThreadCount.ToString());
            table.AddRow("[yellow]Detected Engine[/]", details.DetectedEngine);

            AnsiConsole.Write(table);

            var options = new List<string>
            {
                "1. View Modules",
                "2. Detect Programming Languages",
                "3. View Process Threads",
                "4. Back to Main Menu"
            };

            var option = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("\n[blue]Choose an option:[/]")
                    .PageSize(10)
                    .AddChoices(options));

            return option switch
            {
                "1. View Modules" => ProcessDetailOption.ViewModules,
                "2. Detect Programming Languages" => ProcessDetailOption.DetectProgrammingLanguages,
                "3. View Process Threads" => ProcessDetailOption.ViewThreads,
                "4. Back to Main Menu" => ProcessDetailOption.BackToMainMenu,
                _ => ProcessDetailOption.BackToMainMenu
            };
        }

        public void DisplayModules(IEnumerable<ModuleInfo> modules)
        {
            Console.Clear();
            AnsiConsole.Status()
                .Start("Loading modules...", ctx =>
                {
                    var table = new Table()
                        .Title("[yellow]Loaded Modules[/]")
                        .Border(TableBorder.Rounded)
                        .AddColumn(new TableColumn("Module Name").Centered())
                        .AddColumn(new TableColumn("Path").Centered())
                        .AddColumn(new TableColumn("Size (KB)").Centered());

                    foreach (var module in modules)
                    {
                        table.AddRow(
                            module.Name,
                            module.Path,
                            module.SizeKB.ToString()
                        );
                    }

                    AnsiConsole.Write(table);
                });

            PressAnyKeyToContinue();
        }

        public void DisplayLanguageResults(LanguageDetectionResult results)
        {
            Console.Clear();
            AnsiConsole.Write(new Rule("[yellow]Detected Programming Languages[/]").RuleStyle("yellow"));

            var chart = new BarChart()
                .Width(60)
                .Label("[green bold]Language Distribution[/]")
                .CenterLabel();

            foreach (var score in results.Scores.OrderByDescending(s => s.Percentage))
            {
                chart.AddItem(score.Language, score.Percentage, GetColorForLanguage(score.Language));
            }

            AnsiConsole.Write(chart);

            var table = new Table()
                .Border(TableBorder.Rounded)
                .AddColumn("Language")
                .AddColumn("Percentage");

            foreach (var score in results.Scores.OrderByDescending(s => s.Percentage))
            {
                table.AddRow(score.Language, $"{score.Percentage}%");
            }

            AnsiConsole.Write(table);

            if (results.Scores.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No programming languages could be detected with confidence.[/]");
            }

            PressAnyKeyToContinue();
        }

        public void DisplayThreads(IEnumerable<ThreadInfo> threads)
        {
            Console.Clear();
            var table = new Table()
                .Title("[yellow]Process Threads[/]")
                .Border(TableBorder.Rounded)
                .AddColumn(new TableColumn("Thread ID").Centered())
                .AddColumn(new TableColumn("Start Time").Centered())
                .AddColumn(new TableColumn("Priority").Centered())
                .AddColumn(new TableColumn("State").Centered());

            foreach (var thread in threads)
            {
                table.AddRow(
                    thread.Id.ToString(),
                    thread.StartTime,
                    thread.Priority,
                    thread.State
                );
            }

            AnsiConsole.Write(table);
            PressAnyKeyToContinue();
        }

        public void DisplayNavigationHistory(IEnumerable<string> history)
        {
            Console.Clear();
            AnsiConsole.Write(new Rule("[blue]Navigation History[/]").RuleStyle("blue"));

            var historyList = history.ToList();
            if (historyList.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No navigation history yet.[/]");
            }
            else
            {
                for (int i = 0; i < historyList.Count; i++)
                {
                    AnsiConsole.MarkupLine($"[grey]{i + 1}.[/] {historyList[i]}");
                }
            }

            PressAnyKeyToContinue();
        }

        public void DisplayAboutInfo()
        {
            Console.Clear();
            AnsiConsole.Write(new Rule("[blue]About Process Inspector[/]").RuleStyle("blue"));

            AnsiConsole.MarkupLine(@"
[green]Process Inspector[/]

[yellow]Features:[/]
- Interactive console UI with navigation
- Process inspection and analysis
- Programming language detection with percentages
- Game and application engine detection
- Process modules and threads viewing
- CPU and memory usage monitoring

");

            PressAnyKeyToContinue();
        }

        public void ShowExitMessage()
        {
            Console.Clear();
            AnsiConsole.MarkupLine("[green]Thank you for using Process Inspector![/]");
        }

        private void PressAnyKeyToContinue()
        {
            AnsiConsole.MarkupLine("\n[blue]Press any key to continue...[/]");
            Console.ReadKey(true);
        }

        private Color GetColorForLanguage(string language)
        {
            return language switch
            {
                "C#" => Color.Green,
                "C++" => Color.Blue,
                "Visual Basic" => Color.Purple,
                "F#" => Color.Aqua,
                "Java" => Color.Red,
                "Python" => Color.Yellow,
                "JavaScript" => Color.Gold1,
                "TypeScript" => Color.SteelBlue,
                _ => Color.Grey,
            };
        }
    }
}