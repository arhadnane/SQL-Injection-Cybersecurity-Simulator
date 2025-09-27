using Microsoft.Extensions.Configuration;
using SQLInjectionSimulator.Modules;
using System.Diagnostics;

namespace SQLInjectionSimulator
{
    /// <summary>
    /// SQL Injection Cybersecurity Simulator - Educational Console Application
    /// 
    /// This application demonstrates SQL injection vulnerabilities and defense mechanisms
    /// for educational purposes. It simulates various attack scenarios and shows how to
    /// properly defend against them using secure coding practices.
    /// 
    /// ⚠️ FOR EDUCATIONAL USE ONLY - DO NOT USE AGAINST REAL SYSTEMS
    /// </summary>
    class Program
    {
        private static IConfiguration? _configuration;
        private static string? _connectionString;
        private static UserManager? _userManager;
        private static LoginSimulator? _loginSimulator;
        private static InjectionTester? _injectionTester;
        private static DefenseEngine? _defenseEngine;
        private static Reporter? _reporter;

        static async Task Main(string[] args)
        {
            try
            {
                // Initialize application
                await InitializeApplicationAsync();

                // Show banner
                ShowApplicationBanner();

                // Main application loop
                bool running = true;
                while (running)
                {
                    ShowMainMenu();
                    var choice = Console.ReadLine()?.Trim();

                    switch (choice?.ToUpper())
                    {
                        case "1":
                            await RunFullSimulationAsync();
                            break;
                        case "2":
                            await DemonstrateVulnerabilitiesAsync();
                            break;
                        case "3":
                            await RunCustomAttackTestsAsync();
                            break;
                        case "4":
                            await ShowSecurityDashboardAsync();
                            break;
                        case "5":
                            await GenerateSecurityReportAsync();
                            break;
                        case "6":
                            await SetupDatabaseAsync();
                            break;
                        case "7":
                            ShowEducationalInformation();
                            break;
                        case "8":
                        case "Q":
                            running = false;
                            break;
                        default:
                            Console.WriteLine("❌ Invalid choice. Please try again.");
                            break;
                    }

                    if (running)
                    {
                        Console.WriteLine("\nPress any key to continue...");
                        Console.ReadKey();
                    }
                }

                Console.WriteLine("\n👋 Thank you for using SQL Injection Cybersecurity Simulator!");
                Console.WriteLine("Stay secure and keep learning! 🛡️");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n💥 Fatal error: {ex.Message}");
                Console.WriteLine("Please check your configuration and database connection.");
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        private static async Task InitializeApplicationAsync()
        {
            Console.WriteLine("🚀 Initializing SQL Injection Cybersecurity Simulator...");

            // Load configuration
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
            
            _configuration = builder.Build();
            _connectionString = _configuration.GetConnectionString("DefaultConnection") 
                ?? throw new InvalidOperationException("Connection string not found in configuration");

            Console.WriteLine("✅ Configuration loaded");

            // Initialize modules
            _userManager = new UserManager(_connectionString);
            _loginSimulator = new LoginSimulator(_connectionString, _userManager);
            _injectionTester = new InjectionTester(_connectionString, _userManager);
            _defenseEngine = new DefenseEngine(_connectionString);
            _reporter = new Reporter(_connectionString);

            Console.WriteLine("✅ Modules initialized");

            // Test database connection
            await TestDatabaseConnectionAsync();
            
            Console.WriteLine("✅ Application ready!");
            Console.WriteLine();
        }

        private static async Task TestDatabaseConnectionAsync()
        {
            try
            {
                var users = await _userManager!.GetAllUsersAsync();
                Console.WriteLine($"✅ Database connection successful ({users.Count} users found)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Database connection issue: {ex.Message}");
                Console.WriteLine("💡 Try running option 6 (Database Setup) to initialize the database.");
            }
        }

        private static void ShowApplicationBanner()
        {
            Console.Clear();
            Console.WriteLine();
            Console.WriteLine(new string('*', 100));
            Console.WriteLine("*" + " ".PadRight(98) + "*");
            Console.WriteLine("*" + "🛡️  SQL INJECTION CYBERSECURITY SIMULATOR - EDUCATIONAL EDITION".PadLeft(64).PadRight(98) + "*");
            Console.WriteLine("*" + " ".PadRight(98) + "*");
            Console.WriteLine("*" + "Learn about SQL injection vulnerabilities and defense mechanisms".PadLeft(67).PadRight(98) + "*");
            Console.WriteLine("*" + "⚠️  FOR EDUCATIONAL PURPOSES ONLY - DO NOT USE AGAINST REAL SYSTEMS".PadLeft(67).PadRight(98) + "*");
            Console.WriteLine("*" + " ".PadRight(98) + "*");
            Console.WriteLine(new string('*', 100));
            Console.WriteLine();
        }

        private static void ShowMainMenu()
        {
            Console.WriteLine("\n" + new string('=', 80));
            Console.WriteLine("📋 MAIN MENU - Choose an option:");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine("1. 🎯 Run Full Security Simulation");
            Console.WriteLine("2. 🔬 Demonstrate SQL Injection Vulnerabilities");
            Console.WriteLine("3. 🧪 Run Custom Attack Tests");
            Console.WriteLine("4. 📊 Show Real-time Security Dashboard");
            Console.WriteLine("5. 📈 Generate Comprehensive Security Report");
            Console.WriteLine("6. 🔧 Database Setup & Initialization");
            Console.WriteLine("7. 📚 Educational Information & Resources");
            Console.WriteLine("8. 🚪 Exit Application");
            Console.WriteLine(new string('=', 80));
            Console.Write("Enter your choice (1-8): ");
        }

        private static async Task RunFullSimulationAsync()
        {
            Console.WriteLine("\n🎯 RUNNING FULL SECURITY SIMULATION");
            Console.WriteLine(new string('=', 80));

            var simulationSettings = _configuration!.GetSection("SimulationSettings");
            int normalAttempts = simulationSettings.GetValue<int>("NormalAttemptsCount", 15);
            int injectionAttempts = simulationSettings.GetValue<int>("InjectionAttemptsCount", 10);
            int bruteForceAttempts = simulationSettings.GetValue<int>("BruteForceAttemptsCount", 5);

            var stopwatch = Stopwatch.StartNew();

            try
            {
                Console.WriteLine($"📊 Simulation Parameters:");
                Console.WriteLine($"   • Normal login attempts: {normalAttempts}");
                Console.WriteLine($"   • Injection attempts: {injectionAttempts}");
                Console.WriteLine($"   • Brute force attempts: {bruteForceAttempts}");
                Console.WriteLine();

                // Phase 1: Normal user behavior
                Console.WriteLine("🟢 Phase 1: Simulating normal user login behavior...");
                var normalLoginAttempts = await _loginSimulator!.GenerateNormalAttemptsAsync(normalAttempts);
                
                foreach (var attempt in normalLoginAttempts)
                {
                    var analysis = await _defenseEngine!.AnalyzeLoginAttemptAsync(
                        attempt.Username, attempt.PasswordInput, attempt.IpAddress, attempt.UserAgent);
                    
                    var result = await _loginSimulator.ExecuteLoginAttemptAsync(attempt, useVulnerableMethod: false);
                    
                    Console.Write(".");
                    await Task.Delay(50); // Realistic timing
                }
                Console.WriteLine($" ✅ Completed {normalAttempts} normal attempts");

                // Phase 2: SQL injection attacks
                Console.WriteLine("\n🔴 Phase 2: Simulating SQL injection attacks...");
                var injectionLoginAttempts = await _loginSimulator.GenerateInjectionAttemptsAsync(injectionAttempts);
                
                foreach (var attempt in injectionLoginAttempts)
                {
                    var analysis = await _defenseEngine!.AnalyzeLoginAttemptAsync(
                        attempt.Username, attempt.PasswordInput, attempt.IpAddress, attempt.UserAgent);
                    
                    // Test both vulnerable and secure methods for comparison
                    var vulnerableResult = await _loginSimulator.ExecuteLoginAttemptAsync(attempt, useVulnerableMethod: true);
                    var secureResult = await _loginSimulator.ExecuteLoginAttemptAsync(attempt, useVulnerableMethod: false);
                    
                    Console.Write("🚨");
                    await Task.Delay(100);
                }
                Console.WriteLine($" ✅ Completed {injectionAttempts} injection attempts");

                // Phase 3: Brute force simulation
                Console.WriteLine("\n🟡 Phase 3: Simulating brute force attacks...");
                var bruteForceLoginAttempts = await _loginSimulator.GenerateBruteForceAttemptsAsync("admin", bruteForceAttempts);
                
                foreach (var attempt in bruteForceLoginAttempts)
                {
                    var analysis = await _defenseEngine!.AnalyzeLoginAttemptAsync(
                        attempt.Username, attempt.PasswordInput, attempt.IpAddress, attempt.UserAgent);
                    
                    var result = await _loginSimulator.ExecuteLoginAttemptAsync(attempt, useVulnerableMethod: false);
                    
                    Console.Write("⚡");
                    await Task.Delay(25); // Rapid attempts
                }
                Console.WriteLine($" ✅ Completed {bruteForceAttempts} brute force attempts");

                stopwatch.Stop();

                // Generate simulation report
                Console.WriteLine($"\n🏁 SIMULATION COMPLETE");
                Console.WriteLine($"⏱️  Total execution time: {stopwatch.Elapsed.TotalSeconds:F1} seconds");
                Console.WriteLine();

                // Show immediate results
                var report = await _reporter!.GenerateSummaryReportAsync(TimeSpan.FromMinutes(5));
                _reporter.DisplaySecurityReport(report);

                // Export results
                await _reporter.ExportToCSVAsync(report);
                await _reporter.ExportToJSONAsync(report);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Simulation error: {ex.Message}");
            }
        }

        private static async Task DemonstrateVulnerabilitiesAsync()
        {
            Console.WriteLine("\n🔬 SQL INJECTION VULNERABILITY DEMONSTRATION");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine("This demonstration shows how SQL injection works and how to prevent it.");
            Console.WriteLine("⚠️  Educational purposes only - these techniques should never be used maliciously.");
            Console.WriteLine();

            await _injectionTester!.RunInjectionTestSuiteAsync();
        }

        private static async Task RunCustomAttackTestsAsync()
        {
            Console.WriteLine("\n🧪 CUSTOM ATTACK TESTS");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine("Test custom payloads to see how vulnerable vs secure implementations respond.");
            Console.WriteLine();

            bool continueTesting = true;
            while (continueTesting)
            {
                Console.Write("Enter username (or 'quit' to return): ");
                string? username = Console.ReadLine();
                
                if (string.IsNullOrEmpty(username) || username.ToLower() == "quit")
                {
                    continueTesting = false;
                    continue;
                }

                Console.Write("Enter password: ");
                string? password = Console.ReadLine();
                
                if (string.IsNullOrEmpty(password))
                {
                    password = "";
                }

                // Analyze the input first
                var usernameAnalysis = _defenseEngine!.AnalyzeForSQLInjection(username);
                var passwordAnalysis = _defenseEngine.AnalyzeForSQLInjection(password);

                if (usernameAnalysis.IsInjection || passwordAnalysis.IsInjection)
                {
                    Console.WriteLine("\n⚠️  POTENTIAL INJECTION DETECTED!");
                    if (usernameAnalysis.IsInjection)
                    {
                        Console.WriteLine($"   Username Risk Level: {usernameAnalysis.RiskLevel}");
                        Console.WriteLine($"   Detected Patterns: {string.Join(", ", usernameAnalysis.DetectedPatterns.Select(p => p.PatternType))}");
                    }
                    if (passwordAnalysis.IsInjection)
                    {
                        Console.WriteLine($"   Password Risk Level: {passwordAnalysis.RiskLevel}");
                        Console.WriteLine($"   Detected Patterns: {string.Join(", ", passwordAnalysis.DetectedPatterns.Select(p => p.PatternType))}");
                    }
                    Console.WriteLine();
                }

                // Run the comparison test
                var result = await _injectionTester!.CompareImplementationsAsync(username, password);

                Console.WriteLine("\n" + new string('-', 40));
                Console.WriteLine("Continue testing? (y/n): ");
                var continueChoice = Console.ReadLine()?.ToLower();
                continueTesting = continueChoice == "y" || continueChoice == "yes";
            }
        }

        private static async Task ShowSecurityDashboardAsync()
        {
            Console.WriteLine("\n📊 REAL-TIME SECURITY DASHBOARD");
            Console.WriteLine("Press 'q' to return to main menu, 'r' to refresh");
            Console.WriteLine();

            bool showDashboard = true;
            while (showDashboard)
            {
                var dashboard = await _reporter!.GetDashboardDataAsync();
                _reporter.DisplayDashboard(dashboard);

                var key = Console.ReadKey();
                if (key.KeyChar == 'q' || key.KeyChar == 'Q')
                {
                    showDashboard = false;
                }
                else if (key.KeyChar == 'r' || key.KeyChar == 'R')
                {
                    // Refresh - continue loop
                    await Task.Delay(1000);
                }
                else
                {
                    await Task.Delay(5000); // Auto refresh every 5 seconds
                }
            }
        }

        private static async Task GenerateSecurityReportAsync()
        {
            Console.WriteLine("\n📈 GENERATING COMPREHENSIVE SECURITY REPORT");
            Console.WriteLine(new string('=', 80));

            Console.Write("Report period in hours (default 24): ");
            string? periodInput = Console.ReadLine();
            
            if (!int.TryParse(periodInput, out int hours) || hours <= 0)
            {
                hours = 24;
            }

            var period = TimeSpan.FromHours(hours);
            Console.WriteLine($"Generating report for the last {hours} hours...");

            try
            {
                var report = await _reporter!.GenerateSummaryReportAsync(period);
                _reporter.DisplaySecurityReport(report);

                Console.WriteLine("\nExport options:");
                Console.WriteLine("1. Export to CSV");
                Console.WriteLine("2. Export to JSON");
                Console.WriteLine("3. Export both formats");
                Console.WriteLine("4. No export");
                Console.Write("Choose export option (1-4): ");

                var exportChoice = Console.ReadLine();
                switch (exportChoice)
                {
                    case "1":
                        await _reporter.ExportToCSVAsync(report);
                        break;
                    case "2":
                        await _reporter.ExportToJSONAsync(report);
                        break;
                    case "3":
                        await _reporter.ExportToCSVAsync(report);
                        await _reporter.ExportToJSONAsync(report);
                        break;
                    default:
                        Console.WriteLine("No export performed.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error generating report: {ex.Message}");
            }
        }

        private static async Task SetupDatabaseAsync()
        {
            Console.WriteLine("\n🔧 DATABASE SETUP & INITIALIZATION");
            Console.WriteLine(new string('=', 80));

            try
            {
                Console.WriteLine("🔄 Creating test users...");
                await _userManager!.CreateTestUsersAsync();
                
                Console.WriteLine("✅ Database setup completed successfully!");
                Console.WriteLine("🎉 You can now run simulations and tests.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Database setup error: {ex.Message}");
                Console.WriteLine("💡 Make sure SQL Server LocalDB is installed and running.");
                Console.WriteLine("💡 You may need to run the schema.sql and seed.sql scripts manually.");
            }
        }

        private static void ShowEducationalInformation()
        {
            Console.Clear();
            Console.WriteLine("📚 EDUCATIONAL INFORMATION & RESOURCES");
            Console.WriteLine(new string('=', 100));
            Console.WriteLine();

            Console.WriteLine("🎯 WHAT IS SQL INJECTION?");
            Console.WriteLine("SQL injection is a code injection technique where malicious SQL statements are inserted");
            Console.WriteLine("into application entry points, allowing attackers to interfere with database queries.");
            Console.WriteLine();

            Console.WriteLine("🔍 COMMON ATTACK PATTERNS:");
            Console.WriteLine("• Boolean-based: ' OR '1'='1");
            Console.WriteLine("• Comment injection: admin'--");
            Console.WriteLine("• Union-based: ' UNION SELECT username, password FROM users--");
            Console.WriteLine("• Time-based: '; WAITFOR DELAY '00:00:05'--");
            Console.WriteLine("• Error-based: ' AND (SELECT COUNT(*) FROM sysobjects) > 0--");
            Console.WriteLine();

            Console.WriteLine("🛡️  DEFENSE MECHANISMS:");
            Console.WriteLine("✅ Parameterized Queries: Use @parameters instead of string concatenation");
            Console.WriteLine("✅ Input Validation: Validate and sanitize all user inputs");
            Console.WriteLine("✅ Least Privilege: Use database accounts with minimal necessary permissions");
            Console.WriteLine("✅ Error Handling: Don't expose detailed error messages to users");
            Console.WriteLine("✅ Regular Security Audits: Test applications for vulnerabilities regularly");
            Console.WriteLine();

            Console.WriteLine("📖 ADDITIONAL RESOURCES:");
            Console.WriteLine("• OWASP SQL Injection Prevention Cheat Sheet");
            Console.WriteLine("• Microsoft Security Development Lifecycle (SDL)");
            Console.WriteLine("• NIST Cybersecurity Framework");
            Console.WriteLine("• CWE-89: SQL Injection");
            Console.WriteLine();

            Console.WriteLine("⚠️  LEGAL AND ETHICAL NOTICE:");
            Console.WriteLine("This simulator is for educational purposes only. Using these techniques against");
            Console.WriteLine("systems you don't own or without explicit permission is illegal and unethical.");
            Console.WriteLine("Always practice responsible disclosure and follow your organization's security policies.");
            Console.WriteLine();

            Console.WriteLine("🎓 LEARNING OBJECTIVES:");
            Console.WriteLine("By using this simulator, you should understand:");
            Console.WriteLine("• How SQL injection vulnerabilities occur");
            Console.WriteLine("• The potential impact of successful attacks");
            Console.WriteLine("• How to implement secure coding practices");
            Console.WriteLine("• How to detect and respond to attack attempts");
            Console.WriteLine();

            Console.WriteLine(new string('=', 100));
        }
    }
}