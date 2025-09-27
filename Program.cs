using Microsoft.Extensions.Configuration;
using SQLInjectionSimulator.Modules;
using System.Text;

namespace SQLInjectionSimulator
{
    /// <summary>
    /// SQL Injection Cybersecurity Simulator - Educational Console Application
    /// 
    /// ⚠️ FOR EDUCATIONAL USE ONLY - DO NOT USE AGAINST REAL SYSTEMS
    /// </summary>
    class Program
    {
        private static string _connectionString = "Server=(localdb)\\MSSQLLocalDB;Database=SQLInjectionSimulator;Trusted_Connection=true;MultipleActiveResultSets=true;TrustServerCertificate=true";
        private static UserManager? _userManager;
        private static UserManagerSimple? _userManagerSimple;
        private static InjectionTester? _injectionTester;
        private static LoginSimulator? _loginSimulator;
        private static DefenseEngine? _defenseEngine;
        private static Reporter? _reporter;

        static async Task Main(string[] args)
        {
            try
            {
                Console.WriteLine("🛡️ SQL Injection Cybersecurity Simulator");
                Console.WriteLine("==========================================");
                Console.WriteLine("⚠️  FOR EDUCATIONAL PURPOSES ONLY");
                Console.WriteLine("🎯 Learn how SQL injection works and how to prevent it");
                Console.WriteLine();

                // Initialize components
                await InitializeComponentsAsync();

                bool continueRunning = true;
                while (continueRunning)
                {
                    Console.Clear();
                    ShowWelcomeHeader();
                    ShowMainMenu();
                    
                    var choice = Console.ReadLine()?.Trim();
                    continueRunning = await HandleMainMenuChoice(choice);

                    if (continueRunning)
                    {
                        Console.WriteLine("\nPress any key to continue...");
                        Console.ReadKey();
                    }
                }

                Console.WriteLine("\n👋 Thank you for using SQL Injection Cybersecurity Simulator!");
                Console.WriteLine("Stay safe and secure! 🛡️");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Critical Error: {ex.Message}");
                Console.WriteLine("Please ensure SQL Server LocalDB is installed and accessible.");
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        private static async Task InitializeComponentsAsync()
        {
            Console.WriteLine("🚀 Initializing application components...");
            
            try
            {
                _userManagerSimple = new UserManagerSimple(_connectionString);
                _userManager = new UserManager(_connectionString);
                _injectionTester = new InjectionTester(_connectionString, _userManager);
                _loginSimulator = new LoginSimulator(_connectionString, _userManager);
                _defenseEngine = new DefenseEngine(_connectionString);
                _reporter = new Reporter(_connectionString);

                Console.WriteLine("✅ All components initialized successfully!");
                Console.WriteLine("🗄️  Database connection established");
                Console.WriteLine("📊 Security monitoring active");
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Initialization failed: {ex.Message}");
                throw;
            }
        }

        private static void ShowWelcomeHeader()
        {
            Console.WriteLine("🛡️ SQL Injection Cybersecurity Simulator");
            Console.WriteLine("==========================================");
            Console.WriteLine("⚠️  FOR EDUCATIONAL PURPOSES ONLY");
            Console.WriteLine();
        }

        private static void ShowMainMenu()
        {
            Console.WriteLine("📋 Educational Menu - Choose Your Learning Path:");
            Console.WriteLine();
            Console.WriteLine("🏗️  SETUP & PREPARATION:");
            Console.WriteLine("1. Initialize Database & Create Test Users");
            Console.WriteLine("2. View Current Users & System Status");
            Console.WriteLine();
            Console.WriteLine("🧪 CORE SQL INJECTION DEMONSTRATIONS:");
            Console.WriteLine("3. Interactive Injection Testing Suite");
            Console.WriteLine("4. Compare Vulnerable vs Secure Queries");
            Console.WriteLine("5. Custom Injection Test (Enter Your Own Input)");
            Console.WriteLine();
            Console.WriteLine("⚔️  ATTACK SIMULATION SCENARIOS:");
            Console.WriteLine("6. Simulate Realistic Attack Patterns");
            Console.WriteLine("7. Brute Force Attack Simulation");
            Console.WriteLine("8. Advanced Injection Patterns Demo");
            Console.WriteLine();
            Console.WriteLine("🛡️  DEFENSE & MONITORING:");
            Console.WriteLine("9. Real-time Defense Engine Demo");
            Console.WriteLine("10. Security Metrics Dashboard");
            Console.WriteLine("11. Generate Comprehensive Security Report");
            Console.WriteLine();
            Console.WriteLine("📚 EDUCATIONAL RESOURCES:");
            Console.WriteLine("12. Learn About SQL Injection Basics");
            Console.WriteLine("13. Best Practices & Prevention Guide");
            Console.WriteLine();
            Console.WriteLine("0. Exit Application");
            Console.WriteLine();
            Console.Write("Enter your choice: ");
        }

        private static async Task<bool> HandleMainMenuChoice(string? choice)
        {
            try
            {
                switch (choice?.Trim())
                {
                    case "1":
                        await InitializeDatabaseAsync();
                        break;
                    case "2":
                        await ShowSystemStatusAsync();
                        break;
                    case "3":
                        await RunInteractiveInjectionTestSuiteAsync();
                        break;
                    case "4":
                        await RunVulnerableVsSecureComparisonAsync();
                        break;
                    case "5":
                        await RunCustomInjectionTestAsync();
                        break;
                    case "6":
                        await SimulateRealisticAttackPatternsAsync();
                        break;
                    case "7":
                        await SimulateBruteForceAttackAsync();
                        break;
                    case "8":
                        await DemonstrateAdvancedInjectionPatternsAsync();
                        break;
                    case "9":
                        await RunDefenseEngineDemo();
                        break;
                    case "10":
                        await ShowSecurityMetricsDashboard();
                        break;
                    case "11":
                        await GenerateComprehensiveReport();
                        break;
                    case "12":
                        ShowSqlInjectionBasics();
                        break;
                    case "13":
                        ShowBestPracticesGuide();
                        break;
                    case "0":
                        return false;
                    default:
                        Console.WriteLine("❌ Invalid choice. Please select a number from 0-13.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error executing option: {ex.Message}");
                Console.WriteLine("📝 This might be expected behavior in some injection tests.");
            }

            return true;
        }

        private static async Task InitializeDatabaseAsync()
        {
            Console.WriteLine("\n🏗️ DATABASE INITIALIZATION");
            Console.WriteLine("==============================");
            
            if (_userManagerSimple != null)
            {
                Console.WriteLine("📊 Setting up test users for educational demonstrations...");
                await _userManagerSimple.CreateTestUsersAsync();
                
                Console.WriteLine("\n✅ Database initialized successfully!");
                Console.WriteLine("📝 Test users created for educational purposes");
                Console.WriteLine("🔒 All passwords are securely hashed using BCrypt");
            }
        }

        private static async Task ShowSystemStatusAsync()
        {
            Console.WriteLine("\n📊 SYSTEM STATUS & USER OVERVIEW");
            Console.WriteLine("===================================");
            
            if (_userManagerSimple != null)
            {
                Console.WriteLine("👥 Current Users in System:");
                var users = await _userManagerSimple.GetAllUsersAsync();
                
                foreach (var user in users)
                {
                    string status = user.IsActive ? "✅ Active" : "❌ Inactive";
                    string lastLogin = user.LastLoginDate?.ToString("yyyy-MM-dd HH:mm") ?? "Never";
                    Console.WriteLine($"   🧑 {user.Username,-15} | {status,-10} | Last Login: {lastLogin}");
                }
                
                Console.WriteLine($"\n📈 Total Users: {users.Count()}");
                Console.WriteLine($"✅ Active Users: {users.Count(u => u.IsActive)}");
                Console.WriteLine($"❌ Inactive Users: {users.Count(u => !u.IsActive)}");
            }
        }

        private static async Task RunInteractiveInjectionTestSuiteAsync()
        {
            Console.WriteLine("\n🧪 INTERACTIVE SQL INJECTION TEST SUITE");
            Console.WriteLine("==========================================");
            Console.WriteLine("This demonstration shows various SQL injection techniques");
            Console.WriteLine("and how they behave with vulnerable vs. secure implementations.\n");

            if (_injectionTester != null)
            {
                await _injectionTester.RunInjectionTestSuiteAsync();
            }
        }

        private static async Task RunVulnerableVsSecureComparisonAsync()
        {
            Console.WriteLine("\n⚖️  VULNERABLE vs SECURE QUERY COMPARISON");
            Console.WriteLine("===========================================");
            Console.WriteLine("Enter test credentials to see the difference between");
            Console.WriteLine("vulnerable and secure query implementations.\n");

            Console.Write("Enter username (try 'admin' OR '1'='1'): ");
            var username = Console.ReadLine() ?? "";
            
            Console.Write("Enter password (try anything): ");
            var password = Console.ReadLine() ?? "";

            if (_injectionTester != null)
            {
                await _injectionTester.CompareImplementationsAsync(username, password);
            }
        }

        private static async Task RunCustomInjectionTestAsync()
        {
            Console.WriteLine("\n🎯 CUSTOM INJECTION TEST");
            Console.WriteLine("==========================");
            Console.WriteLine("Test your own SQL injection payloads!");
            Console.WriteLine("This is a safe environment to experiment and learn.\n");

            Console.WriteLine("💡 Try these example payloads:");
            Console.WriteLine("   - admin' OR '1'='1");
            Console.WriteLine("   - admin'--");
            Console.WriteLine("   - ' UNION SELECT 1,'hacker'--");
            Console.WriteLine("   - '; DROP TABLE Users--");
            Console.WriteLine();

            Console.Write("Enter your test username: ");
            var username = Console.ReadLine() ?? "";
            
            Console.Write("Enter your test password: ");
            var password = Console.ReadLine() ?? "";

            if (_injectionTester != null)
            {
                await _injectionTester.CompareImplementationsAsync(username, password);
            }
        }

        private static async Task SimulateRealisticAttackPatternsAsync()
        {
            Console.WriteLine("\n⚔️  REALISTIC ATTACK PATTERN SIMULATION");
            Console.WriteLine("========================================");
            Console.WriteLine("Simulating a mix of normal and malicious login attempts");
            Console.WriteLine("to demonstrate how attacks might look in real scenarios.\n");

            if (_loginSimulator != null && _defenseEngine != null)
            {
                // Generate normal attempts
                Console.WriteLine("👥 Generating normal user behavior...");
                var normalAttempts = await _loginSimulator.GenerateNormalAttemptsAsync(5);
                
                Console.WriteLine("🔍 Analyzing normal attempts:");
                foreach (var attempt in normalAttempts)
                {
                    var result = await _loginSimulator.ExecuteLoginAttemptAsync(attempt);
                    var analysis = await _defenseEngine.AnalyzeLoginAttemptAsync(
                        attempt.Username, attempt.Password, attempt.IpAddress, attempt.UserAgent);
                    
                    Console.WriteLine($"   📝 {attempt.Username}: {(result.IsSuccessful ? "✅ Success" : "❌ Failed")} " +
                                      $"- Threat: {analysis.ThreatLevel}");
                }

                Console.WriteLine("\n🚨 Generating injection attack attempts...");
                var injectionAttempts = await _loginSimulator.GenerateInjectionAttemptsAsync(3);
                
                Console.WriteLine("🔍 Analyzing attack attempts:");
                foreach (var attempt in injectionAttempts)
                {
                    var result = await _loginSimulator.ExecuteLoginAttemptAsync(attempt, true);
                    var analysis = await _defenseEngine.AnalyzeLoginAttemptAsync(
                        attempt.Username, attempt.Password, attempt.IpAddress, attempt.UserAgent);
                    
                    Console.WriteLine($"   🚨 Attack detected: {attempt.Username.Substring(0, Math.Min(20, attempt.Username.Length))}..." +
                                      $" - Threat: {analysis.ThreatLevel}");
                }
            }
        }

        private static async Task SimulateBruteForceAttackAsync()
        {
            Console.WriteLine("\n💥 BRUTE FORCE ATTACK SIMULATION");
            Console.WriteLine("==================================");
            Console.WriteLine("Demonstrating rapid-fire login attempts against a single account.\n");

            Console.Write("Enter target username to attack (default: admin): ");
            var targetUser = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(targetUser))
                targetUser = "admin";

            if (_loginSimulator != null && _defenseEngine != null)
            {
                Console.WriteLine($"🎯 Launching brute force attack against '{targetUser}'...");
                
                var bruteForceAttempts = await _loginSimulator.GenerateBruteForceAttemptsAsync(targetUser, 5);
                
                Console.WriteLine("🔍 Real-time attack analysis:");
                foreach (var attempt in bruteForceAttempts)
                {
                    var startTime = DateTime.Now;
                    var result = await _loginSimulator.ExecuteLoginAttemptAsync(attempt);
                    var analysis = await _defenseEngine.AnalyzeLoginAttemptAsync(
                        attempt.Username, attempt.Password, attempt.IpAddress, attempt.UserAgent);
                    
                    var responseTime = (DateTime.Now - startTime).TotalMilliseconds;
                    
                    Console.WriteLine($"   ⚡ Attempt: {attempt.Password.Substring(0, Math.Min(10, attempt.Password.Length))} " +
                                      $"- Result: {(result.IsSuccessful ? "✅" : "❌")} " +
                                      $"- Threat: {analysis.ThreatLevel} " +
                                      $"- Time: {responseTime:F0}ms");
                    
                    // Small delay to show progression
                    await Task.Delay(200);
                }
            }
        }

        private static async Task DemonstrateAdvancedInjectionPatternsAsync()
        {
            Console.WriteLine("\n🎓 ADVANCED INJECTION PATTERNS DEMONSTRATION");
            Console.WriteLine("===============================================");
            Console.WriteLine("Educational showcase of sophisticated SQL injection techniques.\n");

            var advancedPatterns = new List<(string description, string username, string password)>
            {
                ("Time-Based Blind Injection", "admin", "'; WAITFOR DELAY '00:00:01'--"),
                ("Union-Based Information Extraction", "test' UNION SELECT username, password FROM Users--", "anything"),
                ("Error-Based SQL Injection", "admin'", "convert(int,@@version)--"),
                ("Boolean-Based Blind SQL Injection", "admin' AND 1=1--", "password"),
                ("Second-Order SQL Injection", "admin", "'; UPDATE Users SET password='hacked' WHERE username='admin'--"),
                ("Stacked Queries Attack", "admin'; DROP TABLE IF EXISTS TempTable--", "password"),
                ("Comment-Based Evasion", "admin'/**/OR/**/1=1--", "password")
            };

            Console.WriteLine("🔬 Running advanced pattern analysis:\n");

            if (_injectionTester != null)
            {
                foreach (var (description, username, password) in advancedPatterns)
                {
                    Console.WriteLine($"🧪 Testing: {description}");
                    Console.WriteLine(new string('-', 50));
                    
                    await _injectionTester.CompareImplementationsAsync(username, password);
                    
                    Console.WriteLine("\n" + new string('═', 80) + "\n");
                    await Task.Delay(1000); // Pause between tests for readability
                }
            }
        }

        private static async Task RunDefenseEngineDemo()
        {
            Console.WriteLine("\n🛡️ REAL-TIME DEFENSE ENGINE DEMONSTRATION");
            Console.WriteLine("============================================");
            Console.WriteLine("Watch as the defense engine analyzes and responds to threats.\n");

            if (_defenseEngine != null)
            {
                var testInputs = new[]
                {
                    ("normal_user", "valid_password", "192.168.1.100", "Mozilla/5.0"),
                    ("admin' OR 1=1--", "anything", "10.0.0.1", "curl/7.68.0"),
                    ("admin", "'; DROP TABLE Users--", "192.168.1.1", "sqlmap/1.5.2"),
                    ("test' UNION SELECT * FROM Users--", "password", "172.16.0.1", "Burp Suite")
                };

                Console.WriteLine("🔍 Real-time threat analysis:");
                foreach (var (username, password, ip, userAgent) in testInputs)
                {
                    Console.WriteLine($"\n📥 Analyzing: {username.Substring(0, Math.Min(20, username.Length))}...");
                    
                    var analysis = await _defenseEngine.AnalyzeLoginAttemptAsync(username, password, ip, userAgent);
                    
                    Console.WriteLine($"   🎯 Threat Level: {analysis.ThreatLevel}");
                    Console.WriteLine($"   🚨 SQL Injection Risk: {(analysis.IsSqlInjectionDetected ? "HIGH" : "LOW")}");
                    Console.WriteLine($"   🔄 Brute Force Risk: {(analysis.IsBruteForceDetected ? "HIGH" : "LOW")}");
                    Console.WriteLine($"   📍 Source: {ip} via {userAgent.Substring(0, Math.Min(15, userAgent.Length))}...");
                    
                    if (analysis.RecommendedAction != "ALLOW")
                    {
                        Console.WriteLine($"   ⚡ Action: {analysis.RecommendedAction}");
                    }
                }
            }
        }

        private static async Task ShowSecurityMetricsDashboard()
        {
            Console.WriteLine("\n📊 SECURITY METRICS DASHBOARD");
            Console.WriteLine("===============================");
            
            if (_defenseEngine != null)
            {
                var metrics = await _defenseEngine.GetSecurityMetricsAsync(TimeSpan.FromDays(30));
                
                Console.WriteLine("📈 30-Day Security Overview:");
                Console.WriteLine($"   🔢 Total Login Attempts: {metrics.TotalAttempts}");
                Console.WriteLine($"   ✅ Successful Logins: {metrics.SuccessfulAttempts} ({metrics.SuccessRate:F1}%)");
                Console.WriteLine($"   ❌ Failed Attempts: {metrics.FailedAttempts} ({metrics.FailureRate:F1}%)");
                Console.WriteLine($"   🚨 Injection Attempts: {metrics.InjectionAttempts} ({metrics.InjectionRate:F1}%)");
                Console.WriteLine($"   💥 Brute Force Attempts: {metrics.BruteForceAttempts}");
                Console.WriteLine($"   🎯 Blocked Attacks: {metrics.BlockedAttempts}");
                
                Console.WriteLine("\n🚨 Alert Summary:");
                Console.WriteLine($"   🔴 Critical Alerts: {metrics.CriticalAlerts}");
                Console.WriteLine($"   🟡 High Priority: {metrics.HighAlerts}");
                Console.WriteLine($"   🟠 Medium Priority: {metrics.MediumAlerts}");
                Console.WriteLine($"   🟢 Low Priority: {metrics.LowAlerts}");
                
                Console.WriteLine($"\n⚡ Average Response Time: {metrics.AverageResponseTime:F1}ms");
                Console.WriteLine($"🛡️  Detection Rate: {metrics.DetectionRate:F1}%");
            }
        }

        private static async Task GenerateComprehensiveReport()
        {
            Console.WriteLine("\n📋 COMPREHENSIVE SECURITY REPORT");
            Console.WriteLine("===================================");
            
            if (_reporter != null)
            {
                Console.WriteLine("🔄 Generating detailed security analysis...");
                var report = await _reporter.GenerateReportAsync();
                
                _reporter.DisplayReport(report);
                
                Console.WriteLine("\n💾 Export Options:");
                Console.WriteLine("Would you like to export this report? (y/n): ");
                var exportChoice = Console.ReadLine()?.ToLower();
                
                if (exportChoice == "y" || exportChoice == "yes")
                {
                    Console.WriteLine("📂 Report export functionality would be available in production version.");
                    Console.WriteLine("📊 Data can be exported to CSV, JSON, or PDF formats.");
                }
            }
        }

        private static void ShowSqlInjectionBasics()
        {
            Console.WriteLine("\n📚 SQL INJECTION FUNDAMENTALS");
            Console.WriteLine("===============================");
            
            var basics = new StringBuilder();
            basics.AppendLine("🎯 What is SQL Injection?");
            basics.AppendLine("SQL injection is a code injection technique that exploits vulnerabilities");
            basics.AppendLine("in an application's software by inserting malicious SQL statements into");
            basics.AppendLine("entry fields for execution.\n");
            
            basics.AppendLine("🔍 How Does It Work?");
            basics.AppendLine("1. Attacker finds input field that connects to database");
            basics.AppendLine("2. Sends malicious SQL code instead of expected data");
            basics.AppendLine("3. Application executes the malicious code");
            basics.AppendLine("4. Attacker gains unauthorized access or extracts data\n");
            
            basics.AppendLine("⚠️  Common Vulnerabilities:");
            basics.AppendLine("• String concatenation in SQL queries");
            basics.AppendLine("• Lack of input validation");
            basics.AppendLine("• Excessive database privileges");
            basics.AppendLine("• Poor error handling that reveals information\n");
            
            basics.AppendLine("🛡️  Prevention Techniques:");
            basics.AppendLine("✅ Use parameterized queries/prepared statements");
            basics.AppendLine("✅ Implement input validation and sanitization");
            basics.AppendLine("✅ Apply principle of least privilege");
            basics.AppendLine("✅ Use stored procedures when appropriate");
            basics.AppendLine("✅ Regular security testing and code reviews\n");
            
            Console.WriteLine(basics.ToString());
        }

        private static void ShowBestPracticesGuide()
        {
            Console.WriteLine("\n📖 BEST PRACTICES & PREVENTION GUIDE");
            Console.WriteLine("======================================");
            
            var guide = new StringBuilder();
            guide.AppendLine("🔒 Secure Coding Practices:");
            guide.AppendLine();
            guide.AppendLine("1. 📝 PARAMETERIZED QUERIES (Most Important!)");
            guide.AppendLine("   ❌ Bad:  SELECT * FROM Users WHERE id = '" + "[userId]" + "'");
            guide.AppendLine("   ✅ Good: SELECT * FROM Users WHERE id = @userId");
            guide.AppendLine();
            guide.AppendLine("2. 🧹 INPUT VALIDATION");
            guide.AppendLine("   • Validate data type, length, format, and range");
            guide.AppendLine("   • Use allow-lists rather than block-lists");
            guide.AppendLine("   • Encode output appropriately");
            guide.AppendLine();
            guide.AppendLine("3. 🔐 DATABASE SECURITY");
            guide.AppendLine("   • Use least-privilege principle for database accounts");
            guide.AppendLine("   • Avoid using SA or administrative accounts");
            guide.AppendLine("   • Regular security updates and patches");
            guide.AppendLine();
            guide.AppendLine("4. 🚨 ERROR HANDLING");
            guide.AppendLine("   • Don't expose database errors to users");
            guide.AppendLine("   • Log detailed errors securely for developers");
            guide.AppendLine("   • Use generic error messages for users");
            guide.AppendLine();
            guide.AppendLine("5. 📊 MONITORING & LOGGING");
            guide.AppendLine("   • Log all database access attempts");
            guide.AppendLine("   • Monitor for suspicious patterns");
            guide.AppendLine("   • Implement real-time alerting");
            guide.AppendLine();
            guide.AppendLine("🔍 Testing Your Applications:");
            guide.AppendLine("• Use automated security scanning tools");
            guide.AppendLine("• Perform regular penetration testing");
            guide.AppendLine("• Conduct code reviews with security focus");
            guide.AppendLine("• Use this simulator for educational testing!");
            
            Console.WriteLine(guide.ToString());
        }
    }
}