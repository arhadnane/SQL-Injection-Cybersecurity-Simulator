using Microsoft.Data.SqlClient;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace SQLInjectionSimulator.Modules
{
    /// <summary>
    /// Demonstrates the difference between vulnerable and secure database query implementations
    /// Educational tool showing how SQL injection works and how to prevent it
    /// </summary>
    public class InjectionTester
    {
        private readonly string _connectionString;
        private readonly UserManager _userManager;

        public InjectionTester(string connectionString, UserManager userManager)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }

        /// <summary>
        /// Demonstrate vulnerable query execution (for educational purposes only)
        /// Shows how string concatenation can be exploited
        /// </summary>
        public async Task<VulnerabilityTestResult> DemonstrateVulnerableQueryAsync(string userInput, string passwordInput)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new VulnerabilityTestResult
            {
                TestType = "Vulnerable Query",
                Input = userInput,
                PasswordInput = passwordInput
            };

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                // VULNERABLE: String concatenation - DON'T DO THIS IN PRODUCTION!
                string query = $"SELECT UserId, Username FROM Users WHERE Username = '{userInput}' AND PasswordHash = '{passwordInput}'";
                result.QueryExecuted = query;

                Console.WriteLine("🚨 VULNERABLE QUERY EXECUTION:");
                Console.WriteLine($"   Query: {query}");
                Console.WriteLine("   ⚠️  This query is vulnerable to SQL injection!");

                using var command = new SqlCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                var rows = new List<Dictionary<string, object>>();
                while (reader.Read())
                {
                    var row = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        row[reader.GetName(i)] = reader.GetValue(i);
                    }
                    rows.Add(row);
                }

                result.RowsReturned = rows.Count;
                result.Success = true;
                result.Message = $"Query executed successfully. Returned {rows.Count} rows.";
                
                if (rows.Count > 0)
                {
                    Console.WriteLine($"   📊 Results: {rows.Count} rows returned");
                    foreach (var row in rows.Take(5)) // Show first 5 rows max
                    {
                        Console.WriteLine($"      - UserId: {row.GetValueOrDefault("UserId", "N/A")}, Username: {row.GetValueOrDefault("Username", "N/A")}");
                    }
                }
            }
            catch (SqlException ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                result.Message = "SQL error occurred (possibly due to injection)";
                
                Console.WriteLine($"   💥 SQL Error: {ex.Message}");
                Console.WriteLine("   This error might indicate a successful injection attempt!");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                result.Message = "Unexpected error occurred";
                
                Console.WriteLine($"   ❌ Error: {ex.Message}");
            }

            stopwatch.Stop();
            result.ExecutionTime = stopwatch.ElapsedMilliseconds;
            
            return result;
        }

        /// <summary>
        /// Demonstrate secure query execution using parameterized queries
        /// Shows the proper way to handle user input
        /// </summary>
        public async Task<VulnerabilityTestResult> DemonstrateSecureQueryAsync(string userInput, string passwordInput)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new VulnerabilityTestResult
            {
                TestType = "Secure Query",
                Input = userInput,
                PasswordInput = passwordInput
            };

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                // SECURE: Parameterized query - This is the correct approach!
                string query = "SELECT UserId, Username FROM Users WHERE Username = @username AND PasswordHash = @password";
                result.QueryExecuted = query;

                Console.WriteLine("✅ SECURE QUERY EXECUTION:");
                Console.WriteLine($"   Query: {query}");
                Console.WriteLine("   🛡️  Parameters: @username, @password");
                Console.WriteLine("   ✨ This query is protected against SQL injection!");

                using var command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@username", userInput);
                command.Parameters.AddWithValue("@password", passwordInput);

                using var reader = await command.ExecuteReaderAsync();

                var rows = new List<Dictionary<string, object>>();
                while (reader.Read())
                {
                    var row = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        row[reader.GetName(i)] = reader.GetValue(i);
                    }
                    rows.Add(row);
                }

                result.RowsReturned = rows.Count;
                result.Success = true;
                result.Message = $"Query executed securely. Returned {rows.Count} rows.";
                
                Console.WriteLine($"   📊 Results: {rows.Count} rows returned");
                if (rows.Count > 0)
                {
                    foreach (var row in rows.Take(5))
                    {
                        Console.WriteLine($"      - UserId: {row.GetValueOrDefault("UserId", "N/A")}, Username: {row.GetValueOrDefault("Username", "N/A")}");
                    }
                }
            }
            catch (SqlException ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                result.Message = "SQL error occurred";
                
                Console.WriteLine($"   ❌ SQL Error: {ex.Message}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
                result.Message = "Unexpected error occurred";
                
                Console.WriteLine($"   ❌ Error: {ex.Message}");
            }

            stopwatch.Stop();
            result.ExecutionTime = stopwatch.ElapsedMilliseconds;
            
            return result;
        }

        /// <summary>
        /// Compare vulnerable vs secure implementations side by side
        /// </summary>
        public async Task<ComparisonResult> CompareImplementationsAsync(string userInput, string passwordInput)
        {
            Console.WriteLine("\n" + new string('=', 80));
            Console.WriteLine("🔬 VULNERABILITY COMPARISON TEST");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"Input: '{userInput}'");
            Console.WriteLine($"Password: '{passwordInput}'");
            Console.WriteLine();

            var vulnerableResult = await DemonstrateVulnerableQueryAsync(userInput, passwordInput);
            Console.WriteLine();
            
            var secureResult = await DemonstrateSecureQueryAsync(userInput, passwordInput);
            Console.WriteLine();

            var comparison = new ComparisonResult
            {
                Input = userInput,
                PasswordInput = passwordInput,
                VulnerableResult = vulnerableResult,
                SecureResult = secureResult,
                IsPotentialInjection = IsPotentialInjectionAttempt(userInput) || IsPotentialInjectionAttempt(passwordInput)
            };

            // Analysis
            Console.WriteLine("📋 ANALYSIS:");
            if (comparison.IsPotentialInjection)
            {
                Console.WriteLine("   🚨 POTENTIAL INJECTION DETECTED!");
                Console.WriteLine("   The input contains patterns commonly used in SQL injection attacks.");
                
                if (vulnerableResult.Success && vulnerableResult.RowsReturned > secureResult.RowsReturned)
                {
                    Console.WriteLine("   💀 VULNERABILITY CONFIRMED: Vulnerable query returned more data!");
                    Console.WriteLine("   This demonstrates how injection can bypass authentication.");
                }
                else if (!vulnerableResult.Success && vulnerableResult.Error != null)
                {
                    Console.WriteLine("   💥 INJECTION CAUSED ERROR: The vulnerable query failed.");
                    Console.WriteLine("   This could indicate a successful injection attempt.");
                }
                
                Console.WriteLine("   🛡️  PROTECTION CONFIRMED: Secure query handled input safely.");
            }
            else
            {
                Console.WriteLine("   ✅ Normal input detected - no injection patterns found.");
            }

            Console.WriteLine($"   ⏱️  Performance: Vulnerable={vulnerableResult.ExecutionTime}ms, Secure={secureResult.ExecutionTime}ms");
            Console.WriteLine(new string('=', 80));

            return comparison;
        }

        /// <summary>
        /// Test multiple injection payloads for educational purposes
        /// </summary>
        public async Task RunInjectionTestSuiteAsync()
        {
            var testCases = new List<(string description, string username, string password)>
            {
                ("Normal Login", "admin", "password123"),
                ("Invalid Credentials", "admin", "wrongpassword"),
                ("Classic OR Injection", "admin' OR '1'='1", "anything"),
                ("Comment Injection", "admin'--", "ignored"),
                ("Union Injection", "test' UNION SELECT 1, 'hacker'--", "password"),
                ("Boolean Blind", "admin' AND '1'='1", "password"),
                ("Error-Based", "admin'", "convert(int,@@version)"),
                ("Time-Based", "admin", "'; WAITFOR DELAY '00:00:01'--"),
                ("Drop Table", "admin", "'; DROP TABLE Users--"),
                ("Multiple Statements", "admin'; INSERT INTO Users VALUES('hacker','hash')--", "password")
            };

            Console.WriteLine("\n" + new string('*', 100));
            Console.WriteLine("🧪 SQL INJECTION TEST SUITE - EDUCATIONAL DEMONSTRATION");
            Console.WriteLine(new string('*', 100));

            var results = new List<ComparisonResult>();

            for (int i = 0; i < testCases.Count; i++)
            {
                var (description, username, password) = testCases[i];
                
                Console.WriteLine($"\n🧪 Test Case {i + 1}: {description}");
                Console.WriteLine(new string('-', 50));
                
                var result = await CompareImplementationsAsync(username, password);
                results.Add(result);

                // Add delay between tests for readability
                await Task.Delay(500);
            }

            // Summary
            Console.WriteLine("\n" + new string('*', 100));
            Console.WriteLine("📊 TEST SUITE SUMMARY");
            Console.WriteLine(new string('*', 100));

            int injectionCount = results.Count(r => r.IsPotentialInjection);
            int vulnerableSuccesses = results.Count(r => r.VulnerableResult.Success && r.IsPotentialInjection);
            int secureProtections = results.Count(r => !r.SecureResult.Success || r.SecureResult.RowsReturned == 0 && r.IsPotentialInjection);

            Console.WriteLine($"Total Test Cases: {results.Count}");
            Console.WriteLine($"Injection Attempts: {injectionCount}");
            Console.WriteLine($"Vulnerable Method Exploited: {vulnerableSuccesses}/{injectionCount}");
            Console.WriteLine($"Secure Method Protected: {secureProtections}/{injectionCount}");
            Console.WriteLine($"Protection Effectiveness: {(secureProtections * 100.0 / Math.Max(injectionCount, 1)):F1}%");
        }

        /// <summary>
        /// Check if input contains potential SQL injection patterns
        /// </summary>
        private bool IsPotentialInjectionAttempt(string input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            var patterns = new[]
            {
                @"'\s*(OR|AND)\s*'?\w*'?\s*=\s*'?\w*'?",  // OR/AND conditions
                @"'\s*OR\s+\d+\s*=\s*\d+",                // OR 1=1 style
                @"--",                                      // SQL comments
                @"/\*.*?\*/",                              // Block comments  
                @";\s*(DROP|DELETE|INSERT|UPDATE)",        // Dangerous commands
                @"UNION\s+SELECT",                         // Union injection
                @"WAITFOR\s+DELAY",                        // Time delays
                @"@@\w+",                                  // System variables
                @"xp_\w+|sp_\w+",                         // System procedures
                @"'\s*;",                                  // Statement terminators
                @"EXEC\s*\(",                             // Execute commands
                @"CONVERT\s*\(",                          // Type conversion
                @"CAST\s*\("                              // Type casting
            };

            return patterns.Any(pattern => Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase));
        }
    }

    /// <summary>
    /// Result of a vulnerability test
    /// </summary>
    public class VulnerabilityTestResult
    {
        public string TestType { get; set; } = string.Empty;
        public string Input { get; set; } = string.Empty;
        public string PasswordInput { get; set; } = string.Empty;
        public string QueryExecuted { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Error { get; set; }
        public int RowsReturned { get; set; }
        public long ExecutionTime { get; set; }
    }

    /// <summary>
    /// Comparison between vulnerable and secure implementations
    /// </summary>
    public class ComparisonResult
    {
        public string Input { get; set; } = string.Empty;
        public string PasswordInput { get; set; } = string.Empty;
        public VulnerabilityTestResult VulnerableResult { get; set; } = new();
        public VulnerabilityTestResult SecureResult { get; set; } = new();
        public bool IsPotentialInjection { get; set; }
    }
}