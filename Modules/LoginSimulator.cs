using Microsoft.Data.SqlClient;
using System.Diagnostics;

namespace SQLInjectionSimulator.Modules
{
    /// <summary>
    /// Simulates various login attempts including normal user behavior and potential attacks
    /// Educational tool for demonstrating different attack patterns
    /// </summary>
    public class LoginSimulator
    {
        private readonly string _connectionString;
        private readonly Random _random;
        private readonly UserManager _userManager;

        // Common injection payloads for educational purposes
        private readonly List<string> _injectionPayloads = new()
        {
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' OR 'x'='x",
            "'; DROP TABLE Users; --",
            "' UNION SELECT NULL, username, password FROM Users--",
            "' AND (SELECT COUNT(*) FROM Users) > 0--",
            "admin' OR '1'='1'/*",
            "' OR 1=1#",
            "' WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT SUBSTRING(@@version,1,1)) = '5",
            "'; INSERT INTO Users VALUES ('hacker', 'hacked')--",
            "' OR EXISTS(SELECT * FROM Users WHERE username='admin')--",
            "test'; UPDATE Users SET password='hacked' WHERE username='admin'--",
            "' UNION ALL SELECT username, password, 1 FROM Users--"
        };

        private readonly List<string> _userAgents = new()
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "sqlmap/1.5.2",
            "Burp Suite Professional",
            "PostmanRuntime/7.28.0",
            "Custom Security Tool",
            "Automated Scanner",
            "Manual Testing"
        };

        public LoginSimulator(string connectionString, UserManager userManager)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _random = new Random();
        }

        /// <summary>
        /// Generate realistic normal login attempts
        /// </summary>
        public async Task<List<LoginAttempt>> GenerateNormalAttemptsAsync(int count)
        {
            var attempts = new List<LoginAttempt>();
            var users = await _userManager.GetAllUsersAsync();
            var validUsernames = users.Where(u => u.IsActive).Select(u => u.Username).ToList();

            for (int i = 0; i < count; i++)
            {
                var attempt = GenerateNormalAttempt(validUsernames);
                attempts.Add(attempt);
                
                // Add some realistic timing between attempts
                await Task.Delay(_random.Next(100, 2000));
            }

            return attempts;
        }

        /// <summary>
        /// Generate SQL injection attack attempts for educational demonstration
        /// </summary>
        public async Task<List<LoginAttempt>> GenerateInjectionAttemptsAsync(int count)
        {
            var attempts = new List<LoginAttempt>();

            for (int i = 0; i < count; i++)
            {
                var attempt = GenerateInjectionAttempt();
                attempts.Add(attempt);
                
                // Malicious attempts often come in rapid succession
                await Task.Delay(_random.Next(50, 500));
            }

            return attempts;
        }

        /// <summary>
        /// Simulate brute force attack pattern
        /// </summary>
        public async Task<List<LoginAttempt>> GenerateBruteForceAttemptsAsync(string targetUsername, int count)
        {
            var attempts = new List<LoginAttempt>();
            var commonPasswords = new[] 
            { 
                "password", "123456", "admin", "password123", "letmein", 
                "welcome", "monkey", "1234567890", "qwerty", "abc123" 
            };

            for (int i = 0; i < count; i++)
            {
                var attempt = new LoginAttempt
                {
                    Username = targetUsername,
                    InputPayload = targetUsername,
                    PasswordInput = commonPasswords[_random.Next(commonPasswords.Length)],
                    AttemptTime = DateTime.Now,
                    IpAddress = GenerateRandomIP(),
                    UserAgent = _userAgents[_random.Next(_userAgents.Count)],
                    IsInjection = false
                };

                attempts.Add(attempt);
                
                // Brute force attempts are typically rapid
                await Task.Delay(_random.Next(10, 100));
            }

            return attempts;
        }

        /// <summary>
        /// Execute login attempt and log results
        /// </summary>
        public async Task<LoginResult> ExecuteLoginAttemptAsync(LoginAttempt attempt, bool useVulnerableMethod = false)
        {
            var stopwatch = Stopwatch.StartNew();
            
            try
            {
                bool success;
                string message;
                string queryExecuted = "";

                if (useVulnerableMethod)
                {
                    // Use vulnerable method for demonstration
                    var result = await _userManager.AuthenticateUserVulnerableAsync(attempt.Username, attempt.PasswordInput);
                    success = result.success;
                    message = result.message;
                    queryExecuted = result.executedQuery;
                }
                else
                {
                    // Use secure method
                    var result = await _userManager.AuthenticateUserSecureAsync(attempt.Username, attempt.PasswordInput);
                    success = result.success;
                    message = result.message;
                    queryExecuted = "SELECT UserId, PasswordHash, IsActive, FailedLoginCount FROM Users WHERE Username = @username";
                }

                stopwatch.Stop();

                // Update attempt with results
                attempt.IsSuccessful = success;
                attempt.ResponseTime = (int)stopwatch.ElapsedMilliseconds;
                attempt.QueryExecuted = queryExecuted;

                // Log the attempt
                await LogAttemptAsync(attempt);

                return new LoginResult
                {
                    Success = success,
                    Message = message,
                    ResponseTime = stopwatch.ElapsedMilliseconds,
                    QueryExecuted = queryExecuted
                };
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                
                attempt.IsSuccessful = false;
                attempt.ResponseTime = (int)stopwatch.ElapsedMilliseconds;
                await LogAttemptAsync(attempt);

                return new LoginResult
                {
                    Success = false,
                    Message = $"Error: {ex.Message}",
                    ResponseTime = stopwatch.ElapsedMilliseconds,
                    QueryExecuted = attempt.QueryExecuted ?? ""
                };
            }
        }

        /// <summary>
        /// Log login attempt to database
        /// </summary>
        private async Task LogAttemptAsync(LoginAttempt attempt)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            string query = @"INSERT INTO LoginAttempts 
                           (Username, InputPayload, PasswordInput, AttemptTime, IsSuccessful, 
                            IsInjection, IpAddress, UserAgent, ResponseTime, QueryExecuted)
                           VALUES 
                           (@username, @inputPayload, @passwordInput, @attemptTime, @isSuccessful,
                            @isInjection, @ipAddress, @userAgent, @responseTime, @queryExecuted)";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@username", attempt.Username ?? "");
            command.Parameters.AddWithValue("@inputPayload", attempt.InputPayload ?? "");
            command.Parameters.AddWithValue("@passwordInput", attempt.PasswordInput ?? "");
            command.Parameters.AddWithValue("@attemptTime", attempt.AttemptTime);
            command.Parameters.AddWithValue("@isSuccessful", attempt.IsSuccessful);
            command.Parameters.AddWithValue("@isInjection", attempt.IsInjection);
            command.Parameters.AddWithValue("@ipAddress", attempt.IpAddress ?? "127.0.0.1");
            command.Parameters.AddWithValue("@userAgent", attempt.UserAgent ?? "Unknown");
            command.Parameters.AddWithValue("@responseTime", attempt.ResponseTime);
            command.Parameters.AddWithValue("@queryExecuted", attempt.QueryExecuted ?? "");

            await command.ExecuteNonQueryAsync();
        }

        private LoginAttempt GenerateNormalAttempt(List<string> validUsernames)
        {
            string username;
            string password;
            bool willSucceed = _random.NextDouble() > 0.6; // 40% success rate for realism

            if (willSucceed && validUsernames.Any())
            {
                username = validUsernames[_random.Next(validUsernames.Count)];
                password = "correct_password"; // This would be verified against the hash
            }
            else if (validUsernames.Any())
            {
                username = validUsernames[_random.Next(validUsernames.Count)];
                password = GenerateRandomPassword();
            }
            else
            {
                username = GenerateRandomUsername();
                password = GenerateRandomPassword();
            }

            return new LoginAttempt
            {
                Username = username,
                InputPayload = username,
                PasswordInput = password,
                AttemptTime = DateTime.Now,
                IpAddress = GenerateNormalIP(),
                UserAgent = _userAgents[_random.Next(3)], // Use normal browsers
                IsInjection = false
            };
        }

        private LoginAttempt GenerateInjectionAttempt()
        {
            var payload = _injectionPayloads[_random.Next(_injectionPayloads.Count)];
            bool inUsername = _random.NextDouble() > 0.5;

            return new LoginAttempt
            {
                Username = inUsername ? payload : "admin",
                InputPayload = inUsername ? payload : "admin",
                PasswordInput = inUsername ? "password" : payload,
                AttemptTime = DateTime.Now,
                IpAddress = GenerateSuspiciousIP(),
                UserAgent = _userAgents[_random.Next(3, _userAgents.Count)], // Use suspicious tools
                IsInjection = true
            };
        }

        private string GenerateRandomUsername()
        {
            var names = new[] { "user", "test", "admin", "guest", "demo", "temp", "john", "jane" };
            var numbers = _random.Next(1, 1000);
            return $"{names[_random.Next(names.Length)]}{numbers}";
        }

        private string GenerateRandomPassword()
        {
            var passwords = new[] 
            { 
                "password", "123456", "qwerty", "letmein", "welcome",
                "admin", "test123", "password123", "user123", "temp456"
            };
            return passwords[_random.Next(passwords.Length)];
        }

        private string GenerateNormalIP()
        {
            // Generate realistic internal network IPs
            return $"192.168.{_random.Next(1, 255)}.{_random.Next(1, 255)}";
        }

        private string GenerateSuspiciousIP()
        {
            // Generate IPs that might be associated with attacks
            var ranges = new[]
            {
                $"10.0.{_random.Next(1, 255)}.{_random.Next(1, 255)}",
                $"172.16.{_random.Next(1, 255)}.{_random.Next(1, 255)}",
                $"{_random.Next(1, 223)}.{_random.Next(1, 255)}.{_random.Next(1, 255)}.{_random.Next(1, 255)}"
            };
            return ranges[_random.Next(ranges.Length)];
        }

        private string GenerateRandomIP()
        {
            return _random.NextDouble() > 0.7 ? GenerateSuspiciousIP() : GenerateNormalIP();
        }
    }

    /// <summary>
    /// Represents a login attempt
    /// </summary>
    public class LoginAttempt
    {
        public string Username { get; set; } = string.Empty;
        public string InputPayload { get; set; } = string.Empty;
        public string PasswordInput { get; set; } = string.Empty;
        public DateTime AttemptTime { get; set; }
        public bool IsSuccessful { get; set; }
        public bool IsInjection { get; set; }
        public string IpAddress { get; set; } = "127.0.0.1";
        public string UserAgent { get; set; } = "Unknown";
        public int ResponseTime { get; set; }
        public string QueryExecuted { get; set; } = string.Empty;
    }

    /// <summary>
    /// Result of a login attempt execution
    /// </summary>
    public class LoginResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public long ResponseTime { get; set; }
        public string QueryExecuted { get; set; } = string.Empty;
    }
}