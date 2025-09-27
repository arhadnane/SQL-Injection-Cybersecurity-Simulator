using Microsoft.Data.SqlClient;
using System.Text.RegularExpressions;

namespace SQLInjectionSimulator.Modules
{
    /// <summary>
    /// Advanced security monitoring and attack detection system
    /// Provides real-time analysis of login attempts and automated threat response
    /// </summary>
    public class DefenseEngine
    {
        private readonly string _connectionString;
        private readonly Dictionary<string, List<DateTime>> _ipAttemptHistory;
        private readonly Dictionary<string, List<DateTime>> _userAttemptHistory;
        private readonly object _lockObject;

        // Configuration parameters
        private readonly int _maxAttemptsPerIP = 10;
        private readonly int _maxAttemptsPerUser = 5;
        private readonly TimeSpan _timeWindow = TimeSpan.FromMinutes(5);
        private readonly List<string> _blockedIPs;

        // SQL injection detection patterns
        private readonly Dictionary<string, string> _injectionPatterns = new()
        {
            { @"'\s*(OR|AND)\s*'?[\w\d]*'?\s*=\s*'?[\w\d]*'?", "Boolean-based injection" },
            { @"'\s*OR\s+\d+\s*=\s*\d+", "Classic OR injection" },
            { @"--\s*$", "SQL comment injection" },
            { @"/\*.*?\*/", "Block comment injection" },
            { @";\s*(DROP|DELETE|INSERT|UPDATE)", "Destructive command injection" },
            { @"UNION\s+SELECT", "Union-based injection" },
            { @"WAITFOR\s+DELAY", "Time-based blind injection" },
            { @"@@\w+", "System variable access" },
            { @"(xp_|sp_)\w+", "System procedure call" },
            { @"'\s*;", "Statement terminator" },
            { @"EXEC\s*\(", "Command execution" },
            { @"CONVERT\s*\(.*,.*\)", "Type conversion exploit" },
            { @"CAST\s*\(.*AS.*\)", "Type casting exploit" },
            { @"SUBSTRING\s*\(", "Data extraction function" },
            { @"(SELECT|INSERT|UPDATE|DELETE).*FROM", "Direct SQL command" },
            { @"INFORMATION_SCHEMA", "Schema information access" },
            { @"SYSOBJECTS|SYSCOLUMNS", "System table access" },
            { @"'\s*\+\s*'", "String concatenation" },
            { @"CHAR\s*\(\d+\)", "Character encoding bypass" },
            { @"LOAD_FILE\s*\(", "File system access" }
        };

        public DefenseEngine(string connectionString)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _ipAttemptHistory = new Dictionary<string, List<DateTime>>();
            _userAttemptHistory = new Dictionary<string, List<DateTime>>();
            _blockedIPs = new List<string>();
            _lockObject = new object();
        }

        /// <summary>
        /// Analyze input for SQL injection patterns
        /// </summary>
        public InjectionAnalysisResult AnalyzeForSQLInjection(string input)
        {
            var result = new InjectionAnalysisResult
            {
                Input = input,
                IsInjection = false,
                DetectedPatterns = new List<DetectedPattern>(),
                RiskLevel = RiskLevel.Low
            };

            if (string.IsNullOrEmpty(input))
                return result;

            // Check each pattern
            foreach (var pattern in _injectionPatterns)
            {
                var matches = Regex.Matches(input, pattern.Key, RegexOptions.IgnoreCase | RegexOptions.Multiline);
                if (matches.Count > 0)
                {
                    result.IsInjection = true;
                    result.DetectedPatterns.Add(new DetectedPattern
                    {
                        PatternType = pattern.Value,
                        MatchedText = matches[0].Value,
                        Position = matches[0].Index
                    });
                }
            }

            // Determine risk level based on detected patterns
            if (result.DetectedPatterns.Any())
            {
                result.RiskLevel = DetermineRiskLevel(result.DetectedPatterns);
            }

            // Additional heuristic checks
            result.SuspicionScore = CalculateSuspicionScore(input);

            return result;
        }

        /// <summary>
        /// Monitor login attempt patterns for brute force attacks
        /// </summary>
        public BruteForceAnalysisResult AnalyzeBruteForcePatterns(string ipAddress, string username)
        {
            lock (_lockObject)
            {
                var now = DateTime.Now;
                var result = new BruteForceAnalysisResult
                {
                    IpAddress = ipAddress,
                    Username = username,
                    Timestamp = now
                };

                // Clean old attempts outside time window
                CleanOldAttempts(now);

                // Track IP-based attempts
                if (!_ipAttemptHistory.ContainsKey(ipAddress))
                    _ipAttemptHistory[ipAddress] = new List<DateTime>();
                
                _ipAttemptHistory[ipAddress].Add(now);
                result.RecentAttemptsFromIP = _ipAttemptHistory[ipAddress].Count;

                // Track user-based attempts
                if (!_userAttemptHistory.ContainsKey(username))
                    _userAttemptHistory[username] = new List<DateTime>();
                
                _userAttemptHistory[username].Add(now);
                result.RecentAttemptsForUser = _userAttemptHistory[username].Count;

                // Determine if this looks like brute force
                result.IsBruteForce = result.RecentAttemptsFromIP >= _maxAttemptsPerIP ||
                                    result.RecentAttemptsForUser >= _maxAttemptsPerUser;

                result.ShouldBlockIP = result.RecentAttemptsFromIP >= _maxAttemptsPerIP;

                // Auto-block if threshold exceeded
                if (result.ShouldBlockIP && !_blockedIPs.Contains(ipAddress))
                {
                    _blockedIPs.Add(ipAddress);
                    result.IPBlocked = true;
                }

                return result;
            }
        }

        /// <summary>
        /// Process a login attempt through the defense system
        /// </summary>
        public async Task<DefenseAnalysisResult> AnalyzeLoginAttemptAsync(string username, string password, string ipAddress, string userAgent)
        {
            var result = new DefenseAnalysisResult
            {
                Username = username,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                Timestamp = DateTime.Now
            };

            // Check if IP is already blocked
            if (_blockedIPs.Contains(ipAddress))
            {
                result.ShouldBlock = true;
                result.BlockReason = "IP address is blocked due to previous suspicious activity";
                await LogSecurityEventAsync("IP_BLOCKED", "MEDIUM", 
                    $"Blocked attempt from previously flagged IP: {ipAddress}", username);
                return result;
            }

            // Analyze username for injection
            var usernameAnalysis = AnalyzeForSQLInjection(username);
            result.UsernameAnalysis = usernameAnalysis;

            // Analyze password for injection
            var passwordAnalysis = AnalyzeForSQLInjection(password);
            result.PasswordAnalysis = passwordAnalysis;

            // Check for brute force patterns
            var bruteForceAnalysis = AnalyzeBruteForcePatterns(ipAddress, username);
            result.BruteForceAnalysis = bruteForceAnalysis;

            // Analyze user agent for suspicious patterns
            result.SuspiciousUserAgent = IsSuspiciousUserAgent(userAgent);

            // Overall threat assessment
            result.ThreatLevel = DetermineThreatLevel(result);

            // Generate alerts if necessary
            await GenerateAlertsAsync(result);

            return result;
        }

        /// <summary>
        /// Generate security alerts based on analysis results
        /// </summary>
        private async Task GenerateAlertsAsync(DefenseAnalysisResult analysisResult)
        {
            var alerts = new List<(string type, string severity, string details)>();

            // SQL Injection alerts
            if (analysisResult.UsernameAnalysis.IsInjection)
            {
                var severity = analysisResult.UsernameAnalysis.RiskLevel switch
                {
                    RiskLevel.Critical => "CRITICAL",
                    RiskLevel.High => "HIGH",
                    RiskLevel.Medium => "MEDIUM",
                    _ => "LOW"
                };

                alerts.Add(("SQL_INJECTION_USERNAME", severity, 
                    $"SQL injection detected in username field. Patterns: {string.Join(", ", analysisResult.UsernameAnalysis.DetectedPatterns.Select(p => p.PatternType))}"));
            }

            if (analysisResult.PasswordAnalysis.IsInjection)
            {
                var severity = analysisResult.PasswordAnalysis.RiskLevel switch
                {
                    RiskLevel.Critical => "CRITICAL",
                    RiskLevel.High => "HIGH",
                    RiskLevel.Medium => "MEDIUM",
                    _ => "LOW"
                };

                alerts.Add(("SQL_INJECTION_PASSWORD", severity,
                    $"SQL injection detected in password field. Patterns: {string.Join(", ", analysisResult.PasswordAnalysis.DetectedPatterns.Select(p => p.PatternType))}"));
            }

            // Brute force alerts
            if (analysisResult.BruteForceAnalysis.IsBruteForce)
            {
                alerts.Add(("BRUTE_FORCE_ATTACK", "HIGH",
                    $"Brute force pattern detected. IP attempts: {analysisResult.BruteForceAnalysis.RecentAttemptsFromIP}, User attempts: {analysisResult.BruteForceAnalysis.RecentAttemptsForUser}"));
            }

            // Suspicious user agent
            if (analysisResult.SuspiciousUserAgent)
            {
                alerts.Add(("SUSPICIOUS_USER_AGENT", "MEDIUM",
                    $"Suspicious user agent detected: {analysisResult.UserAgent}"));
            }

            // High threat level
            if (analysisResult.ThreatLevel >= ThreatLevel.High)
            {
                alerts.Add(("HIGH_THREAT_ACTIVITY", "HIGH",
                    $"High threat level activity detected from {analysisResult.IpAddress}"));
            }

            // Log all alerts
            foreach (var (type, severity, details) in alerts)
            {
                await LogSecurityEventAsync(type, severity, details, analysisResult.Username);
            }
        }

        /// <summary>
        /// Log security events to the database
        /// </summary>
        public async Task LogSecurityEventAsync(string alertType, string severity, string details, string username = "")
        {
            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                string query = @"INSERT INTO Alerts (Username, AlertType, Severity, Details, TriggerCondition, AlertTime)
                               VALUES (@username, @alertType, @severity, @details, @triggerCondition, @alertTime)";

                using var command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@username", username);
                command.Parameters.AddWithValue("@alertType", alertType);
                command.Parameters.AddWithValue("@severity", severity);
                command.Parameters.AddWithValue("@details", details);
                command.Parameters.AddWithValue("@triggerCondition", "DefenseEngine automated detection");
                command.Parameters.AddWithValue("@alertTime", DateTime.Now);

                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error logging security event: {ex.Message}");
            }
        }

        /// <summary>
        /// Get security statistics and metrics
        /// </summary>
        public async Task<SecurityMetrics> GetSecurityMetricsAsync(TimeSpan? period = null)
        {
            var actualPeriod = period ?? TimeSpan.FromHours(24);
            var cutoffTime = DateTime.Now.Subtract(actualPeriod);

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            var metrics = new SecurityMetrics();

            // Get login attempt statistics
            string attemptQuery = @"SELECT 
                                  COUNT(*) as TotalAttempts,
                                  SUM(CAST(IsSuccessful as INT)) as SuccessfulAttempts,
                                  SUM(CAST(IsInjection as INT)) as InjectionAttempts,
                                  COUNT(DISTINCT IpAddress) as UniqueIPs,
                                  COUNT(DISTINCT Username) as UniqueUsers
                                FROM LoginAttempts 
                                WHERE AttemptTime >= @cutoffTime";

            using var attemptCommand = new SqlCommand(attemptQuery, connection);
            attemptCommand.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var attemptReader = await attemptCommand.ExecuteReaderAsync();

            if (attemptReader.Read())
            {
                metrics.TotalAttempts = attemptReader.GetInt32("TotalAttempts");
                metrics.SuccessfulAttempts = attemptReader.GetInt32("SuccessfulAttempts");
                metrics.InjectionAttempts = attemptReader.GetInt32("InjectionAttempts");
                metrics.UniqueIPs = attemptReader.GetInt32("UniqueIPs");
                metrics.UniqueUsers = attemptReader.GetInt32("UniqueUsers");
            }
            attemptReader.Close();

            // Get alert statistics
            string alertQuery = @"SELECT 
                                COUNT(*) as TotalAlerts,
                                COUNT(CASE WHEN Severity = 'CRITICAL' THEN 1 END) as CriticalAlerts,
                                COUNT(CASE WHEN Severity = 'HIGH' THEN 1 END) as HighAlerts,
                                COUNT(CASE WHEN Severity = 'MEDIUM' THEN 1 END) as MediumAlerts,
                                COUNT(CASE WHEN Severity = 'LOW' THEN 1 END) as LowAlerts
                              FROM Alerts 
                              WHERE AlertTime >= @cutoffTime";

            using var alertCommand = new SqlCommand(alertQuery, connection);
            alertCommand.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var alertReader = await alertCommand.ExecuteReaderAsync();

            if (alertReader.Read())
            {
                metrics.TotalAlerts = alertReader.GetInt32("TotalAlerts");
                metrics.CriticalAlerts = alertReader.GetInt32("CriticalAlerts");
                metrics.HighAlerts = alertReader.GetInt32("HighAlerts");
                metrics.MediumAlerts = alertReader.GetInt32("MediumAlerts");
                metrics.LowAlerts = alertReader.GetInt32("LowAlerts");
            }

            // Calculate derived metrics
            metrics.AttackDetectionRate = metrics.TotalAttempts > 0 ? 
                (metrics.InjectionAttempts * 100.0 / metrics.TotalAttempts) : 0;
            metrics.SuccessRate = metrics.TotalAttempts > 0 ? 
                (metrics.SuccessfulAttempts * 100.0 / metrics.TotalAttempts) : 0;
            metrics.BlockedIPs = _blockedIPs.Count;

            return metrics;
        }

        private RiskLevel DetermineRiskLevel(List<DetectedPattern> patterns)
        {
            if (patterns.Any(p => p.PatternType.Contains("Destructive") || p.PatternType.Contains("DROP") || p.PatternType.Contains("DELETE")))
                return RiskLevel.Critical;
            
            if (patterns.Any(p => p.PatternType.Contains("Union") || p.PatternType.Contains("System") || p.PatternType.Contains("EXEC")))
                return RiskLevel.High;
            
            if (patterns.Count >= 2)
                return RiskLevel.High;
            
            return patterns.Count > 0 ? RiskLevel.Medium : RiskLevel.Low;
        }

        private ThreatLevel DetermineThreatLevel(DefenseAnalysisResult result)
        {
            int score = 0;

            if (result.UsernameAnalysis.IsInjection) score += (int)result.UsernameAnalysis.RiskLevel;
            if (result.PasswordAnalysis.IsInjection) score += (int)result.PasswordAnalysis.RiskLevel;
            if (result.BruteForceAnalysis.IsBruteForce) score += 3;
            if (result.SuspiciousUserAgent) score += 1;

            return score switch
            {
                >= 6 => ThreatLevel.Critical,
                >= 4 => ThreatLevel.High,
                >= 2 => ThreatLevel.Medium,
                >= 1 => ThreatLevel.Low,
                _ => ThreatLevel.None
            };
        }

        private double CalculateSuspicionScore(string input)
        {
            double score = 0;

            // Length-based scoring
            if (input.Length > 100) score += 1;
            if (input.Length > 200) score += 2;

            // Character-based scoring
            if (input.Contains('\'')) score += 1;
            if (input.Contains('"')) score += 1;
            if (input.Contains(';')) score += 2;
            if (input.Contains('-')) score += 0.5;
            if (input.Contains('*')) score += 0.5;

            // Keyword density
            var sqlKeywords = new[] { "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND" };
            var keywordCount = sqlKeywords.Count(keyword => input.ToUpper().Contains(keyword));
            score += keywordCount * 1.5;

            return Math.Min(score, 10); // Cap at 10
        }

        private bool IsSuspiciousUserAgent(string userAgent)
        {
            if (string.IsNullOrEmpty(userAgent))
                return true;

            var suspiciousAgents = new[]
            {
                "sqlmap", "havij", "nmap", "nikto", "burp", "zap", "wget", "curl",
                "python", "perl", "php", "scanner", "bot", "crawler", "exploit"
            };

            return suspiciousAgents.Any(agent => userAgent.ToLower().Contains(agent));
        }

        private void CleanOldAttempts(DateTime now)
        {
            var cutoffTime = now.Subtract(_timeWindow);

            // Clean IP history
            foreach (var ip in _ipAttemptHistory.Keys.ToList())
            {
                _ipAttemptHistory[ip] = _ipAttemptHistory[ip]
                    .Where(time => time > cutoffTime)
                    .ToList();

                if (!_ipAttemptHistory[ip].Any())
                    _ipAttemptHistory.Remove(ip);
            }

            // Clean user history
            foreach (var user in _userAttemptHistory.Keys.ToList())
            {
                _userAttemptHistory[user] = _userAttemptHistory[user]
                    .Where(time => time > cutoffTime)
                    .ToList();

                if (!_userAttemptHistory[user].Any())
                    _userAttemptHistory.Remove(user);
            }
        }
    }

    // Data structures for analysis results
    public class InjectionAnalysisResult
    {
        public string Input { get; set; } = string.Empty;
        public bool IsInjection { get; set; }
        public List<DetectedPattern> DetectedPatterns { get; set; } = new();
        public RiskLevel RiskLevel { get; set; }
        public double SuspicionScore { get; set; }
    }

    public class DetectedPattern
    {
        public string PatternType { get; set; } = string.Empty;
        public string MatchedText { get; set; } = string.Empty;
        public int Position { get; set; }
    }

    public class BruteForceAnalysisResult
    {
        public string IpAddress { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public int RecentAttemptsFromIP { get; set; }
        public int RecentAttemptsForUser { get; set; }
        public bool IsBruteForce { get; set; }
        public bool ShouldBlockIP { get; set; }
        public bool IPBlocked { get; set; }
    }

    public class DefenseAnalysisResult
    {
        public string Username { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public InjectionAnalysisResult UsernameAnalysis { get; set; } = new();
        public InjectionAnalysisResult PasswordAnalysis { get; set; } = new();
        public BruteForceAnalysisResult BruteForceAnalysis { get; set; } = new();
        public bool SuspiciousUserAgent { get; set; }
        public ThreatLevel ThreatLevel { get; set; }
        public bool ShouldBlock { get; set; }
        public string BlockReason { get; set; } = string.Empty;
    }

    public class SecurityMetrics
    {
        public int TotalAttempts { get; set; }
        public int SuccessfulAttempts { get; set; }
        public int InjectionAttempts { get; set; }
        public int UniqueIPs { get; set; }
        public int UniqueUsers { get; set; }
        public int TotalAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }
        public int MediumAlerts { get; set; }
        public int LowAlerts { get; set; }
        public double AttackDetectionRate { get; set; }
        public double SuccessRate { get; set; }
        public int BlockedIPs { get; set; }
    }

    public enum RiskLevel
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    public enum ThreatLevel
    {
        None = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}