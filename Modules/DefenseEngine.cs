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
        private readonly Dictionary<string, DateTime> _blockedIPs;

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
            _blockedIPs = new Dictionary<string, DateTime>();
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
                if (result.ShouldBlockIP && !_blockedIPs.ContainsKey(ipAddress))
                {
                    _blockedIPs[ipAddress] = DateTime.Now.AddMinutes(30); // Block for 30 minutes
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
            if (_blockedIPs.ContainsKey(ipAddress) && _blockedIPs[ipAddress] > DateTime.Now)
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
                metrics.TotalAttempts = attemptReader.GetInt32(0);
                metrics.SuccessfulAttempts = attemptReader.GetInt32(1);
                metrics.InjectionAttempts = attemptReader.GetInt32(2);
                metrics.UniqueIPs = attemptReader.GetInt32(3);
                metrics.UniqueUsers = attemptReader.GetInt32(4);
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
                metrics.TotalAlerts = alertReader.GetInt32(0);
                metrics.CriticalAlerts = alertReader.GetInt32(1);
                metrics.HighAlerts = alertReader.GetInt32(2);
                metrics.MediumAlerts = alertReader.GetInt32(3);
                metrics.LowAlerts = alertReader.GetInt32(4);
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

        /// <summary>
        /// Advanced SQL injection pattern detection and analysis
        /// </summary>
        public async Task<SqlInjectionScanResult> ScanForSqlInjectionAsync(string input)
        {
            var result = new SqlInjectionScanResult
            {
                Input = input,
                ScanTime = DateTime.Now
            };

            if (string.IsNullOrWhiteSpace(input))
            {
                result.RiskLevel = "LOW";
                result.Message = "Empty input - no risk detected";
                return result;
            }

            var detectedPatterns = new List<string>();
            var riskScore = 0;

            // Pattern 1: Classic OR injection
            if (Regex.IsMatch(input, @"'\s*(OR|AND)\s*'?\w*'?\s*=\s*'?\w*'?", RegexOptions.IgnoreCase))
            {
                detectedPatterns.Add("Classic OR/AND injection pattern");
                riskScore += 5;
            }

            // Pattern 2: Union-based injection
            if (Regex.IsMatch(input, @"UNION\s+SELECT", RegexOptions.IgnoreCase))
            {
                detectedPatterns.Add("Union-based SQL injection");
                riskScore += 5;
            }

            // Pattern 3: Comment injection
            if (input.Contains("--") || input.Contains("/*"))
            {
                detectedPatterns.Add("SQL comment injection");
                riskScore += 3;
            }

            // Pattern 4: Stacked queries
            if (Regex.IsMatch(input, @";\s*(DROP|DELETE|INSERT|UPDATE)", RegexOptions.IgnoreCase))
            {
                detectedPatterns.Add("Dangerous stacked queries");
                riskScore += 8;
            }

            // Pattern 5: Time-based blind injection
            if (Regex.IsMatch(input, @"WAITFOR\s+DELAY", RegexOptions.IgnoreCase))
            {
                detectedPatterns.Add("Time-based blind injection");
                riskScore += 6;
            }

            // Pattern 6: Error-based injection
            if (Regex.IsMatch(input, @"CONVERT\s*\(|CAST\s*\(", RegexOptions.IgnoreCase))
            {
                detectedPatterns.Add("Error-based injection attempt");
                riskScore += 4;
            }

            // Pattern 7: System function calls
            if (Regex.IsMatch(input, @"@@\w+|xp_\w+|sp_\w+", RegexOptions.IgnoreCase))
            {
                detectedPatterns.Add("System function exploitation");
                riskScore += 7;
            }

            result.DetectedPatterns = detectedPatterns;
            result.RiskScore = riskScore;
            result.RiskLevel = riskScore switch
            {
                0 => "LOW",
                >= 1 and <= 3 => "MEDIUM",
                >= 4 and <= 7 => "HIGH",
                _ => "CRITICAL"
            };
            result.IsInjection = riskScore > 0;
            result.Message = $"Detected {detectedPatterns.Count} injection patterns with risk score {riskScore}";

            // Log the scan result
            if (result.IsInjection)
            {
                await LogSecurityEventAsync("SQL_INJECTION_SCAN", result.RiskLevel, 
                    $"SQL injection patterns detected: {string.Join(", ", detectedPatterns)}", 
                    $"ScanForSqlInjection - Score: {riskScore}");
            }

            return result;
        }

        /// <summary>
        /// Detect and analyze brute force attack patterns
        /// </summary>
        public async Task<BruteForceAnalysisResult> DetectBruteForcePatternAsync(string username, string ipAddress)
        {
            var result = new BruteForceAnalysisResult
            {
                Username = username,
                IpAddress = ipAddress,
                AnalysisTime = DateTime.Now
            };

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Check recent attempts from this IP
            var ipQuery = @"SELECT COUNT(*) as AttemptCount, 
                           MIN(AttemptTime) as FirstAttempt,
                           MAX(AttemptTime) as LastAttempt
                           FROM LoginAttempts 
                           WHERE IpAddress = @ip AND AttemptTime >= @cutoff";

            var cutoffTime = DateTime.Now.AddMinutes(-15); // 15-minute window
            
            using var command = new SqlCommand(ipQuery, connection);
            command.Parameters.AddWithValue("@ip", ipAddress);
            command.Parameters.AddWithValue("@cutoff", cutoffTime);

            using var reader = await command.ExecuteReaderAsync();
            
            if (reader.Read())
            {
                result.AttemptsInTimeWindow = reader.GetInt32(0); // AttemptCount
                
                if (result.AttemptsInTimeWindow > 0)
                {
                    var firstAttempt = reader.GetDateTime(1); // FirstAttempt
                    var lastAttempt = reader.GetDateTime(2); // LastAttempt
                    var timeSpan = lastAttempt - firstAttempt;
                    
                    result.AttemptsPerMinute = result.AttemptsInTimeWindow / Math.Max(timeSpan.TotalMinutes, 1);
                }
            }
            reader.Close();

            // Check for rapid sequential attempts against same user
            var userQuery = @"SELECT COUNT(*) as UserAttempts
                             FROM LoginAttempts 
                             WHERE Username = @username AND AttemptTime >= @cutoff";

            using var userCommand = new SqlCommand(userQuery, connection);
            userCommand.Parameters.AddWithValue("@username", username);
            userCommand.Parameters.AddWithValue("@cutoff", cutoffTime);

            var userAttempts = (int)(await userCommand.ExecuteScalarAsync() ?? 0);

            // Analyze patterns
            result.IsBruteForce = result.AttemptsInTimeWindow >= 10 || result.AttemptsPerMinute >= 2 || userAttempts >= 5;
            
            result.Severity = (result.AttemptsInTimeWindow, result.AttemptsPerMinute) switch
            {
                (>= 50, _) or (_, >= 10) => "CRITICAL",
                (>= 20, _) or (_, >= 5) => "HIGH", 
                (>= 10, _) or (_, >= 2) => "MEDIUM",
                _ => "LOW"
            };

            result.RecommendedAction = result.Severity switch
            {
                "CRITICAL" => "IMMEDIATE_BLOCK",
                "HIGH" => "TEMPORARY_BLOCK",
                "MEDIUM" => "RATE_LIMIT",
                _ => "MONITOR"
            };

            result.Message = $"IP: {result.AttemptsInTimeWindow} attempts, Rate: {result.AttemptsPerMinute:F1}/min, User: {userAttempts} attempts";

            // Log if brute force detected
            if (result.IsBruteForce)
            {
                await LogSecurityEventAsync("BRUTE_FORCE_DETECTION", result.Severity, 
                    $"Brute force attack detected: {result.Message}", username);
            }

            return result;
        }

        /// <summary>
        /// Analyze login patterns for anomaly detection
        /// </summary>
        public async Task<LoginPatternAnalysisResult> AnalyzeLoginPatternsAsync(string username, TimeSpan? period = null)
        {
            var analysisResult = new LoginPatternAnalysisResult
            {
                Username = username,
                AnalysisTime = DateTime.Now
            };

            var cutoffTime = DateTime.Now.Subtract(period ?? TimeSpan.FromDays(7));

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Get pattern statistics
            var query = @"SELECT 
                         COUNT(*) as TotalAttempts,
                         COUNT(CASE WHEN IsSuccessful = 1 THEN 1 END) as SuccessfulAttempts,
                         COUNT(CASE WHEN IsInjection = 1 THEN 1 END) as InjectionAttempts,
                         COUNT(DISTINCT IpAddress) as UniqueIPs,
                         COUNT(DISTINCT UserAgent) as UniqueUserAgents,
                         AVG(CAST(ResponseTime as FLOAT)) as AvgResponseTime,
                         MIN(AttemptTime) as FirstAttempt,
                         MAX(AttemptTime) as LastAttempt
                         FROM LoginAttempts 
                         WHERE Username = @username AND AttemptTime >= @cutoff";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@username", username);
            command.Parameters.AddWithValue("@cutoff", cutoffTime);

            using var reader = await command.ExecuteReaderAsync();
            
            if (reader.Read() && !reader.IsDBNull(0)) // TotalAttempts
            {
                analysisResult.TotalAttempts = reader.GetInt32(0); // TotalAttempts
                analysisResult.SuccessfulAttempts = reader.GetInt32(1); // SuccessfulAttempts
                analysisResult.InjectionAttempts = reader.GetInt32(2); // InjectionAttempts
                analysisResult.UniqueIPs = reader.GetInt32(3); // UniqueIPs
                analysisResult.UniqueUserAgents = reader.GetInt32(4); // UniqueUserAgents
                analysisResult.AverageResponseTime = reader.IsDBNull(5) ? 0 : reader.GetDouble(5); // AvgResponseTime
            }

            // Calculate anomaly score
            var anomalyScore = 0;
            
            // High number of failed attempts
            if (analysisResult.TotalAttempts > 0)
            {
                var failureRate = (double)(analysisResult.TotalAttempts - analysisResult.SuccessfulAttempts) / analysisResult.TotalAttempts;
                if (failureRate > 0.9) anomalyScore += 3;
                else if (failureRate > 0.7) anomalyScore += 2;
                else if (failureRate > 0.5) anomalyScore += 1;
            }

            // Multiple IP addresses
            if (analysisResult.UniqueIPs > 5) anomalyScore += 3;
            else if (analysisResult.UniqueIPs > 3) anomalyScore += 2;
            else if (analysisResult.UniqueIPs > 1) anomalyScore += 1;

            // Injection attempts
            if (analysisResult.InjectionAttempts > 0) anomalyScore += 5;

            // Multiple user agents
            if (analysisResult.UniqueUserAgents > 3) anomalyScore += 2;

            analysisResult.AnomalyScore = anomalyScore;
            analysisResult.IsAnomalous = anomalyScore >= 4;
            analysisResult.RiskLevel = anomalyScore switch
            {
                >= 8 => "CRITICAL",
                >= 6 => "HIGH",
                >= 4 => "MEDIUM",
                >= 2 => "LOW",
                _ => "MINIMAL"
            };

            return analysisResult;
        }

        /// <summary>
        /// Trigger security alerts based on threat analysis
        /// </summary>
        public async Task<AlertResult> TriggerAlertAsync(string alertType, string severity, string details, string username = "")
        {
            var alertResult = new AlertResult
            {
                AlertType = alertType,
                Severity = severity,
                Details = details,
                Username = username,
                Timestamp = DateTime.Now,
                Success = false
            };

            try
            {
                // Log to database
                await LogSecurityEventAsync(alertType, severity, details, username);
                
                // Console alert for immediate visibility
                var emoji = severity switch
                {
                    "CRITICAL" => "🚨",
                    "HIGH" => "⚠️",
                    "MEDIUM" => "⚡",
                    "LOW" => "ℹ️",
                    _ => "📊"
                };

                Console.WriteLine($"\n{emoji} SECURITY ALERT [{severity}] - {alertType}");
                Console.WriteLine($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"User: {username}");
                Console.WriteLine($"Details: {details}");
                Console.WriteLine(new string('-', 50));

                alertResult.Success = true;
                alertResult.Message = "Alert triggered successfully";
            }
            catch (Exception ex)
            {
                alertResult.Message = $"Failed to trigger alert: {ex.Message}";
                Console.WriteLine($"❌ Alert system error: {ex.Message}");
            }

            return alertResult;
        }

        /// <summary>
        /// Block suspicious activity and implement protective measures
        /// </summary>
        public async Task<BlockingResult> BlockSuspiciousActivityAsync(string ipAddress, string username, string reason, TimeSpan? blockDuration = null)
        {
            var blockResult = new BlockingResult
            {
                IpAddress = ipAddress,
                Username = username,
                Reason = reason,
                BlockTime = DateTime.Now,
                BlockDuration = blockDuration ?? TimeSpan.FromMinutes(30),
                Success = false
            };

            try
            {
                // In a real implementation, this would:
                // 1. Add IP to firewall block list
                // 2. Update application-level blocking rules
                // 3. Send alerts to security team
                // 4. Log the blocking action

                Console.WriteLine($"\n🚫 BLOCKING SUSPICIOUS ACTIVITY");
                Console.WriteLine($"IP Address: {ipAddress}");
                Console.WriteLine($"Username: {username}");
                Console.WriteLine($"Reason: {reason}");
                Console.WriteLine($"Block Duration: {blockResult.BlockDuration.TotalMinutes:F0} minutes");
                Console.WriteLine($"Expires: {blockResult.BlockTime.Add(blockResult.BlockDuration):yyyy-MM-dd HH:mm:ss}");

                // Log the blocking action
                await LogSecurityEventAsync("ACTIVITY_BLOCKED", "HIGH", 
                    $"Blocked {ipAddress} for {reason}. Duration: {blockResult.BlockDuration.TotalMinutes:F0} minutes", 
                    username);

                // Simulate adding to block list (in real app, this would be persistent)
                if (!_blockedIPs.ContainsKey(ipAddress))
                {
                    _blockedIPs[ipAddress] = blockResult.BlockTime.Add(blockResult.BlockDuration);
                }

                blockResult.Success = true;
                blockResult.Message = "Activity blocked successfully";
            }
            catch (Exception ex)
            {
                blockResult.Message = $"Failed to block activity: {ex.Message}";
                Console.WriteLine($"❌ Blocking system error: {ex.Message}");
            }

            return blockResult;
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
        public DateTime AnalysisTime { get; set; }
        public int RecentAttemptsFromIP { get; set; }
        public int RecentAttemptsForUser { get; set; }
        public int AttemptsInTimeWindow { get; set; }
        public double AttemptsPerMinute { get; set; }
        public bool IsBruteForce { get; set; }
        public bool ShouldBlockIP { get; set; }
        public bool IPBlocked { get; set; }
        public string Severity { get; set; } = "LOW";
        public string RecommendedAction { get; set; } = "MONITOR";
        public string Message { get; set; } = string.Empty;
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
        public bool IsSqlInjectionDetected { get; set; }
        public bool IsBruteForceDetected { get; set; }
        public string RecommendedAction { get; set; } = "ALLOW";
    }

    public class SecurityMetrics
    {
        public int TotalAttempts { get; set; }
        public int SuccessfulAttempts { get; set; }
        public int FailedAttempts { get; set; }
        public int InjectionAttempts { get; set; }
        public int BruteForceAttempts { get; set; }
        public int BlockedAttempts { get; set; }
        public int UniqueIPs { get; set; }
        public int UniqueUsers { get; set; }
        public int TotalAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }
        public int MediumAlerts { get; set; }
        public int LowAlerts { get; set; }
        public double AttackDetectionRate { get; set; }
        public double SuccessRate { get; set; }
        public double FailureRate { get; set; }
        public double InjectionRate { get; set; }
        public double DetectionRate { get; set; }
        public double AverageResponseTime { get; set; }
        public int BlockedIPs { get; set; }
    }

    public class SqlInjectionScanResult
    {
        public string Input { get; set; } = string.Empty;
        public DateTime ScanTime { get; set; }
        public bool IsInjection { get; set; }
        public List<string> DetectedPatterns { get; set; } = new();
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "LOW";
        public string Message { get; set; } = string.Empty;
    }

    public class LoginPatternAnalysisResult
    {
        public string Username { get; set; } = string.Empty;
        public DateTime AnalysisTime { get; set; }
        public int TotalAttempts { get; set; }
        public int SuccessfulAttempts { get; set; }
        public int InjectionAttempts { get; set; }
        public int UniqueIPs { get; set; }
        public int UniqueUserAgents { get; set; }
        public double AverageResponseTime { get; set; }
        public int AnomalyScore { get; set; }
        public bool IsAnomalous { get; set; }
        public string RiskLevel { get; set; } = "LOW";
    }

    public class AlertResult
    {
        public string AlertType { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class BlockingResult
    {
        public string IpAddress { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime BlockTime { get; set; }
        public TimeSpan BlockDuration { get; set; }
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
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