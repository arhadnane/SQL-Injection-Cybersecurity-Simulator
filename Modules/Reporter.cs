using Microsoft.Data.SqlClient;
using System.Globalization;
using System.Text;
using CsvHelper;
using Newtonsoft.Json;

namespace SQLInjectionSimulator.Modules
{
    /// <summary>
    /// Comprehensive reporting and analysis module
    /// Generates detailed security reports and exports data for further analysis
    /// </summary>
    public class Reporter
    {
        private readonly string _connectionString;
        private readonly string _reportPath;

        public Reporter(string connectionString, string reportPath = "./Reports/")
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _reportPath = reportPath;
            
            // Ensure report directory exists
            if (!Directory.Exists(_reportPath))
                Directory.CreateDirectory(_reportPath);
        }

        /// <summary>
        /// Generate comprehensive security summary report
        /// </summary>
        public async Task<SecurityReport> GenerateSummaryReportAsync(TimeSpan? period = null)
        {
            var actualPeriod = period ?? TimeSpan.FromHours(24);
            var cutoffTime = DateTime.Now.Subtract(actualPeriod);

            var report = new SecurityReport
            {
                GeneratedAt = DateTime.Now,
                ReportPeriod = actualPeriod,
                PeriodStart = cutoffTime,
                PeriodEnd = DateTime.Now
            };

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Get basic statistics
            await PopulateBasicStatisticsAsync(connection, report, cutoffTime);
            
            // Get attack patterns
            await PopulateAttackPatternsAsync(connection, report, cutoffTime);
            
            // Get top attackers
            await PopulateTopAttackersAsync(connection, report, cutoffTime);
            
            // Get alert statistics
            await PopulateAlertStatisticsAsync(connection, report, cutoffTime);
            
            // Generate recommendations
            report.Recommendations = GenerateRecommendations(report);

            return report;
        }

        /// <summary>
        /// Display security report to console
        /// </summary>
        public void DisplaySecurityReport(SecurityReport report)
        {
            Console.WriteLine();
            Console.WriteLine(new string('=', 100));
            Console.WriteLine("🛡️  SQL INJECTION CYBERSECURITY SIMULATOR - SECURITY REPORT");
            Console.WriteLine(new string('=', 100));
            Console.WriteLine($"Report Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"Analysis Period: {report.ReportPeriod.TotalHours:F1} hours ({report.PeriodStart:yyyy-MM-dd HH:mm} to {report.PeriodEnd:yyyy-MM-dd HH:mm})");
            Console.WriteLine();

            // Basic Statistics
            Console.WriteLine("📊 SECURITY OVERVIEW");
            Console.WriteLine(new string('-', 50));
            Console.WriteLine($"Total Login Attempts: {report.TotalAttempts:N0}");
            Console.WriteLine($"├── Successful Logins: {report.SuccessfulAttempts:N0} ({report.SuccessRate:F1}%)");
            Console.WriteLine($"├── Failed Attempts: {report.FailedAttempts:N0} ({report.FailureRate:F1}%)");
            Console.WriteLine($"└── Injection Attempts: {report.InjectionAttempts:N0} ({report.InjectionRate:F1}%)");
            Console.WriteLine();

            Console.WriteLine($"Unique Sources:");
            Console.WriteLine($"├── IP Addresses: {report.UniqueIPs}");
            Console.WriteLine($"└── Usernames Targeted: {report.UniqueUsers}");
            Console.WriteLine();

            // Security Metrics
            Console.WriteLine("🔍 THREAT DETECTION");
            Console.WriteLine(new string('-', 50));
            Console.WriteLine($"Security Alerts: {report.TotalAlerts:N0}");
            Console.WriteLine($"├── Critical: {report.CriticalAlerts:N0} 🔴");
            Console.WriteLine($"├── High: {report.HighAlerts:N0} 🟠");
            Console.WriteLine($"├── Medium: {report.MediumAlerts:N0} 🟡");
            Console.WriteLine($"└── Low: {report.LowAlerts:N0} 🟢");
            Console.WriteLine();

            Console.WriteLine($"Detection Effectiveness: {report.DetectionRate:F1}%");
            Console.WriteLine($"Average Response Time: {report.AverageResponseTime:F0} ms");
            Console.WriteLine();

            // Attack Patterns
            if (report.AttackPatterns.Any())
            {
                Console.WriteLine("🎯 TOP ATTACK PATTERNS");
                Console.WriteLine(new string('-', 50));
                foreach (var pattern in report.AttackPatterns.Take(10))
                {
                    Console.WriteLine($"{pattern.Count,4}x {pattern.Pattern}");
                    if (!string.IsNullOrEmpty(pattern.Example))
                    {
                        var truncated = pattern.Example.Length > 60 ? pattern.Example[..60] + "..." : pattern.Example;
                        Console.WriteLine($"      Example: {truncated}");
                    }
                }
                Console.WriteLine();
            }

            // Top Attackers
            if (report.TopAttackers.Any())
            {
                Console.WriteLine("🚨 TOP ATTACKING IP ADDRESSES");
                Console.WriteLine(new string('-', 50));
                foreach (var attacker in report.TopAttackers.Take(10))
                {
                    Console.WriteLine($"{attacker.IpAddress,-15} {attacker.AttemptCount,4} attempts ({attacker.InjectionCount} injections)");
                }
                Console.WriteLine();
            }

            // Recommendations
            if (report.Recommendations.Any())
            {
                Console.WriteLine("💡 SECURITY RECOMMENDATIONS");
                Console.WriteLine(new string('-', 50));
                foreach (var recommendation in report.Recommendations)
                {
                    Console.WriteLine($"• {recommendation}");
                }
                Console.WriteLine();
            }

            // Footer
            Console.WriteLine(new string('=', 100));
            Console.WriteLine($"Report complete. Data exported to: {_reportPath}");
            Console.WriteLine(new string('=', 100));
        }

        /// <summary>
        /// Export report data to CSV format
        /// </summary>
        public async Task ExportToCSVAsync(SecurityReport report, string filename = "")
        {
            if (string.IsNullOrEmpty(filename))
                filename = $"security_report_{DateTime.Now:yyyyMMdd_HHmmss}.csv";

            var fullPath = Path.Combine(_reportPath, filename);

            // Export login attempts
            await ExportLoginAttemptsToCSVAsync(Path.Combine(_reportPath, $"login_attempts_{DateTime.Now:yyyyMMdd_HHmmss}.csv"), report.PeriodStart);
            
            // Export alerts
            await ExportAlertsToCSVAsync(Path.Combine(_reportPath, $"security_alerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv"), report.PeriodStart);

            // Export summary report
            var summaryData = new[]
            {
                new { Metric = "Total Attempts", Value = report.TotalAttempts.ToString() },
                new { Metric = "Successful Attempts", Value = report.SuccessfulAttempts.ToString() },
                new { Metric = "Failed Attempts", Value = report.FailedAttempts.ToString() },
                new { Metric = "Injection Attempts", Value = report.InjectionAttempts.ToString() },
                new { Metric = "Success Rate %", Value = report.SuccessRate.ToString("F2") },
                new { Metric = "Injection Rate %", Value = report.InjectionRate.ToString("F2") },
                new { Metric = "Unique IPs", Value = report.UniqueIPs.ToString() },
                new { Metric = "Unique Users", Value = report.UniqueUsers.ToString() },
                new { Metric = "Total Alerts", Value = report.TotalAlerts.ToString() },
                new { Metric = "Critical Alerts", Value = report.CriticalAlerts.ToString() },
                new { Metric = "High Alerts", Value = report.HighAlerts.ToString() },
                new { Metric = "Detection Rate %", Value = report.DetectionRate.ToString("F2") },
                new { Metric = "Average Response Time ms", Value = report.AverageResponseTime.ToString("F0") }
            };

            using var writer = new StreamWriter(fullPath);
            using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
            await csv.WriteRecordsAsync(summaryData);

            Console.WriteLine($"✅ Security report exported to: {fullPath}");
        }

        /// <summary>
        /// Export report data to JSON format
        /// </summary>
        public async Task ExportToJSONAsync(SecurityReport report, string filename = "")
        {
            if (string.IsNullOrEmpty(filename))
                filename = $"security_report_{DateTime.Now:yyyyMMdd_HHmmss}.json";

            var fullPath = Path.Combine(_reportPath, filename);

            var json = JsonConvert.SerializeObject(report, Formatting.Indented, new JsonSerializerSettings
            {
                DateFormatHandling = DateFormatHandling.IsoDateFormat,
                NullValueHandling = NullValueHandling.Ignore
            });

            await File.WriteAllTextAsync(fullPath, json);
            Console.WriteLine($"✅ Security report exported to JSON: {fullPath}");
        }

        /// <summary>
        /// Generate real-time security dashboard data
        /// </summary>
        public async Task<DashboardData> GetDashboardDataAsync()
        {
            var dashboard = new DashboardData
            {
                LastUpdated = DateTime.Now
            };

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Recent activity (last hour)
            var lastHour = DateTime.Now.AddHours(-1);
            
            string recentQuery = @"SELECT 
                COUNT(*) as RecentAttempts,
                SUM(CAST(IsInjection as INT)) as RecentInjections,
                COUNT(DISTINCT IpAddress) as ActiveIPs
                FROM LoginAttempts 
                WHERE AttemptTime >= @lastHour";

            using var recentCommand = new SqlCommand(recentQuery, connection);
            recentCommand.Parameters.AddWithValue("@lastHour", lastHour);
            using var recentReader = await recentCommand.ExecuteReaderAsync();

            if (recentReader.Read())
            {
                dashboard.RecentAttempts = recentReader.GetInt32("RecentAttempts");
                dashboard.RecentInjections = recentReader.GetInt32("RecentInjections");
                dashboard.ActiveIPs = recentReader.GetInt32("ActiveIPs");
            }
            recentReader.Close();

            // Unresolved alerts
            string alertQuery = "SELECT COUNT(*) FROM Alerts WHERE IsResolved = 0";
            using var alertCommand = new SqlCommand(alertQuery, connection);
            dashboard.UnresolvedAlerts = (int)await alertCommand.ExecuteScalarAsync();

            // Activity trend (last 24 hours by hour)
            dashboard.HourlyActivity = await GetHourlyActivityAsync(connection);

            return dashboard;
        }

        /// <summary>
        /// Display real-time dashboard
        /// </summary>
        public void DisplayDashboard(DashboardData dashboard)
        {
            Console.Clear();
            Console.WriteLine("🔴 LIVE SECURITY DASHBOARD");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"Last Updated: {dashboard.LastUpdated:HH:mm:ss}");
            Console.WriteLine();

            Console.WriteLine("📈 REAL-TIME ACTIVITY (Last Hour)");
            Console.WriteLine($"├── Login Attempts: {dashboard.RecentAttempts}");
            Console.WriteLine($"├── Injection Attempts: {dashboard.RecentInjections}");
            Console.WriteLine($"├── Active IP Addresses: {dashboard.ActiveIPs}");
            Console.WriteLine($"└── Unresolved Alerts: {dashboard.UnresolvedAlerts}");
            Console.WriteLine();

            if (dashboard.HourlyActivity.Any())
            {
                Console.WriteLine("📊 ACTIVITY TREND (24 Hours)");
                foreach (var hour in dashboard.HourlyActivity.TakeLast(12))
                {
                    var bar = new string('█', Math.Min(hour.Attempts / 5, 40));
                    Console.WriteLine($"{hour.Hour:HH}:00 │{bar} ({hour.Attempts} attempts)");
                }
            }

            Console.WriteLine();
            Console.WriteLine("Press any key to return to main menu...");
        }

        private async Task PopulateBasicStatisticsAsync(SqlConnection connection, SecurityReport report, DateTime cutoffTime)
        {
            string query = @"SELECT 
                COUNT(*) as TotalAttempts,
                SUM(CAST(IsSuccessful as INT)) as SuccessfulAttempts,
                SUM(CAST(IsInjection as INT)) as InjectionAttempts,
                COUNT(DISTINCT IpAddress) as UniqueIPs,
                COUNT(DISTINCT Username) as UniqueUsers,
                AVG(CAST(ResponseTime as FLOAT)) as AvgResponseTime
                FROM LoginAttempts 
                WHERE AttemptTime >= @cutoffTime";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var reader = await command.ExecuteReaderAsync();

            if (reader.Read())
            {
                report.TotalAttempts = reader.GetInt32("TotalAttempts");
                report.SuccessfulAttempts = reader.GetInt32("SuccessfulAttempts");
                report.InjectionAttempts = reader.GetInt32("InjectionAttempts");
                report.UniqueIPs = reader.GetInt32("UniqueIPs");
                report.UniqueUsers = reader.GetInt32("UniqueUsers");
                report.AverageResponseTime = reader.IsDBNull("AvgResponseTime") ? 0 : reader.GetDouble("AvgResponseTime");
                
                report.FailedAttempts = report.TotalAttempts - report.SuccessfulAttempts;
                report.SuccessRate = report.TotalAttempts > 0 ? (report.SuccessfulAttempts * 100.0 / report.TotalAttempts) : 0;
                report.FailureRate = report.TotalAttempts > 0 ? (report.FailedAttempts * 100.0 / report.TotalAttempts) : 0;
                report.InjectionRate = report.TotalAttempts > 0 ? (report.InjectionAttempts * 100.0 / report.TotalAttempts) : 0;
                report.DetectionRate = report.InjectionAttempts > 0 ? 100.0 : 0; // Assume 100% detection for injections in database
            }
        }

        private async Task PopulateAttackPatternsAsync(SqlConnection connection, SecurityReport report, DateTime cutoffTime)
        {
            string query = @"SELECT 
                InputPayload,
                COUNT(*) as Count
                FROM LoginAttempts 
                WHERE IsInjection = 1 AND AttemptTime >= @cutoffTime 
                  AND InputPayload IS NOT NULL AND InputPayload != ''
                GROUP BY InputPayload
                ORDER BY COUNT(*) DESC";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var reader = await command.ExecuteReaderAsync();

            while (reader.Read())
            {
                report.AttackPatterns.Add(new AttackPattern
                {
                    Pattern = ExtractPatternType(reader.GetString("InputPayload")),
                    Count = reader.GetInt32("Count"),
                    Example = reader.GetString("InputPayload")
                });
            }
        }

        private async Task PopulateTopAttackersAsync(SqlConnection connection, SecurityReport report, DateTime cutoffTime)
        {
            string query = @"SELECT 
                IpAddress,
                COUNT(*) as AttemptCount,
                SUM(CAST(IsInjection as INT)) as InjectionCount
                FROM LoginAttempts 
                WHERE AttemptTime >= @cutoffTime
                GROUP BY IpAddress
                HAVING COUNT(*) > 1
                ORDER BY COUNT(*) DESC";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var reader = await command.ExecuteReaderAsync();

            while (reader.Read())
            {
                report.TopAttackers.Add(new AttackerInfo
                {
                    IpAddress = reader.GetString("IpAddress"),
                    AttemptCount = reader.GetInt32("AttemptCount"),
                    InjectionCount = reader.GetInt32("InjectionCount")
                });
            }
        }

        private async Task PopulateAlertStatisticsAsync(SqlConnection connection, SecurityReport report, DateTime cutoffTime)
        {
            string query = @"SELECT 
                COUNT(*) as TotalAlerts,
                COUNT(CASE WHEN Severity = 'CRITICAL' THEN 1 END) as CriticalAlerts,
                COUNT(CASE WHEN Severity = 'HIGH' THEN 1 END) as HighAlerts,
                COUNT(CASE WHEN Severity = 'MEDIUM' THEN 1 END) as MediumAlerts,
                COUNT(CASE WHEN Severity = 'LOW' THEN 1 END) as LowAlerts
                FROM Alerts 
                WHERE AlertTime >= @cutoffTime";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var reader = await command.ExecuteReaderAsync();

            if (reader.Read())
            {
                report.TotalAlerts = reader.GetInt32("TotalAlerts");
                report.CriticalAlerts = reader.GetInt32("CriticalAlerts");
                report.HighAlerts = reader.GetInt32("HighAlerts");
                report.MediumAlerts = reader.GetInt32("MediumAlerts");
                report.LowAlerts = reader.GetInt32("LowAlerts");
            }
        }

        private async Task<List<HourlyActivity>> GetHourlyActivityAsync(SqlConnection connection)
        {
            var activity = new List<HourlyActivity>();
            
            string query = @"SELECT 
                DATEPART(hour, AttemptTime) as Hour,
                COUNT(*) as Attempts
                FROM LoginAttempts 
                WHERE AttemptTime >= @cutoffTime
                GROUP BY DATEPART(hour, AttemptTime)
                ORDER BY DATEPART(hour, AttemptTime)";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", DateTime.Now.AddHours(-24));
            using var reader = await command.ExecuteReaderAsync();

            while (reader.Read())
            {
                activity.Add(new HourlyActivity
                {
                    Hour = DateTime.Today.AddHours(reader.GetInt32("Hour")),
                    Attempts = reader.GetInt32("Attempts")
                });
            }

            return activity;
        }

        private async Task ExportLoginAttemptsToCSVAsync(string filePath, DateTime cutoffTime)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            string query = @"SELECT AttemptTime, Username, IpAddress, IsSuccessful, IsInjection, ResponseTime, UserAgent
                           FROM LoginAttempts 
                           WHERE AttemptTime >= @cutoffTime
                           ORDER BY AttemptTime DESC";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var reader = await command.ExecuteReaderAsync();

            using var writer = new StreamWriter(filePath);
            using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);

            csv.WriteHeader<LoginAttemptExport>();
            csv.NextRecord();

            while (reader.Read())
            {
                csv.WriteRecord(new LoginAttemptExport
                {
                    AttemptTime = reader.GetDateTime("AttemptTime"),
                    Username = reader.GetString("Username"),
                    IpAddress = reader.GetString("IpAddress"),
                    IsSuccessful = reader.GetBoolean("IsSuccessful"),
                    IsInjection = reader.GetBoolean("IsInjection"),
                    ResponseTime = reader.GetInt32("ResponseTime"),
                    UserAgent = reader.GetString("UserAgent")
                });
                csv.NextRecord();
            }
        }

        private async Task ExportAlertsToCSVAsync(string filePath, DateTime cutoffTime)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            string query = @"SELECT AlertTime, AlertType, Severity, Username, Details, IsResolved
                           FROM Alerts 
                           WHERE AlertTime >= @cutoffTime
                           ORDER BY AlertTime DESC";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);
            using var reader = await command.ExecuteReaderAsync();

            using var writer = new StreamWriter(filePath);
            using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);

            csv.WriteHeader<AlertExport>();
            csv.NextRecord();

            while (reader.Read())
            {
                csv.WriteRecord(new AlertExport
                {
                    AlertTime = reader.GetDateTime("AlertTime"),
                    AlertType = reader.GetString("AlertType"),
                    Severity = reader.GetString("Severity"),
                    Username = reader.IsDBNull("Username") ? "" : reader.GetString("Username"),
                    Details = reader.IsDBNull("Details") ? "" : reader.GetString("Details"),
                    IsResolved = reader.GetBoolean("IsResolved")
                });
                csv.NextRecord();
            }
        }

        private string ExtractPatternType(string payload)
        {
            if (payload.Contains("OR") && payload.Contains("=")) return "Boolean-based injection";
            if (payload.Contains("--")) return "Comment-based injection";
            if (payload.Contains("UNION")) return "Union-based injection";
            if (payload.Contains("WAITFOR")) return "Time-based injection";
            if (payload.Contains("DROP") || payload.Contains("DELETE")) return "Destructive injection";
            return "Generic injection pattern";
        }

        private List<string> GenerateRecommendations(SecurityReport report)
        {
            var recommendations = new List<string>();

            if (report.InjectionRate > 10)
                recommendations.Add("High injection attempt rate detected. Consider implementing additional input validation.");

            if (report.FailureRate > 80)
                recommendations.Add("High failure rate may indicate brute force attacks. Consider implementing account lockout policies.");

            if (report.CriticalAlerts > 0)
                recommendations.Add("Critical security alerts detected. Immediate investigation recommended.");

            if (report.UniqueIPs > 50)
                recommendations.Add("Large number of unique IP addresses. Consider implementing IP-based rate limiting.");

            if (report.AverageResponseTime > 1000)
                recommendations.Add("High average response time may indicate performance issues during attacks.");

            recommendations.Add("Regularly update parameterized queries and input validation mechanisms.");
            recommendations.Add("Monitor logs for emerging attack patterns and update detection rules accordingly.");
            recommendations.Add("Consider implementing Web Application Firewall (WAF) for additional protection.");

            return recommendations;
        }
    }

    // Data structures for reporting
    public class SecurityReport
    {
        public DateTime GeneratedAt { get; set; }
        public TimeSpan ReportPeriod { get; set; }
        public DateTime PeriodStart { get; set; }
        public DateTime PeriodEnd { get; set; }
        
        public int TotalAttempts { get; set; }
        public int SuccessfulAttempts { get; set; }
        public int FailedAttempts { get; set; }
        public int InjectionAttempts { get; set; }
        public int UniqueIPs { get; set; }
        public int UniqueUsers { get; set; }
        
        public double SuccessRate { get; set; }
        public double FailureRate { get; set; }
        public double InjectionRate { get; set; }
        public double DetectionRate { get; set; }
        public double AverageResponseTime { get; set; }
        
        public int TotalAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }
        public int MediumAlerts { get; set; }
        public int LowAlerts { get; set; }
        
        public List<AttackPattern> AttackPatterns { get; set; } = new();
        public List<AttackerInfo> TopAttackers { get; set; } = new();
        public List<string> Recommendations { get; set; } = new();
    }

    public class AttackPattern
    {
        public string Pattern { get; set; } = string.Empty;
        public int Count { get; set; }
        public string Example { get; set; } = string.Empty;
    }

    public class AttackerInfo
    {
        public string IpAddress { get; set; } = string.Empty;
        public int AttemptCount { get; set; }
        public int InjectionCount { get; set; }
    }

    public class DashboardData
    {
        public DateTime LastUpdated { get; set; }
        public int RecentAttempts { get; set; }
        public int RecentInjections { get; set; }
        public int ActiveIPs { get; set; }
        public int UnresolvedAlerts { get; set; }
        public List<HourlyActivity> HourlyActivity { get; set; } = new();
    }

    public class HourlyActivity
    {
        public DateTime Hour { get; set; }
        public int Attempts { get; set; }
    }

    public class LoginAttemptExport
    {
        public DateTime AttemptTime { get; set; }
        public string Username { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public bool IsSuccessful { get; set; }
        public bool IsInjection { get; set; }
        public int ResponseTime { get; set; }
        public string UserAgent { get; set; } = string.Empty;
    }

    public class AlertExport
    {
        public DateTime AlertTime { get; set; }
        public string AlertType { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public bool IsResolved { get; set; }
    }
}