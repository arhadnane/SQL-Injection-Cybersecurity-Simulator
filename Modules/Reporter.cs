using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Microsoft.Data.SqlClient;

namespace SQLInjectionSimulator.Modules
{
    public class Reporter
    {
        private readonly string _connectionString;

        public Reporter(string connectionString)
        {
            _connectionString = connectionString;
        }

        /// <summary>
        /// Generate comprehensive security report
        /// </summary>
        public async Task<SecurityReport> GenerateReportAsync(DateTime? startDate = null)
        {
            var report = new SecurityReport();
            var cutoffTime = startDate ?? DateTime.Now.AddDays(-30); // Last 30 days by default

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                await PopulateBasicStatisticsAsync(connection, report, cutoffTime);

                Console.WriteLine($"Generated security report for period: {cutoffTime:yyyy-MM-dd} to {DateTime.Now:yyyy-MM-dd}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error generating report: {ex.Message}");
            }

            return report;
        }

        /// <summary>
        /// Display comprehensive security report
        /// </summary>
        public void DisplayReport(SecurityReport report)
        {
            Console.Clear();
            Console.WriteLine("📊 COMPREHENSIVE SECURITY REPORT");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"Report Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine($"Analysis Period: {report.AnalysisPeriod} days");
            Console.WriteLine();

            DisplayBasicStatistics(report);
        }

        private async Task PopulateBasicStatisticsAsync(SqlConnection connection, SecurityReport report, DateTime cutoffTime)
        {
            try
            {
                string query = @"SELECT 
                    COUNT(*) as TotalAttempts,
                    SUM(CAST(IsSuccessful as INT)) as SuccessfulAttempts,
                    SUM(CAST(IsInjection as INT)) as InjectionAttempts
                    FROM LoginAttempts 
                    WHERE AttemptTime >= @cutoffTime";

                using var command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@cutoffTime", cutoffTime);
                using var reader = await command.ExecuteReaderAsync();

                if (reader.Read())
                {
                    report.TotalAttempts = reader.GetInt32(0);
                    report.SuccessfulAttempts = reader.GetInt32(1);
                    report.InjectionAttempts = reader.GetInt32(2);
                    
                    report.FailedAttempts = report.TotalAttempts - report.SuccessfulAttempts;
                    report.SuccessRate = report.TotalAttempts > 0 ? (report.SuccessfulAttempts * 100.0 / report.TotalAttempts) : 0;
                    report.FailureRate = report.TotalAttempts > 0 ? (report.FailedAttempts * 100.0 / report.TotalAttempts) : 0;
                    report.InjectionRate = report.TotalAttempts > 0 ? (report.InjectionAttempts * 100.0 / report.TotalAttempts) : 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error populating basic statistics: {ex.Message}");
            }
        }

        private void DisplayBasicStatistics(SecurityReport report)
        {
            Console.WriteLine("📈 BASIC STATISTICS");
            Console.WriteLine($"├── Total Login Attempts: {report.TotalAttempts:N0}");
            Console.WriteLine($"├── Successful Logins: {report.SuccessfulAttempts:N0} ({report.SuccessRate:F1}%)");
            Console.WriteLine($"├── Failed Logins: {report.FailedAttempts:N0} ({report.FailureRate:F1}%)");
            Console.WriteLine($"└── Injection Attempts: {report.InjectionAttempts:N0} ({report.InjectionRate:F1}%)");
            Console.WriteLine();
        }

        /// <summary>
        /// Generate comprehensive summary report with advanced analytics
        /// </summary>
        public async Task<ComprehensiveReport> GenerateSummaryReportAsync(TimeSpan? period = null)
        {
            var analysisSpan = period ?? TimeSpan.FromDays(30);
            var cutoffTime = DateTime.Now.Subtract(analysisSpan);
            
            var report = new ComprehensiveReport
            {
                GeneratedAt = DateTime.Now,
                AnalysisPeriod = analysisSpan,
                CutoffTime = cutoffTime
            };

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Get basic statistics first (reuse existing method)
            var basicReport = new SecurityReport();
            await PopulateBasicStatisticsAsync(connection, basicReport, cutoffTime);
            report.BasicStats = basicReport;

            // Get top attack patterns
            report.TopAttackPatterns = await GetTopAttackPatternsAsync(connection, cutoffTime, 10);
            
            // Get alert summary
            report.AlertSummary = await GetAlertSummaryAsync(connection, cutoffTime);
            
            // Get hourly activity
            report.HourlyActivity = await GetHourlyActivityAsync(connection, cutoffTime);

            return report;
        }

        /// <summary>
        /// Export report data to CSV format
        /// </summary>
        public async Task<bool> ExportToCSVAsync(SecurityReport report, string fileName = "")
        {
            try
            {
                if (string.IsNullOrEmpty(fileName))
                    fileName = $"SecurityReport_{DateTime.Now:yyyyMMdd_HHmmss}.csv";

                var csv = new StringBuilder();
                csv.AppendLine("Metric,Value,Percentage");
                csv.AppendLine($"Total Attempts,{report.TotalAttempts},100.0");
                csv.AppendLine($"Successful Attempts,{report.SuccessfulAttempts},{report.SuccessRate:F1}");
                csv.AppendLine($"Failed Attempts,{report.FailedAttempts},{report.FailureRate:F1}");
                csv.AppendLine($"Injection Attempts,{report.InjectionAttempts},{report.InjectionRate:F1}");
                csv.AppendLine($"Unique IPs,{report.UniqueIPs},-");
                csv.AppendLine($"Unique Users,{report.UniqueUsers},-");
                csv.AppendLine($"Critical Alerts,{report.CriticalAlerts},-");
                csv.AppendLine($"High Alerts,{report.HighAlerts},-");
                csv.AppendLine($"Medium Alerts,{report.MediumAlerts},-");
                csv.AppendLine($"Low Alerts,{report.LowAlerts},-");

                // In a real application, save to file
                Console.WriteLine($"📄 CSV Report Generated:");
                Console.WriteLine($"Filename: {fileName}");
                Console.WriteLine($"Size: {csv.Length} characters");
                Console.WriteLine("Content preview:");
                Console.WriteLine(csv.ToString().Substring(0, Math.Min(200, csv.Length)));
                
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error exporting to CSV: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Display real-time security metrics dashboard
        /// </summary>
        public async Task DisplaySecurityMetricsDashboardAsync()
        {
            Console.Clear();
            Console.WriteLine("📊 REAL-TIME SECURITY METRICS DASHBOARD");
            Console.WriteLine("=========================================");
            Console.WriteLine($"Last Updated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine();

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                // Real-time metrics (last 24 hours)
                var cutoff24h = DateTime.Now.AddDays(-1);
                var metricsQuery = @"
                    SELECT 
                        COUNT(*) as Total24h,
                        COUNT(CASE WHEN IsInjection = 1 THEN 1 END) as Injections24h,
                        COUNT(CASE WHEN AttemptTime >= @cutoff1h THEN 1 END) as Total1h,
                        COUNT(CASE WHEN IsInjection = 1 AND AttemptTime >= @cutoff1h THEN 1 END) as Injections1h,
                        COUNT(DISTINCT IpAddress) as UniqueIPs,
                        COUNT(DISTINCT CASE WHEN AttemptTime >= @cutoff1h THEN IpAddress END) as ActiveIPs
                    FROM LoginAttempts 
                    WHERE AttemptTime >= @cutoff24h";

                using var command = new SqlCommand(metricsQuery, connection);
                command.Parameters.AddWithValue("@cutoff24h", cutoff24h);
                command.Parameters.AddWithValue("@cutoff1h", DateTime.Now.AddHours(-1));

                using var reader = await command.ExecuteReaderAsync();
                
                if (reader.Read())
                {
                    Console.WriteLine("🔄 ACTIVITY OVERVIEW:");
                    Console.WriteLine($"   📈 Last 24 hours: {reader.GetInt32(0)} total attempts"); // Total24h
                    Console.WriteLine($"   🚨 Injections (24h): {reader.GetInt32(1)} attempts"); // Injections24h
                    Console.WriteLine($"   ⚡ Last 1 hour: {reader.GetInt32(2)} total attempts"); // Total1h
                    Console.WriteLine($"   💥 Injections (1h): {reader.GetInt32(3)} attempts"); // Injections1h
                    Console.WriteLine($"   🌐 Unique IPs: {reader.GetInt32(4)} total"); // UniqueIPs
                    Console.WriteLine($"   🔴 Active IPs: {reader.GetInt32(5)} in last hour"); // ActiveIPs
                }
                reader.Close();

                // Alert status
                var alertQuery = @"
                    SELECT 
                        COUNT(*) as TotalAlerts,
                        COUNT(CASE WHEN IsResolved = 0 THEN 1 END) as UnresolvedAlerts,
                        COUNT(CASE WHEN Severity = 'CRITICAL' AND IsResolved = 0 THEN 1 END) as CriticalOpen,
                        COUNT(CASE WHEN AlertTime >= @cutoff24h THEN 1 END) as Recent24h
                    FROM Alerts";

                using var alertCommand = new SqlCommand(alertQuery, connection);
                alertCommand.Parameters.AddWithValue("@cutoff24h", cutoff24h);

                using var alertReader = await alertCommand.ExecuteReaderAsync();
                if (alertReader.Read())
                {
                    Console.WriteLine("\n🚨 ALERT STATUS:");
                    Console.WriteLine($"   📋 Total Alerts: {alertReader.GetInt32(0)}"); // TotalAlerts
                    Console.WriteLine($"   ⚠️  Unresolved: {alertReader.GetInt32(1)}"); // UnresolvedAlerts
                    Console.WriteLine($"   🔴 Critical Open: {alertReader.GetInt32(2)}"); // CriticalOpen
                    Console.WriteLine($"   📅 Recent (24h): {alertReader.GetInt32(3)}"); // Recent24h
                }

                Console.WriteLine("\n⏱️  Auto-refresh: Dashboard updates every 30 seconds");
                Console.WriteLine("Press any key to return to main menu...");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Dashboard error: {ex.Message}");
            }
        }

        /// <summary>
        /// Analyze and display top attack patterns
        /// </summary>
        public async Task<List<AttackPattern>> ShowTopAttackPatternsAsync(int topCount = 10)
        {
            var patterns = new List<AttackPattern>();
            
            Console.WriteLine($"\n🎯 TOP {topCount} ATTACK PATTERNS");
            Console.WriteLine("================================");

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                patterns = await GetTopAttackPatternsAsync(connection, DateTime.Now.AddDays(-30), topCount);

                int rank = 1;
                foreach (var pattern in patterns)
                {
                    Console.WriteLine($"{rank,2}. Pattern: {pattern.Pattern.Substring(0, Math.Min(40, pattern.Pattern.Length))}...");
                    Console.WriteLine($"     Frequency: {pattern.Frequency} attempts from {pattern.UniqueIPs} IPs");
                    Console.WriteLine($"     Success: {pattern.SuccessCount} times | Last seen: {pattern.LastSeen:yyyy-MM-dd HH:mm}");
                    Console.WriteLine();
                    rank++;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error analyzing attack patterns: {ex.Message}");
            }

            return patterns;
        }

        /// <summary>
        /// Generate security recommendations based on current threats
        /// </summary>
        public async Task<List<SecurityRecommendation>> GenerateRecommendationsAsync()
        {
            var recommendations = new List<SecurityRecommendation>();
            
            Console.WriteLine("\n🛡️  SECURITY RECOMMENDATIONS");
            Console.WriteLine("==============================");

            try
            {
                using var connection = new SqlConnection(_connectionString);
                await connection.OpenAsync();

                // Analyze recent data (last 7 days)
                var cutoff = DateTime.Now.AddDays(-7);
                
                var analysisQuery = @"
                    SELECT 
                        COUNT(*) as TotalAttempts,
                        COUNT(CASE WHEN IsInjection = 1 THEN 1 END) as InjectionAttempts,
                        COUNT(CASE WHEN IsSuccessful = 1 THEN 1 END) as SuccessfulAttempts,
                        COUNT(DISTINCT IpAddress) as UniqueIPs,
                        AVG(CAST(ResponseTime as FLOAT)) as AvgResponseTime
                    FROM LoginAttempts 
                    WHERE AttemptTime >= @cutoff";

                using var command = new SqlCommand(analysisQuery, connection);
                command.Parameters.AddWithValue("@cutoff", cutoff);

                using var reader = await command.ExecuteReaderAsync();
                
                if (reader.Read() && !reader.IsDBNull(0)) // TotalAttempts
                {
                    var totalAttempts = reader.GetInt32(0); // TotalAttempts
                    var injectionAttempts = reader.GetInt32(1); // InjectionAttempts
                    var uniqueIPs = reader.GetInt32(3); // UniqueIPs

                    // Generate recommendations based on analysis
                    if (totalAttempts > 1000)
                    {
                        recommendations.Add(new SecurityRecommendation
                        {
                            Priority = "HIGH",
                            Category = "Rate Limiting",
                            Title = "Implement Rate Limiting",
                            Description = $"High volume of login attempts detected ({totalAttempts} in 7 days). Implement rate limiting to slow down attackers.",
                            ActionItems = new[] { "Configure IP-based rate limiting", "Set up progressive delays", "Monitor for distributed attacks" }
                        });
                    }

                    if (injectionAttempts > totalAttempts * 0.1) // More than 10% injection attempts
                    {
                        recommendations.Add(new SecurityRecommendation
                        {
                            Priority = "CRITICAL",
                            Category = "Input Validation",
                            Title = "Strengthen Input Validation",
                            Description = $"Significant SQL injection activity ({injectionAttempts}/{totalAttempts}). Review and enhance input validation.",
                            ActionItems = new[] { "Implement strict input validation", "Use parameterized queries exclusively", "Deploy WAF rules" }
                        });
                    }

                    if (uniqueIPs > 100)
                    {
                        recommendations.Add(new SecurityRecommendation
                        {
                            Priority = "MEDIUM",
                            Category = "Monitoring",
                            Title = "Enhanced IP Monitoring",
                            Description = $"Activity from many unique IPs ({uniqueIPs}). Implement enhanced IP reputation checking.",
                            ActionItems = new[] { "Integrate IP reputation services", "Implement geo-blocking", "Monitor for VPN/proxy usage" }
                        });
                    }
                }

                // Always include baseline recommendations
                recommendations.Add(new SecurityRecommendation
                {
                    Priority = "HIGH",
                    Category = "Best Practices",
                    Title = "Regular Security Audits",
                    Description = "Maintain regular security assessments to identify new vulnerabilities.",
                    ActionItems = new[] { "Schedule monthly security reviews", "Conduct penetration testing", "Update security policies" }
                });

                // Display recommendations
                foreach (var rec in recommendations.OrderByDescending(r => r.Priority))
                {
                    var emoji = rec.Priority switch
                    {
                        "CRITICAL" => "🔴",
                        "HIGH" => "🟡",
                        "MEDIUM" => "🟠",
                        _ => "🟢"
                    };

                    Console.WriteLine($"{emoji} [{rec.Priority}] {rec.Category}: {rec.Title}");
                    Console.WriteLine($"   📝 {rec.Description}");
                    Console.WriteLine("   📋 Action Items:");
                    foreach (var action in rec.ActionItems)
                    {
                        Console.WriteLine($"      • {action}");
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error generating recommendations: {ex.Message}");
            }

            return recommendations;
        }

        private async Task<List<AttackPattern>> GetTopAttackPatternsAsync(SqlConnection connection, DateTime cutoffTime, int count)
        {
            var patterns = new List<AttackPattern>();
            
            var query = @"
                SELECT TOP (@count)
                    InputPayload,
                    COUNT(*) as Frequency,
                    COUNT(DISTINCT IpAddress) as UniqueIPs,
                    COUNT(CASE WHEN IsSuccessful = 1 THEN 1 END) as SuccessCount,
                    MAX(AttemptTime) as LastSeen
                FROM LoginAttempts 
                WHERE IsInjection = 1 AND AttemptTime >= @cutoffTime AND InputPayload IS NOT NULL
                GROUP BY InputPayload
                ORDER BY COUNT(*) DESC";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@count", count);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);

            using var reader = await command.ExecuteReaderAsync();
            
            while (reader.Read())
            {
                patterns.Add(new AttackPattern
                {
                    Pattern = reader.GetString(0), // InputPayload
                    Frequency = reader.GetInt32(1), // Frequency
                    UniqueIPs = reader.GetInt32(2), // UniqueIPs
                    SuccessCount = reader.GetInt32(3), // SuccessCount
                    LastSeen = reader.GetDateTime(4) // LastSeen
                });
            }

            return patterns;
        }

        private async Task<AlertSummary> GetAlertSummaryAsync(SqlConnection connection, DateTime cutoffTime)
        {
            var summary = new AlertSummary();
            
            var query = @"
                SELECT 
                    COUNT(*) as TotalAlerts,
                    COUNT(CASE WHEN Severity = 'CRITICAL' THEN 1 END) as Critical,
                    COUNT(CASE WHEN Severity = 'HIGH' THEN 1 END) as High,
                    COUNT(CASE WHEN Severity = 'MEDIUM' THEN 1 END) as Medium,
                    COUNT(CASE WHEN Severity = 'LOW' THEN 1 END) as Low
                FROM Alerts 
                WHERE AlertTime >= @cutoffTime";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);

            using var reader = await command.ExecuteReaderAsync();
            
            if (reader.Read())
            {
                summary.TotalAlerts = reader.GetInt32(0); // TotalAlerts
                summary.CriticalAlerts = reader.GetInt32(1); // Critical
                summary.HighAlerts = reader.GetInt32(2); // High
                summary.MediumAlerts = reader.GetInt32(3); // Medium
                summary.LowAlerts = reader.GetInt32(4); // Low
            }

            return summary;
        }

        private async Task<List<HourlyActivity>> GetHourlyActivityAsync(SqlConnection connection, DateTime cutoffTime)
        {
            var activity = new List<HourlyActivity>();
            
            var query = @"
                SELECT 
                    DATEPART(hour, AttemptTime) as Hour,
                    COUNT(*) as Attempts
                FROM LoginAttempts 
                WHERE AttemptTime >= @cutoffTime
                GROUP BY DATEPART(hour, AttemptTime)
                ORDER BY Hour";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@cutoffTime", cutoffTime);

            using var reader = await command.ExecuteReaderAsync();
            
            while (reader.Read())
            {
                activity.Add(new HourlyActivity
                {
                    Hour = DateTime.Today.AddHours(reader.GetInt32(0)), // Hour
                    Attempts = reader.GetInt32(1) // Attempts
                });
            }

            return activity;
        }
    }

    /// <summary>
    /// Comprehensive report with advanced analytics
    /// </summary>
    public class ComprehensiveReport
    {
        public DateTime GeneratedAt { get; set; } = DateTime.Now;
        public TimeSpan AnalysisPeriod { get; set; }
        public DateTime CutoffTime { get; set; }
        public SecurityReport BasicStats { get; set; } = new();
        public List<AttackPattern> TopAttackPatterns { get; set; } = new();
        public AlertSummary AlertSummary { get; set; } = new();
        public List<HourlyActivity> HourlyActivity { get; set; } = new();
    }

    /// <summary>
    /// Attack pattern analysis
    /// </summary>
    public class AttackPattern
    {
        public string Pattern { get; set; } = string.Empty;
        public int Frequency { get; set; }
        public int UniqueIPs { get; set; }
        public int SuccessCount { get; set; }
        public DateTime LastSeen { get; set; }
    }

    /// <summary>
    /// Alert summary statistics
    /// </summary>
    public class AlertSummary
    {
        public int TotalAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }
        public int MediumAlerts { get; set; }
        public int LowAlerts { get; set; }
    }

    /// <summary>
    /// Security recommendation
    /// </summary>
    public class SecurityRecommendation
    {
        public string Priority { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string[] ActionItems { get; set; } = Array.Empty<string>();
    }

    /// <summary>
    /// Security report data structure
    /// </summary>
    public class SecurityReport
    {
        public DateTime GeneratedAt { get; set; } = DateTime.Now;
        public int AnalysisPeriod { get; set; } = 30; // Days

        // Basic statistics
        public int TotalAttempts { get; set; }
        public int SuccessfulAttempts { get; set; }
        public int FailedAttempts { get; set; }
        public int InjectionAttempts { get; set; }
        public double SuccessRate { get; set; }
        public double FailureRate { get; set; }
        public double InjectionRate { get; set; }
        
        // Additional metrics
        public int UniqueIPs { get; set; }
        public int UniqueUsers { get; set; }
        public double AverageResponseTime { get; set; }

        // Alert statistics
        public int TotalAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }
        public int MediumAlerts { get; set; }
        public int LowAlerts { get; set; }
    }

    /// <summary>
    /// Dashboard data structure for live monitoring
    /// </summary>
    public class DashboardData
    {
        public DateTime LastUpdated { get; set; } = DateTime.Now;
        public int RecentAttempts { get; set; }
        public int RecentInjections { get; set; }
        public int ActiveIPs { get; set; }
        public int UnresolvedAlerts { get; set; }
        
        public List<HourlyActivity> HourlyActivity { get; set; } = new();
    }

    /// <summary>
    /// Hourly activity tracking
    /// </summary>
    public class HourlyActivity
    {
        public DateTime Hour { get; set; }
        public int Attempts { get; set; }
    }
}