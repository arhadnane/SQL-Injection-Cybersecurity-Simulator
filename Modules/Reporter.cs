using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
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