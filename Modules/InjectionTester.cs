using System.Diagnostics;
using Microsoft.Data.SqlClient;

namespace SQLInjectionSimulator.Modules
{
    /// <summary>
    /// Minimal InjectionTester for Phase 1: compare vulnerable vs secure query handling.
    /// Uses simple schema (Users: Id, Username, PasswordHash, IsActive)
    /// </summary>
    public class InjectionTester
    {
        private readonly string _connectionString;

        public InjectionTester(string connectionString)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
        }

        public async Task<CompareResult> CompareQueryResultsAsync(string input)
        {
            var vulnerable = await DemonstrateVulnerableQueryAsync(input);
            var secure = await DemonstrateSecureQueryAsync(input);
            return new CompareResult
            {
                Vulnerable = vulnerable,
                Secure = secure,
                AreDifferent = (vulnerable.Rows ?? -1) != (secure.Rows ?? -1) || (!string.IsNullOrEmpty(vulnerable.Error) && string.IsNullOrEmpty(secure.Error)),
                Explanation = (vulnerable.Rows ?? -1) != (secure.Rows ?? -1)
                    ? "Vulnerable query produced a different outcome due to input affecting query semantics."
                    : "Secure parameterized query prevents input from altering logic."
            };
        }

        public async Task<DemoResult> DemonstrateVulnerableQueryAsync(string input)
        {
            var result = new DemoResult
            {
                Explanation = "VULNERABLE: String concatenation allows input to alter query semantics.",
                DetectedInjection = ContainsSuspicious(input)
            };

            string unsafeQuery = $"SELECT COUNT(*) FROM Users WHERE Username = '{input}' AND IsActive = 1";
            result.Query = unsafeQuery;

            if (ContainsDestructive(input))
            {
                result.Error = "Destructive payload detected. Skipping execution (explain-only).";
                await LogAlertAsync("SQL_INJECTION", "CRITICAL", $"Destructive payload detected: {Sanitize(input)}", input);
                await LogAttemptAsync(input, false, true, unsafeQuery, null);
                return result;
            }

            var sw = Stopwatch.StartNew();
            try
            {
                using var conn = new SqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new SqlCommand(unsafeQuery, conn);
                object? scalar = await cmd.ExecuteScalarAsync();
                result.Rows = ToInt(scalar);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            finally
            {
                sw.Stop();
                await LogAttemptAsync(input, (result.Rows ?? 0) > 0, result.DetectedInjection, unsafeQuery, (int)sw.ElapsedMilliseconds);
                if (result.DetectedInjection)
                {
                    await LogAlertAsync("SQL_INJECTION", "HIGH", $"Suspicious input detected: {Sanitize(input)}", input);
                }
            }

            return result;
        }

        public async Task<DemoResult> DemonstrateSecureQueryAsync(string input)
        {
            var result = new DemoResult
            {
                Explanation = "SECURE: Parameterized query treats input as data, not code.",
                DetectedInjection = ContainsSuspicious(input)
            };

            string sql = "SELECT COUNT(*) FROM Users WHERE Username = @username AND IsActive = 1";
            result.Query = sql + " -- parameterized @username";

            var sw = Stopwatch.StartNew();
            try
            {
                using var conn = new SqlConnection(_connectionString);
                await conn.OpenAsync();
                using var cmd = new SqlCommand(sql, conn);
                cmd.Parameters.Add("@username", System.Data.SqlDbType.NVarChar, 50).Value = input;
                object? scalar = await cmd.ExecuteScalarAsync();
                result.Rows = ToInt(scalar);
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            finally
            {
                sw.Stop();
                await LogAttemptAsync(input, (result.Rows ?? 0) > 0, result.DetectedInjection, sql, (int)sw.ElapsedMilliseconds);
            }

            return result;
        }

        private static bool ContainsSuspicious(string input)
        {
            if (string.IsNullOrEmpty(input)) return false;
            string[] patterns = { "' OR '1'='1", " OR 1=1", "--", "/*", "*/", " UNION " };
            foreach (var p in patterns)
            {
                if (input.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        private static bool ContainsDestructive(string input)
        {
            if (string.IsNullOrEmpty(input)) return false;
            string up = " " + input.ToUpperInvariant() + " ";
            string[] patterns = { " DROP ", "; DROP", " DELETE ", " TRUNCATE ", " ALTER ", " UPDATE ", " INSERT INTO ", " EXEC ", " XP_", " SP_" };
            foreach (var p in patterns)
            {
                if (up.Contains(p, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        private static int? ToInt(object? scalar)
        {
            try
            {
                if (scalar == null || scalar is DBNull) return null;
                if (scalar is int i) return i;
                return Convert.ToInt32(scalar);
            }
            catch { return null; }
        }

        private static string Sanitize(string value)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value.Length > 200 ? value.Substring(0, 200) + "…" : value;
        }

        private async Task LogAttemptAsync(string username, bool isSuccessful, bool isInjection, string query, int? responseTimeMs)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            string sql = @"INSERT INTO LoginAttempts (Username, IpAddress, IsSuccessful, IsInjection, QueryAttempted, ResponseTime)
                           VALUES (@u, @ip, @ok, @inj, @q, @rt)";
            using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.Add("@u", System.Data.SqlDbType.NVarChar, 50).Value = username ?? string.Empty;
            cmd.Parameters.Add("@ip", System.Data.SqlDbType.NVarChar, 45).Value = "127.0.0.1";
            cmd.Parameters.Add("@ok", System.Data.SqlDbType.Bit).Value = isSuccessful;
            cmd.Parameters.Add("@inj", System.Data.SqlDbType.Bit).Value = isInjection;
            cmd.Parameters.Add("@q", System.Data.SqlDbType.NVarChar).Value = query ?? string.Empty;
            cmd.Parameters.Add("@rt", System.Data.SqlDbType.Int).Value = (object?)responseTimeMs ?? DBNull.Value;
            await cmd.ExecuteNonQueryAsync();
        }

        private async Task LogAlertAsync(string type, string severity, string message, string? username)
        {
            using var conn = new SqlConnection(_connectionString);
            await conn.OpenAsync();
            string sql = @"INSERT INTO Alerts (AlertType, Severity, Message, Details, IpAddress, Username)
                           VALUES (@t, @sev, @msg, @det, @ip, @u)";
            using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.Add("@t", System.Data.SqlDbType.NVarChar, 50).Value = type;
            cmd.Parameters.Add("@sev", System.Data.SqlDbType.NVarChar, 20).Value = severity;
            cmd.Parameters.Add("@msg", System.Data.SqlDbType.NVarChar, 500).Value = message;
            cmd.Parameters.Add("@det", System.Data.SqlDbType.NVarChar).Value = message;
            cmd.Parameters.Add("@ip", System.Data.SqlDbType.NVarChar, 45).Value = "127.0.0.1";
            cmd.Parameters.Add("@u", System.Data.SqlDbType.NVarChar, 50).Value = (object?)username ?? DBNull.Value;
            await cmd.ExecuteNonQueryAsync();
        }
    }

    public class DemoResult
    {
        public string? Query { get; set; }
        public int? Rows { get; set; }
        public string? Error { get; set; }
        public bool DetectedInjection { get; set; }
        public string? Explanation { get; set; }
    }

    public class CompareResult
    {
        public DemoResult? Vulnerable { get; set; }
        public DemoResult? Secure { get; set; }
        public bool AreDifferent { get; set; }
        public string? Explanation { get; set; }
    }
}