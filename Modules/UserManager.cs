using Microsoft.Data.SqlClient;
using BCrypt.Net;
using System.Security.Cryptography;
using System.Text;

namespace SQLInjectionSimulator.Modules
{
    /// <summary>
    /// Secure user management and authentication module
    /// Demonstrates proper password hashing and parameterized queries
    /// </summary>
    public class UserManager
    {
        private readonly string _connectionString;
        private readonly Random _random;

        public UserManager(string connectionString)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _random = new Random();
        }

        /// <summary>
        /// Create test users with secure password hashing
        /// </summary>
        public async Task CreateTestUsersAsync()
        {
            var testUsers = new List<(string username, string password)>
            {
                ("admin", "SecureAdmin123!"),
                ("user1", "UserPassword456@"),
                ("guest", "GuestAccess789#"),
                ("testuser", "TestUser321$"),
                ("developer", "DevSecure654%"),
                ("demouser", "DemoPass987^")
            };

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            foreach (var (username, password) in testUsers)
            {
                try
                {
                    // Check if user already exists
                    if (await UserExistsAsync(connection, username))
                    {
                        Console.WriteLine($"User '{username}' already exists, skipping...");
                        continue;
                    }

                    // Hash password securely
                    string passwordHash = HashPassword(password);

                    // Use parameterized query for security
                    string query = @"INSERT INTO Users (Username, PasswordHash, CreatedDate, IsActive) 
                                   VALUES (@username, @passwordHash, @createdDate, @isActive)";

                using var command = new SqlCommand(query, connection);
                command.Parameters.Add("@username", System.Data.SqlDbType.NVarChar, 50).Value = username;
                command.Parameters.Add("@passwordHash", System.Data.SqlDbType.NVarChar, 255).Value = passwordHash;
                command.Parameters.Add("@createdDate", System.Data.SqlDbType.DateTime).Value = DateTime.Now;
                command.Parameters.Add("@isActive", System.Data.SqlDbType.Bit).Value = true;                    await command.ExecuteNonQueryAsync();
                    Console.WriteLine($"✅ Created user: {username}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error creating user '{username}': {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Securely hash a password using BCrypt
        /// </summary>
        public string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            // Use BCrypt with work factor of 12 (secure but reasonable performance)
            return BCrypt.Net.BCrypt.HashPassword(password, 12);
        }

        /// <summary>
        /// Verify a password against its hash
        /// </summary>
        public bool VerifyPassword(string password, string hash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
                return false;

            try
            {
                return BCrypt.Net.BCrypt.Verify(password, hash);
            }
            catch
            {
                return false; // Invalid hash format or verification error
            }
        }

        /// <summary>
        /// SECURE authentication method using parameterized queries
        /// </summary>
        public async Task<(bool success, string message, int? userId)> AuthenticateUserSecureAsync(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                return (false, "Username and password are required", null);

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Use parameterized query - SECURE approach
            string query = @"SELECT UserId, PasswordHash, IsActive, FailedLoginCount 
                           FROM Users 
                           WHERE Username = @username";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@username", username);

            using var reader = await command.ExecuteReaderAsync();
            
            if (!reader.Read())
                return (false, "Invalid credentials", null);

            int userId = reader.GetInt32(0); // UserId
            string storedHash = reader.GetString(1); // PasswordHash  
            bool isActive = reader.GetBoolean(2); // IsActive
            int failedCount = reader.GetInt32(3); // FailedLoginCount

            if (!isActive)
                return (false, "Account is disabled", null);

            if (failedCount >= 5)
                return (false, "Account is locked due to too many failed attempts", null);

            // Verify password
            if (VerifyPassword(password, storedHash))
            {
                // Reset failed login count on successful authentication
                await ResetFailedLoginCountAsync(connection, userId);
                return (true, "Authentication successful", userId);
            }
            else
            {
                // Increment failed login count
                await IncrementFailedLoginCountAsync(connection, userId);
                return (false, "Invalid credentials", null);
            }
        }

        /// <summary>
        /// VULNERABLE authentication method for educational demonstration
        /// DO NOT USE IN PRODUCTION - Shows how NOT to do authentication
        /// </summary>
        public async Task<(bool success, string message, string executedQuery)> AuthenticateUserVulnerableAsync(string username, string password)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // String concatenation - VULNERABLE to SQL injection
            string query = $"SELECT UserId, Username FROM Users WHERE Username = '{username}' AND PasswordHash = '{password}'";

            try
            {
                using var command = new SqlCommand(query, connection);
                using var reader = await command.ExecuteReaderAsync();

                bool hasResult = reader.Read();
                return (hasResult, hasResult ? "Authentication successful" : "Invalid credentials", query);
            }
            catch (SqlException ex)
            {
                return (false, $"Database error: {ex.Message}", query);
            }
        }

        /// <summary>
        /// Get user information by username (secure implementation)
        /// </summary>
        public async Task<UserInfo?> GetUserByUsernameAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
                return null;

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            string query = @"SELECT UserId, Username, CreatedDate, IsActive, LastLoginDate, FailedLoginCount 
                           FROM Users 
                           WHERE Username = @username";

            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@username", username);

            using var reader = await command.ExecuteReaderAsync();
            
            if (!reader.Read())
                return null;

            return new UserInfo
            {
                UserId = reader.GetInt32(0), // UserId
                Username = reader.GetString(1), // Username
                CreatedDate = reader.GetDateTime(2), // CreatedDate
                IsActive = reader.GetBoolean(3), // IsActive
                LastLoginDate = reader.IsDBNull(4) ? null : reader.GetDateTime(4), // LastLoginDate
                FailedLoginCount = reader.GetInt32(5) // FailedLoginCount
            };
        }

        /// <summary>
        /// Get all users for reporting purposes
        /// </summary>
        public async Task<List<UserInfo>> GetAllUsersAsync()
        {
            var users = new List<UserInfo>();

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            string query = @"SELECT UserId, Username, CreatedDate, IsActive, LastLoginDate, FailedLoginCount 
                           FROM Users 
                           ORDER BY Username";

            using var command = new SqlCommand(query, connection);
            using var reader = await command.ExecuteReaderAsync();

            while (reader.Read())
            {
                users.Add(new UserInfo
                {
                    UserId = reader.GetInt32(0), // UserId
                    Username = reader.GetString(1), // Username
                    CreatedDate = reader.GetDateTime(2), // CreatedDate
                    IsActive = reader.GetBoolean(3), // IsActive
                    LastLoginDate = reader.IsDBNull(4) ? null : reader.GetDateTime(4), // LastLoginDate
                    FailedLoginCount = reader.GetInt32(5) // FailedLoginCount
                });
            }

            return users;
        }

        private async Task<bool> UserExistsAsync(SqlConnection connection, string username)
        {
            string query = "SELECT COUNT(*) FROM Users WHERE Username = @username";
            using var command = new SqlCommand(query, connection);
            command.Parameters.Add("@username", System.Data.SqlDbType.NVarChar, 50).Value = username;

            int count = (int)(await command.ExecuteScalarAsync() ?? 0);
            return count > 0;
        }

        private async Task ResetFailedLoginCountAsync(SqlConnection connection, int userId)
        {
            string query = "UPDATE Users SET FailedLoginCount = 0, LastLoginDate = @lastLogin WHERE UserId = @userId";
            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@userId", userId);
            command.Parameters.AddWithValue("@lastLogin", DateTime.Now);
            await command.ExecuteNonQueryAsync();
        }

        private async Task IncrementFailedLoginCountAsync(SqlConnection connection, int userId)
        {
            string query = "UPDATE Users SET FailedLoginCount = FailedLoginCount + 1 WHERE UserId = @userId";
            using var command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@userId", userId);
            await command.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// User information data structure
    /// </summary>
    public class UserInfo
    {
        public int UserId { get; set; }
        public string Username { get; set; } = string.Empty;
        public DateTime CreatedDate { get; set; }
        public bool IsActive { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public int FailedLoginCount { get; set; }
    }
}