using Microsoft.Data.SqlClient;
using BCrypt.Net;

namespace SQLInjectionSimulator.Modules
{
    /// <summary>
    /// Simplified UserManager for initial testing
    /// </summary>
    public class UserManagerSimple
    {
        private readonly string _connectionString;

        public UserManagerSimple(string connectionString)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
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
                ("guest", "GuestAccess789#")
            };

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            foreach (var (username, password) in testUsers)
            {
                try
                {
                    string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, 12);
                    
                    string query = @"IF NOT EXISTS (SELECT 1 FROM Users WHERE Username = @username)
                                   INSERT INTO Users (Username, PasswordHash, CreatedAt, IsActive) 
                                   VALUES (@username, @passwordHash, @createdDate, @isActive)";

                    using var command = new SqlCommand(query, connection);
                    command.Parameters.Add("@username", System.Data.SqlDbType.NVarChar, 50).Value = username;
                    command.Parameters.Add("@passwordHash", System.Data.SqlDbType.NVarChar, 255).Value = passwordHash;
                    command.Parameters.Add("@createdDate", System.Data.SqlDbType.DateTime2).Value = DateTime.Now;
                    command.Parameters.Add("@isActive", System.Data.SqlDbType.Bit).Value = true;

                    await command.ExecuteNonQueryAsync();
                    Console.WriteLine($"✅ User created/verified: {username}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error with user '{username}': {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Get all users
        /// </summary>
        public async Task<List<SimpleUserInfo>> GetAllUsersAsync()
        {
            var users = new List<SimpleUserInfo>();

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            string query = "SELECT Id, Username, IsActive FROM Users ORDER BY Username";

            using var command = new SqlCommand(query, connection);
            using var reader = await command.ExecuteReaderAsync();

            while (reader.Read())
            {
                users.Add(new SimpleUserInfo
                {
                    UserId = reader.GetInt32(0),
                    Username = reader.GetString(1),
                    IsActive = reader.GetBoolean(2)
                });
            }

            return users;
        }

        /// <summary>
        /// Secure authentication
        /// </summary>
        public async Task<(bool success, string message)> AuthenticateUserSecureAsync(string username, string password)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            string query = "SELECT PasswordHash, IsActive FROM Users WHERE Username = @username";

            using var command = new SqlCommand(query, connection);
            command.Parameters.Add("@username", System.Data.SqlDbType.NVarChar, 50).Value = username;

            using var reader = await command.ExecuteReaderAsync();
            
            if (!reader.Read())
                return (false, "User not found");

            string storedHash = reader.GetString(0);
            bool isActive = reader.GetBoolean(1);

            if (!isActive)
                return (false, "Account disabled");

            if (BCrypt.Net.BCrypt.Verify(password, storedHash))
                return (true, "Authentication successful");
            else
                return (false, "Invalid credentials");
        }
    }

    public class SimpleUserInfo
    {
        public int UserId { get; set; }
        public string Username { get; set; } = string.Empty;
        public bool IsActive { get; set; }
    }
}