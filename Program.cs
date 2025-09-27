using Microsoft.Extensions.Configuration;
using SQLInjectionSimulator.Modules;

namespace SQLInjectionSimulator
{
    /// <summary>
    /// SQL Injection Cybersecurity Simulator - Educational Console Application
    /// 
    /// ⚠️ FOR EDUCATIONAL USE ONLY - DO NOT USE AGAINST REAL SYSTEMS
    /// </summary>
    class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                Console.WriteLine("🛡️ SQL Injection Cybersecurity Simulator");
                Console.WriteLine("==========================================");
                Console.WriteLine("⚠️  FOR EDUCATIONAL PURPOSES ONLY");
                Console.WriteLine();

                // Simple connection string for LocalDB
                string connectionString = "Server=(localdb)\\MSSQLLocalDB;Database=SQLInjectionSimulator;Trusted_Connection=true;MultipleActiveResultSets=true;TrustServerCertificate=true";

                // Initialize basic components
                var userManager = new UserManagerSimple(connectionString);

                Console.WriteLine("🚀 Initializing application...");
                Console.WriteLine("✅ Application ready!");
                Console.WriteLine();

                ShowMainMenu();
                var choice = Console.ReadLine()?.Trim();

                switch (choice?.ToUpper())
                {
                    case "1":
                        Console.WriteLine("Setting up test users...");
                        await userManager.CreateTestUsersAsync();
                        break;
                    case "2":
                        Console.WriteLine("Listing users...");
                        var users = await userManager.GetAllUsersAsync();
                        foreach (var user in users)
                        {
                            Console.WriteLine($"- {user.Username} (Active: {user.IsActive})");
                        }
                        break;
                    case "3":
                        Console.WriteLine("Testing secure authentication...");
                        var result = await userManager.AuthenticateUserSecureAsync("admin", "SecureAdmin123!");
                        Console.WriteLine($"Authentication result: {result.success} - {result.message}");
                        break;
                    default:
                        Console.WriteLine("Invalid choice. Exiting...");
                        break;
                }

                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
                Console.WriteLine("Please ensure SQL Server LocalDB is installed and accessible.");
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }

        private static void ShowMainMenu()
        {
            Console.WriteLine("📋 Choose an option:");
            Console.WriteLine("1. Setup test users");
            Console.WriteLine("2. List users");
            Console.WriteLine("3. Test authentication");
            Console.WriteLine("4. Exit");
            Console.Write("Enter choice: ");
        }
    }
}