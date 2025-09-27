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
                var tester = new InjectionTester(connectionString);

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
                    case "4":
                        Console.WriteLine("\nDemo: SQL Injection vs Secure Parameterization");
                        Console.Write("Enter a username to test: ");
                        var input = Console.ReadLine() ?? string.Empty;

                        var compare = await tester.CompareQueryResultsAsync(input);

                        Console.WriteLine("\nVulnerable query result:");
                        Console.WriteLine($"- Query: {compare.Vulnerable?.Query}");
                        Console.WriteLine($"- Rows: {compare.Vulnerable?.Rows?.ToString() ?? "null"}");
                        if (!string.IsNullOrWhiteSpace(compare.Vulnerable?.Error))
                            Console.WriteLine($"- Error: {compare.Vulnerable?.Error}");

                        Console.WriteLine("\nSecure query result:");
                        Console.WriteLine($"- Query: {compare.Secure?.Query}");
                        Console.WriteLine($"- Rows: {compare.Secure?.Rows?.ToString() ?? "null"}");
                        if (!string.IsNullOrWhiteSpace(compare.Secure?.Error))
                            Console.WriteLine($"- Error: {compare.Secure?.Error}");

                        Console.WriteLine("\nExplanation:");
                        Console.WriteLine(compare.Explanation);
                        break;
                    case "5":
                        // Exit
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
            Console.WriteLine("4. Demo injection");
            Console.WriteLine("5. Exit");
            Console.Write("Enter choice: ");
        }
    }
}