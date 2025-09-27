# 🛡️ SQL Injection Cybersecurity Simulator

An educational console application built with **pure C# + SQL** that demonstrates SQL injection vulnerabilities and defense mechanisms for learning purposes.

**⚠️ FOR EDUCATIONAL USE ONLY - DO NOT USE AGAINST REAL SYSTEMS**

## 🎯 Project Overview

This simulator provides a safe, controlled environment to:
- Learn how SQL injection vulnerabilities work
- Understand the impact of improper input handling
- Practice implementing secure coding techniques
- Analyze attack patterns and defense mechanisms
- Generate comprehensive security reports

## 📂 Project Structure

```
SQLInjectionSimulator/
├── Program.cs                      # Main application entry point
├── SQLInjectionSimulator.csproj    # Project configuration
├── appsettings.json                # Application configuration
├── copilot-instruction.md          # Comprehensive development guide
├── Database/
│   ├── schema.sql                  # Database table definitions
│   └── seed.sql                    # Initial test data
├── Modules/
│   ├── UserManager.cs              # Secure user management
│   ├── LoginSimulator.cs           # Attack simulation
│   ├── InjectionTester.cs          # Vulnerability demonstration
│   ├── DefenseEngine.cs            # Threat detection & analysis
│   └── Reporter.cs                 # Security reporting & analytics
└── README.md                       # This file
```

## 🚀 Quick Start

### Prerequisites
- .NET 8.0 SDK
- SQL Server LocalDB (included with Visual Studio)
- Windows OS (for LocalDB support)

### Installation & Setup

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd SQLInjectionSimulator
   ```

2. **Restore NuGet packages**
   ```bash
   dotnet restore
   ```

3. **Initialize the database**
   ```bash
   # Execute the SQL scripts in order:
   # 1. Run Database/schema.sql in SQL Server Management Studio or VS Code
   # 2. Run Database/seed.sql to populate with test data
   ```

4. **Run the application**
   ```bash
   dotnet run
   ```

5. **Choose option 6 from the main menu** to create test users if needed

## 🎮 How to Use

### Main Menu Options

1. **🎯 Run Full Security Simulation**
   - Executes a comprehensive simulation with normal and malicious attempts
   - Generates real-time security analysis
   - Produces detailed reports

2. **🔬 Demonstrate SQL Injection Vulnerabilities**
   - Shows side-by-side comparison of vulnerable vs secure code
   - Educational test suite with various attack patterns

3. **🧪 Run Custom Attack Tests**
   - Interactive testing with custom payloads
   - Real-time vulnerability analysis

4. **📊 Show Real-time Security Dashboard**
   - Live monitoring of security events
   - Activity trends and threat indicators

5. **📈 Generate Comprehensive Security Report**
   - Detailed analysis of security events
   - Export capabilities (CSV, JSON)

### Educational Features

- **Safe Learning Environment**: All attacks are contained within the simulator
- **Comparative Analysis**: See vulnerable vs secure implementations side-by-side
- **Pattern Recognition**: Learn to identify common attack signatures
- **Defense Mechanisms**: Understand how proper security measures work

## 🔒 Security Features Demonstrated

### Attack Patterns Covered
- **Boolean-based injection**: `' OR '1'='1`
- **Comment injection**: `admin'--`
- **Union-based attacks**: `' UNION SELECT username, password FROM users--`
- **Time-based blind injection**: `'; WAITFOR DELAY '00:00:05'--`
- **Error-based injection**: `' AND (SELECT COUNT(*) FROM sysobjects) > 0--`
- **Destructive commands**: `'; DROP TABLE Users--`

### Defense Techniques Implemented
- ✅ **Parameterized Queries** using `SqlCommand.Parameters`
- ✅ **Input Validation** with pattern detection
- ✅ **Least Privilege** database access
- ✅ **Real-time Monitoring** and alerting
- ✅ **Brute Force Detection** with IP blocking
- ✅ **Comprehensive Logging** for audit trails

## 📊 Sample Output

```
🛡️ SQL INJECTION CYBERSECURITY SIMULATOR - SECURITY REPORT
================================================================================
Report Generated: 2024-01-15 14:30:22
Analysis Period: 1.0 hours (2024-01-15 13:30 to 2024-01-15 14:30)

📊 SECURITY OVERVIEW
--------------------------------------------------
Total Login Attempts: 30
├── Successful Logins: 8 (26.7%)
├── Failed Attempts: 22 (73.3%)
└── Injection Attempts: 12 (40.0%)

🔍 THREAT DETECTION
--------------------------------------------------
Security Alerts: 15
├── Critical: 3 🔴
├── High: 5 🟠
├── Medium: 4 🟡
└── Low: 3 🟢

Detection Effectiveness: 95.2%
```

## 🧪 Educational Scenarios

### Scenario 1: Basic Authentication Bypass
```csharp
// VULNERABLE (DON'T DO THIS):
string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";

// Input: username = "admin' OR '1'='1'--"
// Result: Bypasses authentication

// SECURE (CORRECT APPROACH):
string query = "SELECT * FROM Users WHERE Username = @username AND Password = @password";
command.Parameters.AddWithValue("@username", username);
command.Parameters.AddWithValue("@password", password);
```

### Scenario 2: Data Extraction Attack
```sql
-- Attacker input: ' UNION SELECT username, password FROM users--
-- Resulting query attempts to extract sensitive data
-- Secure implementation prevents this with parameterization
```

## 📈 Reporting & Analytics

The simulator generates comprehensive reports including:
- Attack attempt statistics
- Top attack patterns and frequencies
- Source IP analysis
- Security alert summaries
- Performance metrics
- Actionable security recommendations

Reports can be exported to:
- CSV format for spreadsheet analysis
- JSON format for programmatic processing
- Console output for immediate review

## 🛠️ Technical Implementation

### Database Schema
- **Users**: Secure user accounts with BCrypt password hashing
- **LoginAttempts**: Comprehensive logging of all authentication attempts
- **Alerts**: Security event tracking with severity levels

### Security Analysis Engine
- Pattern-based injection detection
- Behavioral analysis for brute force attacks
- Real-time threat scoring
- Automated alert generation

### Performance Considerations
- Efficient database indexing
- Connection pooling
- Asynchronous operations
- Memory-conscious reporting

## 🎓 Learning Outcomes

After using this simulator, you will understand:

1. **SQL Injection Mechanics**
   - How malicious input alters database queries
   - Common attack vectors and payloads
   - Business impact of successful attacks

2. **Secure Development Practices**
   - Parameterized query implementation
   - Input validation strategies
   - Error handling best practices

3. **Security Architecture**
   - Defense-in-depth principles
   - Monitoring and alerting systems
   - Incident response procedures

4. **Risk Assessment**
   - Vulnerability impact analysis
   - Threat pattern recognition
   - Security metric interpretation

## ⚠️ Important Disclaimers

### Educational Use Only
This tool is designed **exclusively for educational purposes**:
- Learning secure coding practices
- Understanding vulnerability concepts
- Training security professionals
- Supporting cybersecurity education

### Prohibited Uses
**DO NOT** use this simulator to:
- Attack real systems or applications
- Test security without explicit permission
- Harm individuals, organizations, or systems
- Violate any laws or regulations

### Responsible Disclosure
If you discover real vulnerabilities during your learning:
- Report them through proper channels
- Follow responsible disclosure practices
- Protect sensitive information
- Respect affected organizations

## 🤝 Contributing

This is an educational project. If you'd like to contribute:
1. Ensure all contributions maintain the educational focus
2. Add comprehensive documentation for new features
3. Include security considerations in all code
4. Follow the existing code structure and patterns

## 📚 Additional Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Microsoft Security Development Lifecycle](https://www.microsoft.com/en-us/securityengineering/sdl/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## 📝 License

This educational project is provided as-is for learning purposes. Please use responsibly and ethically.

---

**Remember**: The best defense against SQL injection is to never concatenate user input directly into SQL queries. Always use parameterized queries and validate all inputs! 🛡️