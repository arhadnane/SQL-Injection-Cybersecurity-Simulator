-- SQL Injection Simulator Database Schema
-- Educational cybersecurity project - for learning purposes only

-- Drop existing tables if they exist (for development)
IF OBJECT_ID('Alerts', 'U') IS NOT NULL DROP TABLE Alerts;
IF OBJECT_ID('LoginAttempts', 'U') IS NOT NULL DROP TABLE LoginAttempts;
IF OBJECT_ID('Users', 'U') IS NOT NULL DROP TABLE Users;

-- Create Users table for authentication testing
CREATE TABLE Users (
    UserId INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    CreatedDate DATETIME DEFAULT GETDATE(),
    IsActive BIT DEFAULT 1,
    LastLoginDate DATETIME NULL,
    FailedLoginCount INT DEFAULT 0
);

-- Create index for faster username lookups
CREATE INDEX IX_Users_Username ON Users(Username);

-- Create LoginAttempts table to track all authentication attempts
CREATE TABLE LoginAttempts (
    AttemptId INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(255),              -- Might contain injection payloads
    AttemptTime DATETIME DEFAULT GETDATE(),
    InputPayload NVARCHAR(MAX),          -- Raw input received (for analysis)
    PasswordInput NVARCHAR(MAX),         -- Raw password input (for analysis)
    IsSuccessful BIT NOT NULL DEFAULT 0,
    IsInjection BIT DEFAULT 0,           -- Detected as injection attempt
    IpAddress NVARCHAR(45) DEFAULT '127.0.0.1',
    UserAgent NVARCHAR(255) DEFAULT 'SQLInjectionSimulator',
    ResponseTime INT DEFAULT 0,          -- Response time in milliseconds
    QueryExecuted NVARCHAR(MAX)          -- The actual query that was executed
);

-- Create indexes for better query performance
CREATE INDEX IX_LoginAttempts_Username ON LoginAttempts(Username);
CREATE INDEX IX_LoginAttempts_AttemptTime ON LoginAttempts(AttemptTime);
CREATE INDEX IX_LoginAttempts_IsInjection ON LoginAttempts(IsInjection);

-- Create Alerts table for security monitoring
CREATE TABLE Alerts (
    AlertId INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(255),
    AlertTime DATETIME DEFAULT GETDATE(),
    AlertType NVARCHAR(100) NOT NULL,    -- e.g., 'SQL_INJECTION', 'BRUTE_FORCE', 'SUSPICIOUS_PATTERN'
    Severity NVARCHAR(20) DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
    Details NVARCHAR(MAX),
    TriggerCondition NVARCHAR(255),      -- What triggered this alert
    IsResolved BIT DEFAULT 0,
    ResolvedDate DATETIME NULL,
    ResolvedBy NVARCHAR(50) NULL
);

-- Create indexes for alert management
CREATE INDEX IX_Alerts_AlertTime ON Alerts(AlertTime);
CREATE INDEX IX_Alerts_AlertType ON Alerts(AlertType);
CREATE INDEX IX_Alerts_Severity ON Alerts(Severity);
CREATE INDEX IX_Alerts_IsResolved ON Alerts(IsResolved);

-- Create a view for security analysis
CREATE VIEW SecurityAnalysisView AS
SELECT 
    la.AttemptTime,
    la.Username,
    la.InputPayload,
    la.IsSuccessful,
    la.IsInjection,
    la.ResponseTime,
    CASE 
        WHEN la.IsInjection = 1 THEN 'Injection Attempt'
        WHEN la.IsSuccessful = 0 THEN 'Failed Login'
        ELSE 'Successful Login'
    END as AttemptType
FROM LoginAttempts la
WHERE la.AttemptTime >= DATEADD(day, -30, GETDATE());

-- Create stored procedure for secure user authentication
CREATE PROCEDURE sp_AuthenticateUser
    @Username NVARCHAR(50),
    @PasswordHash NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;
    
    DECLARE @UserId INT;
    DECLARE @IsActive BIT;
    DECLARE @FailedCount INT;
    
    -- Check if user exists and account is active
    SELECT @UserId = UserId, @IsActive = IsActive, @FailedCount = FailedLoginCount
    FROM Users 
    WHERE Username = @Username AND PasswordHash = @PasswordHash;
    
    -- Return result
    IF @UserId IS NOT NULL AND @IsActive = 1 AND @FailedCount < 5
    BEGIN
        -- Update last login date and reset failed count
        UPDATE Users 
        SET LastLoginDate = GETDATE(), FailedLoginCount = 0 
        WHERE UserId = @UserId;
        
        SELECT @UserId as UserId, 'SUCCESS' as Result;
    END
    ELSE IF @FailedCount >= 5
    BEGIN
        SELECT NULL as UserId, 'ACCOUNT_LOCKED' as Result;
    END
    ELSE
    BEGIN
        -- Increment failed login count for existing users
        IF EXISTS (SELECT 1 FROM Users WHERE Username = @Username)
        BEGIN
            UPDATE Users 
            SET FailedLoginCount = FailedLoginCount + 1 
            WHERE Username = @Username;
        END
        
        SELECT NULL as UserId, 'INVALID_CREDENTIALS' as Result;
    END
END;

-- Create stored procedure for logging security events
CREATE PROCEDURE sp_LogSecurityEvent
    @Username NVARCHAR(255),
    @AlertType NVARCHAR(100),
    @Severity NVARCHAR(20),
    @Details NVARCHAR(MAX),
    @TriggerCondition NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;
    
    INSERT INTO Alerts (Username, AlertType, Severity, Details, TriggerCondition, AlertTime)
    VALUES (@Username, @AlertType, @Severity, @Details, @TriggerCondition, GETDATE());
END;

-- Create function to detect suspicious patterns
CREATE FUNCTION fn_IsSuspiciousInput(@Input NVARCHAR(MAX))
RETURNS BIT
AS
BEGIN
    DECLARE @IsSuspicious BIT = 0;
    
    -- Check for common SQL injection patterns
    IF @Input LIKE '%''%OR%''%' OR
       @Input LIKE '%---%' OR
       @Input LIKE '%/*%*/%' OR
       @Input LIKE '%UNION%SELECT%' OR
       @Input LIKE '%DROP%TABLE%' OR
       @Input LIKE '%INSERT%INTO%' OR
       @Input LIKE '%UPDATE%SET%' OR
       @Input LIKE '%DELETE%FROM%' OR
       @Input LIKE '%xp_%' OR
       @Input LIKE '%sp_%' OR
       @Input LIKE '%;%' OR
       @Input LIKE '%=%=%'
    BEGIN
        SET @IsSuspicious = 1;
    END
    
    RETURN @IsSuspicious;
END;

-- Create trigger to automatically detect injection attempts
CREATE TRIGGER tr_DetectInjection
ON LoginAttempts
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;
    
    UPDATE la
    SET IsInjection = 1
    FROM LoginAttempts la
    INNER JOIN inserted i ON la.AttemptId = i.AttemptId
    WHERE dbo.fn_IsSuspiciousInput(i.InputPayload) = 1 
       OR dbo.fn_IsSuspiciousInput(i.PasswordInput) = 1;
    
    -- Auto-generate alerts for detected injections
    INSERT INTO Alerts (Username, AlertType, Severity, Details, TriggerCondition)
    SELECT 
        i.Username,
        'SQL_INJECTION',
        'HIGH',
        'Potential SQL injection detected in input: ' + ISNULL(i.InputPayload, '') + ' | Password: ' + ISNULL(i.PasswordInput, ''),
        'Automatic detection via trigger'
    FROM inserted i
    INNER JOIN LoginAttempts la ON i.AttemptId = la.AttemptId
    WHERE la.IsInjection = 1;
END;

PRINT 'Database schema created successfully for SQL Injection Simulator';
PRINT 'Tables created: Users, LoginAttempts, Alerts';
PRINT 'Views created: SecurityAnalysisView';
PRINT 'Stored procedures created: sp_AuthenticateUser, sp_LogSecurityEvent';
PRINT 'Functions created: fn_IsSuspiciousInput';
PRINT 'Triggers created: tr_DetectInjection';