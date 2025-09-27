-- Create Users table
CREATE TABLE Users (
    Id INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(255) NOT NULL,
    Email NVARCHAR(100),
    IsActive BIT DEFAULT 1,
    CreatedAt DATETIME2 DEFAULT GETDATE()
);

-- Create LoginAttempts table
CREATE TABLE LoginAttempts (
    Id INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL,
    IpAddress NVARCHAR(45),
    IsSuccessful BIT NOT NULL,
    IsInjection BIT DEFAULT 0,
    QueryAttempted NVARCHAR(MAX),
    ResponseTime INT,
    AttemptTime DATETIME2 DEFAULT GETDATE()
);

-- Create Alerts table
CREATE TABLE Alerts (
    Id INT PRIMARY KEY IDENTITY(1,1),
    AlertType NVARCHAR(50) NOT NULL,
    Severity NVARCHAR(20) NOT NULL,
    Message NVARCHAR(500) NOT NULL,
    Details NVARCHAR(MAX),
    IpAddress NVARCHAR(45),
    Username NVARCHAR(50),
    IsResolved BIT DEFAULT 0,
    AlertTime DATETIME2 DEFAULT GETDATE()
);

-- Insert some test data
INSERT INTO Users (Username, PasswordHash, Email) VALUES 
('admin', '$2a$11$dummy.hash.for.admin.password123456789012345678901', 'admin@company.com'),
('user1', '$2a$11$dummy.hash.for.user1.password123456789012345678901', 'user1@company.com'),
('testuser', '$2a$11$dummy.hash.for.test.password123456789012345678901', 'test@company.com');

-- Insert some sample login attempts
INSERT INTO LoginAttempts (Username, IpAddress, IsSuccessful, IsInjection, QueryAttempted) VALUES
('admin', '192.168.1.100', 1, 0, 'Normal login'),
('user1', '192.168.1.101', 0, 1, 'SELECT * FROM Users WHERE Username = ''admin'' OR ''1''=''1'' --'),
('testuser', '192.168.1.102', 1, 0, 'Normal login'),
('hacker', '10.0.0.1', 0, 1, 'SELECT * FROM Users WHERE Username = '''' UNION SELECT 1,2,3,4,5,6 --');

PRINT 'Database schema created successfully!';