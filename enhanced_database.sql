-- SQL Injection Practice Database Setup
-- This creates a database with sample data for SQL injection testing

-- Create and use the database
DROP DATABASE IF EXISTS user_auth;
CREATE DATABASE user_auth;
USE user_auth;

-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user', 'moderator') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    phone VARCHAR(20),
    address TEXT,
    
    -- Indexes for better performance
    INDEX idx_email (email),
    INDEX idx_username (username),
    INDEX idx_role (role)
);

-- Create additional tables for more realistic SQL injection practice
CREATE TABLE user_profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    bio TEXT,
    website VARCHAR(255),
    social_media JSON,
    profile_picture VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100),
    ip_address VARCHAR(45),
    success BOOLEAN,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT
);

CREATE TABLE sensitive_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    credit_card_number VARCHAR(20),
    ssn VARCHAR(11),
    secret_notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert sample users with different roles
INSERT INTO users (username, email, password, role, first_name, last_name, phone, address, is_active) VALUES 
-- Admin users (password: admin123)
('admin', 'admin@example.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', 'John', 'Administrator', '555-0001', '123 Admin St, City, State', 1),
('superadmin', 'superadmin@company.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', 'Jane', 'Super', '555-0002', '456 Super Ave, City, State', 1),

-- Regular users (password: password123)
('testuser', 'test@example.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user', 'Test', 'User', '555-0003', '789 Test Rd, City, State', 1),
('johndoe', 'john.doe@email.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user', 'John', 'Doe', '555-0004', '321 User Blvd, City, State', 1),
('janedoe', 'jane.doe@email.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user', 'Jane', 'Doe', '555-0005', '654 Jane St, City, State', 1),
('alice', 'alice@company.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user', 'Alice', 'Smith', '555-0006', '987 Alice Way, City, State', 1),
('bob', 'bob@example.org', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user', 'Bob', 'Johnson', '555-0007', '147 Bob Lane, City, State', 1),

-- Moderators (password: mod123)
('moderator1', 'mod1@example.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'moderator', 'Mike', 'Moderator', '555-0008', '258 Mod Plaza, City, State', 1),
('moderator2', 'mod2@company.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'moderator', 'Sarah', 'Moderator', '555-0009', '369 Mod Circle, City, State', 1),

-- Inactive user
('inactive', 'inactive@example.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user', 'Inactive', 'User', '555-0010', '741 Inactive Dr, City, State', 0);

-- Insert user profiles
INSERT INTO user_profiles (user_id, bio, website, social_media, profile_picture) VALUES 
(1, 'System administrator with 10+ years experience', 'https://admin.example.com', '{"twitter": "@admin", "linkedin": "admin"}', 'admin.jpg'),
(2, 'Senior system administrator', 'https://superadmin.company.com', '{"twitter": "@superadmin"}', 'superadmin.jpg'),
(3, 'Test user account for development', NULL, NULL, 'test.jpg'),
(4, 'Software developer and tech enthusiast', 'https://johndoe.dev', '{"github": "johndoe", "twitter": "@johndoe"}', 'john.jpg'),
(5, 'UX Designer with passion for clean interfaces', 'https://janedoe.design', '{"behance": "janedoe", "dribbble": "janedoe"}', 'jane.jpg'),
(6, 'Data scientist and AI researcher', 'https://alice-research.com', '{"researchgate": "alice", "orcid": "alice"}', 'alice.jpg'),
(7, 'Network security specialist', NULL, '{"linkedin": "bob-security"}', 'bob.jpg'),
(8, 'Community moderator', NULL, NULL, 'mod1.jpg'),
(9, 'Senior community moderator', NULL, NULL, 'mod2.jpg');

-- Insert some login attempts (for realistic data)
INSERT INTO login_attempts (email, ip_address, success, attempted_at, user_agent) VALUES 
('admin@example.com', '192.168.1.100', 1, '2025-08-22 10:30:00', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'),
('test@example.com', '192.168.1.101', 1, '2025-08-22 11:15:00', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'),
('hacker@evil.com', '10.0.0.1', 0, '2025-08-22 12:00:00', 'sqlmap/1.0'),
('admin@example.com', '10.0.0.1', 0, '2025-08-22 12:01:00', 'sqlmap/1.0'),
('john.doe@email.com', '192.168.1.102', 1, '2025-08-22 13:45:00', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)');

-- Insert sensitive data (for demonstrating data extraction attacks)
INSERT INTO sensitive_data (user_id, credit_card_number, ssn, secret_notes) VALUES 
(1, '4532-1234-5678-9012', '123-45-6789', 'Admin master key: ADM1N_K3Y_2025'),
(2, '5555-4444-3333-2222', '987-65-4321', 'Backup server password: B@ckup2025!'),
(3, '4111-1111-1111-1111', '555-44-3333', 'Test account - no real data'),
(4, '4000-0000-0000-0002', '111-22-3333', 'Personal API key: pk_test_123456789'),
(5, '5200-0000-0000-0000', '444-55-6666', 'Design portfolio password: Des1gn@2025'),
(6, '4242-4242-4242-4242', '777-88-9999', 'Research data encryption key: R3s3@rch_K3y'),
(7, '4000-0000-0000-0051', '222-33-4444', 'Network security codes: SEC_2025_ALPHA');

-- Create a view for easier data access (another target for injection)
CREATE VIEW user_summary AS 
SELECT 
    u.id,
    u.username,
    u.email,
    u.role,
    u.first_name,
    u.last_name,
    u.is_active,
    up.bio
FROM users u
LEFT JOIN user_profiles up ON u.id = up.user_id;

-- Show table structures for reference
SHOW TABLES;
DESCRIBE users;
DESCRIBE user_profiles;
DESCRIBE sensitive_data;
