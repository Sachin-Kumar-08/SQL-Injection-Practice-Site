<?php
require_once 'config.php';
require_once 'VulnerableUserAuth.php';

$auth = new VulnerableUserAuth();

// Redirect if not logged in
if (!$auth->isLoggedIn()) {
    header('Location: vulnerable_login.php');
    exit();
}

$user = $auth->getCurrentUser();

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $auth->logout();
    header('Location: vulnerable_login.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Dashboard - SQL Injection Practice</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            min-height: 100vh;
        }

        .navbar {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        .nav-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
        }

        .nav-brand {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .nav-user {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
        }

        .username {
            font-weight: 500;
            margin-bottom: 0.2rem;
        }

        .user-email {
            font-size: 0.8rem;
            opacity: 0.8;
        }

        .logout-btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.3);
            padding: 0.5rem 1rem;
            border-radius: 5px;
            text-decoration: none;
            transition: all 0.3s ease;
            font-size: 0.9rem;
        }

        .logout-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-1px);
        }

        .warning-banner {
            background: #fff3cd;
            border: 2px solid #ffeaa7;
            color: #856404;
            padding: 1rem;
            text-align: center;
            font-weight: 600;
            border-radius: 0;
        }

        .main-content {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
        }

        .success-card {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
            text-align: center;
            border-left: 5px solid #e74c3c;
        }

        .success-card h1 {
            color: #e74c3c;
            margin-bottom: 1rem;
            font-size: 2rem;
        }

        .success-card p {
            color: #666;
            font-size: 1.1rem;
            margin-bottom: 1.5rem;
        }

        .learning-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .learning-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }

        .learning-card:hover {
            transform: translateY(-5px);
        }

        .learning-card h3 {
            color: #e74c3c;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }

        .learning-card p {
            color: #666;
            margin-bottom: 1rem;
            line-height: 1.6;
        }

        .code-example {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 1rem;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin: 1rem 0;
            overflow-x: auto;
        }

        .prevention-tips {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .prevention-tips h3 {
            color: #155724;
            margin-bottom: 1rem;
        }

        .prevention-tips ul {
            color: #155724;
            padding-left: 1.5rem;
        }

        .prevention-tips li {
            margin-bottom: 0.5rem;
        }

        .resources-section {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
        }

        .resources-section h3 {
            color: #333;
            margin-bottom: 1rem;
        }

        .resource-link {
            display: inline-block;
            background: #e74c3c;
            color: white;
            padding: 0.6rem 1.2rem;
            border-radius: 5px;
            text-decoration: none;
            margin: 0.5rem 0.5rem 0.5rem 0;
            transition: all 0.3s ease;
        }

        .resource-link:hover {
            background: #c0392b;
            transform: translateY(-2px);
        }

        .footer {
            text-align: center;
            padding: 2rem;
            color: #666;
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .navbar {
                padding: 1rem;
            }
            
            .nav-container {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .main-content {
                padding: 0 1rem;
                margin: 1rem auto;
            }
            
            .success-card h1 {
                font-size: 1.5rem;
            }
            
            .learning-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="warning-banner">
        ⚠️ <strong>EDUCATIONAL ENVIRONMENT:</strong> You successfully exploited SQL injection vulnerabilities! This is for learning purposes only.
    </div>

    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">🔓 Vulnerable Dashboard</div>
            <div class="nav-user">
                <div class="user-info">
                    <div class="username">Hacker: <?php echo htmlspecialchars($user['username']); ?>!</div>
                    <div class="user-email"><?php echo htmlspecialchars($user['email']); ?></div>
                </div>
                <a href="?action=logout" class="logout-btn">Logout</a>
            </div>
        </div>
    </nav>

    <div class="main-content">
        <div class="success-card">
            <h1>🎯 SQL Injection Success!</h1>
            <p>Congratulations! You successfully bypassed authentication using SQL injection. This demonstrates how dangerous vulnerable code can be.</p>
        </div>

        <div class="learning-grid">
            <div class="learning-card">
                <h3>🔍 What Just Happened?</h3>
                <p>You exploited a SQL injection vulnerability by manipulating the login query. The application didn't properly validate your input, allowing you to alter the SQL logic.</p>
                <div class="code-example">
-- Original intended query:
SELECT * FROM users 
WHERE email = 'user@email.com' 
AND password = 'userpassword'

-- Your injected query:
SELECT * FROM users 
WHERE email = 'admin@example.com' 
OR '1'='1' AND password = 'anything'
                </div>
            </div>
            
            <div class="learning-card">
                <h3>⚠️ Types of SQL Injection</h3>
                <p>There are several types of SQL injection attacks:</p>
                <ul style="text-align: left; color: #666; padding-left: 1.5rem;">
                    <li><strong>Boolean-based:</strong> Using OR conditions to bypass authentication</li>
                    <li><strong>Union-based:</strong> Extracting data from other tables</li>
                    <li><strong>Time-based:</strong> Using delays to infer information</li>
                    <li><strong>Error-based:</strong> Using database errors to extract information</li>
                </ul>
            </div>
            
            <div class="learning-card">
                <h3>🛡️ How to Prevent This</h3>
                <p>SQL injection can be prevented by:</p>
                <div class="code-example">
// BAD - Vulnerable to injection
$query = "SELECT * FROM users WHERE email = '$email'";

// GOOD - Using prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
                </div>
            </div>
            
            <div class="learning-card">
                <h3>🔬 Practice More</h3>
                <p>Try different injection techniques:</p>
                <ul style="text-align: left; color: #666; padding-left: 1.5rem;">
                    <li>Extract user passwords using UNION</li>
                    <li>List all database tables</li>
                    <li>Bypass different types of filters</li>
                    <li>Practice on the search functionality</li>
                </ul>
                <a href="vulnerable_login.php?action=logout" class="resource-link">Try Again</a>
            </div>
        </div>

        <div class="prevention-tips">
            <h3>🛡️ Security Best Practices</h3>
            <ul>
                <li><strong>Use Prepared Statements:</strong> Always use parameterized queries with bound parameters</li>
                <li><strong>Input Validation:</strong> Validate and sanitize all user inputs</li>
                <li><strong>Least Privilege:</strong> Database users should have minimal necessary permissions</li>
                <li><strong>Error Handling:</strong> Don't expose database errors to users</li>
                <li><strong>Web Application Firewall:</strong> Use WAF to filter malicious requests</li>
                <li><strong>Regular Updates:</strong> Keep database software and frameworks updated</li>
            </ul>
        </div>

        <div class="resources-section">
            <h3>📚 Learning Resources</h3>
            <p>Continue learning about web security:</p>
            <a href="login.php" class="resource-link">🔒 View Secure Version</a>
            <a href="https://owasp.org/www-project-top-ten/" class="resource-link" target="_blank">OWASP Top 10</a>
            <a href="https://portswigger.net/web-security/sql-injection" class="resource-link" target="_blank">PortSwigger SQL Injection</a>
            <a href="https://www.w3schools.com/sql/sql_injection.asp" class="resource-link" target="_blank">W3Schools SQL Injection</a>
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2025 SQL Injection Practice Environment - Educational Use Only</p>
        <p><strong>Remember:</strong> Never use these techniques on systems you don't own or without permission!</p>
    </div>
</body>
</html>
