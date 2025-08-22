<?php
require_once 'config.php';
require_once 'UserAuth.php';

$auth = new UserAuth();

// Redirect if not logged in
if (!$auth->isLoggedIn()) {
    header('Location: login.php');
    exit();
}

$user = $auth->getCurrentUser();

// Handle logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $auth->logout();
    header('Location: login.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - User Authentication</title>
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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

        .main-content {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 2rem;
        }

        .welcome-card {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
            text-align: center;
        }

        .welcome-card h1 {
            color: #333;
            margin-bottom: 1rem;
            font-size: 2rem;
        }

        .welcome-card p {
            color: #666;
            font-size: 1.1rem;
            margin-bottom: 1.5rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #667eea;
        }

        .stat-card h3 {
            color: #333;
            margin-bottom: 0.5rem;
            font-size: 1.2rem;
        }

        .stat-card p {
            color: #666;
            font-size: 0.9rem;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .feature-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }

        .feature-card:hover {
            transform: translateY(-5px);
        }

        .feature-card h3 {
            color: #333;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }

        .feature-card p {
            color: #666;
            margin-bottom: 1rem;
            line-height: 1.6;
        }

        .feature-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 0.6rem 1.2rem;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s ease;
            font-size: 0.9rem;
        }

        .feature-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
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
            
            .welcome-card h1 {
                font-size: 1.5rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .features-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">User Dashboard</div>
            <div class="nav-user">
                <div class="user-info">
                    <div class="username">Welcome, <?php echo htmlspecialchars($user['username']); ?>!</div>
                    <div class="user-email"><?php echo htmlspecialchars($user['email']); ?></div>
                </div>
                <a href="?action=logout" class="logout-btn">Logout</a>
            </div>
        </div>
    </nav>

    <div class="main-content">
        <div class="welcome-card">
            <h1>🎉 Welcome to Your Dashboard!</h1>
            <p>You have successfully logged in to your account. Explore the features below to get started.</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Account Status</h3>
                <p>Your account is active and in good standing. All features are available for use.</p>
            </div>
            <div class="stat-card">
                <h3>Security Level</h3>
                <p>Your account is secured with password authentication. Consider enabling two-factor authentication for enhanced security.</p>
            </div>
            <div class="stat-card">
                <h3>Member Since</h3>
                <p>Welcome to our growing community! Thank you for joining our platform.</p>
            </div>
        </div>

        <div class="features-grid">
            <div class="feature-card">
                <h3>🔐 Account Settings</h3>
                <p>Manage your account information, update your profile, change your password, and configure security settings.</p>
                <a href="#" class="feature-btn">Manage Account</a>
            </div>
            
            <div class="feature-card">
                <h3>📊 Analytics</h3>
                <p>View detailed analytics and insights about your account activity and usage patterns.</p>
                <a href="#" class="feature-btn">View Analytics</a>
            </div>
            
            <div class="feature-card">
                <h3>🛡️ Security</h3>
                <p>Monitor login activity, manage active sessions, and configure advanced security options.</p>
                <a href="#" class="feature-btn">Security Settings</a>
            </div>
            
            <div class="feature-card">
                <h3>📱 Mobile App</h3>
                <p>Download our mobile app for convenient access to your account on the go.</p>
                <a href="#" class="feature-btn">Download App</a>
            </div>
            
            <div class="feature-card">
                <h3>💬 Support</h3>
                <p>Get help from our support team, browse our knowledge base, or contact us directly.</p>
                <a href="#" class="feature-btn">Get Support</a>
            </div>
            
            <div class="feature-card">
                <h3>🔔 Notifications</h3>
                <p>Manage your notification preferences and stay updated with important account information.</p>
                <a href="#" class="feature-btn">Manage Notifications</a>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2025 User Authentication System. Built with PHP and MySQL.</p>
    </div>
</body>
</html>
