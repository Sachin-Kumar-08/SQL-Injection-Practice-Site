<?php
// VULNERABLE VERSION - FOR EDUCATIONAL PURPOSES ONLY
// This file demonstrates SQL injection vulnerabilities
// NEVER use this code in production!

require_once 'config.php';

class VulnerableUserAuth {
    private $pdo;
    
    public function __construct() {
        $this->pdo = getDBConnection();
    }
    
    // VULNERABLE LOGIN - Uses string concatenation instead of prepared statements
    public function vulnerableLogin($email, $password) {
        try {
            // VULNERABILITY: Direct string concatenation allows SQL injection
            $query = "SELECT id, username, email, password FROM users WHERE email = '$email' AND password = '$password'";
            
            echo "<div style='background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px;'>";
            echo "<strong>Debug - Executed Query:</strong><br>";
            echo "<code>" . htmlspecialchars($query) . "</code>";
            echo "</div>";
            
            $stmt = $this->pdo->query($query);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user) {
                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['logged_in'] = true;
                
                return ['success' => true, 'message' => 'Login successful via SQL injection!'];
            } else {
                return ['success' => false, 'message' => 'Invalid credentials'];
            }
        } catch(PDOException $e) {
            return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
        }
    }
    
    // VULNERABLE SEARCH - Another SQL injection example
    public function searchUsers($searchTerm) {
        try {
            // VULNERABILITY: User input directly inserted into query
            $query = "SELECT username, email FROM users WHERE username LIKE '%$searchTerm%' OR email LIKE '%$searchTerm%'";
            
            echo "<div style='background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px;'>";
            echo "<strong>Debug - Search Query:</strong><br>";
            echo "<code>" . htmlspecialchars($query) . "</code>";
            echo "</div>";
            
            $stmt = $this->pdo->query($query);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            return ['success' => true, 'data' => $results];
        } catch(PDOException $e) {
            return ['success' => false, 'message' => 'Search error: ' . $e->getMessage()];
        }
    }
    
    // Check if user is logged in
    public function isLoggedIn() {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }
    
    // Logout user
    public function logout() {
        session_destroy();
        return ['success' => true, 'message' => 'Logged out successfully'];
    }
    
    // Get current user info
    public function getCurrentUser() {
        if ($this->isLoggedIn()) {
            return [
                'id' => $_SESSION['user_id'],
                'username' => $_SESSION['username'],
                'email' => $_SESSION['email']
            ];
        }
        return null;
    }
}
?>
