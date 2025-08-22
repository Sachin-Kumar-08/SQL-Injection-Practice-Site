<?php
// Step 1: Database Setup
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "test_db";

// Create connection
$conn = new mysqli($servername, $username, $password);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create database and table if not exists
$conn->query("CREATE DATABASE IF NOT EXISTS $dbname");
$conn->select_db($dbname);
$conn->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL
)");
$conn->query("INSERT IGNORE INTO users (username, password) VALUES ('admin', 'password')");

// Step 2: Vulnerable Login Form
echo "<h2>Vulnerable Login Form</h2>";
echo '<form method="POST" action="">
    Username: <input type="text" name="username_vuln"><br><br>
    Password: <input type="text" name="password_vuln"><br><br>
    <input type="submit" name="submit_vuln" value="Login (Vulnerable)">
</form>';

if (isset($_POST['submit_vuln'])) {
    $username = $_POST['username_vuln'];
    $password = $_POST['password_vuln'];
    
    // Vulnerable query: Directly concatenating user input
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    echo "<p>Query: " . htmlspecialchars($query) . "</p>";
    
    $result = $conn->query($query);
    
    if ($result->num_rows > 0) {
        echo "<p style='color:green'>Vulnerable Login Successful!</p>";
    } else {
        echo "<p style='color:red'>Vulnerable Login Failed!</p>";
    }
}

// Step 3: Secure Login Form
echo "<h2>Secure Login Form</h2>";
echo '<form method="POST" action="">
    Username: <input type="text" name="username_secure"><br><br>
    Password: <input type="text" name="password_secure"><br><br>
    <input type="submit" name="submit_secure" value="Login (Secure)">
</form>';

if (isset($_POST['submit_secure'])) {
    $username = $_POST['username_secure'];
    $password = $_POST['password_secure'];
    
    // Secure query: Using prepared statements
    $query = "SELECT * FROM users WHERE username = ? AND password = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();
    
    echo "<p>Query: SELECT * FROM users WHERE username = ? AND password = ? (Params: " . htmlspecialchars($username) . ", " . htmlspecialchars($password) . ")</p>";
    
    if ($result->num_rows > 0) {
        echo "<p style='color:green'>Secure Login Successful!</p>";
    } else {
        echo "<p style='color:red'>Secure Login Failed!</p>";
    }
    $stmt->close();
}

$conn->close();
?>