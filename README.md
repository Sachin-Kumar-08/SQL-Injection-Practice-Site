# PHP Login and Signup System

A complete PHP authentication system with login, signup, and dashboard functionality.

## 📁 Files Included

- **config.php** - Database configuration and connection
- **UserAuth.php** - User authentication class with login/signup methods
- **login.php** - Login page with form handling
- **signup.php** - Registration page with validation
- **dashboard.php** - Protected dashboard page for logged-in users
- **database.sql** - MySQL database schema

## 🚀 Setup Instructions

### 1. Database Setup
1. Create a MySQL database named `user_auth`
2. Run the SQL script in `database.sql` to create the users table
3. Update database credentials in `config.php` if needed

### 2. Configuration
Edit `config.php` and update these constants:
```php
define('DB_HOST', 'localhost');     // Your database host
define('DB_USER', 'root');          // Your database username
define('DB_PASS', '');              // Your database password
define('DB_NAME', 'user_auth');     // Your database name
```

### 3. Web Server
1. Place all files in your web server directory (e.g., `htdocs` for XAMPP)
2. Start your web server (Apache) and MySQL
3. Access the application via `http://localhost/login.php`

## 🔧 Features

### ✅ User Registration
- Username validation (minimum 3 characters)
- Email format validation
- Password strength requirements (minimum 6 characters)
- Password confirmation
- Duplicate user checking
- Secure password hashing

### ✅ User Login
- Email and password authentication
- Password verification
- Session management
- Remember me functionality
- Automatic redirect to dashboard

### ✅ Security Features
- Password hashing with PHP's `password_hash()`
- SQL injection prevention with prepared statements
- XSS protection with `htmlspecialchars()`
- Session-based authentication
- Protected routes

### ✅ User Interface
- Responsive design for all devices
- Modern gradient styling
- Form validation with error messages
- Loading animations
- Smooth transitions and hover effects

## 📱 Pages Overview

### Login Page (`login.php`)
- Email and password fields
- Form validation
- Error/success messages
- Link to signup page
- Forgot password placeholder

### Signup Page (`signup.php`)
- Username, email, and password fields
- Password confirmation
- Real-time validation
- Terms of service links
- Link to login page

### Dashboard (`dashboard.php`)
- Welcome message with user info
- Navigation with logout option
- Feature cards and statistics
- Responsive layout
- Protected route (requires login)

## 🛠️ Technical Details

### Database Schema
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

### Security Measures
- **Password Hashing**: Uses `password_hash()` with default algorithm
- **Prepared Statements**: All database queries use PDO prepared statements
- **Input Sanitization**: All user inputs are sanitized and validated
- **Session Security**: Proper session management and validation

## 🧪 Testing

### Test Account
A test user is included in the database script:
- **Email**: test@example.com
- **Password**: password123

### Manual Testing
1. Register a new account via `signup.php`
2. Login with your credentials via `login.php`
3. Access the dashboard and test logout functionality

## 🔗 File Dependencies

```
config.php (database connection)
    ↓
UserAuth.php (authentication class)
    ↓
login.php, signup.php, dashboard.php (main pages)
```

## 📝 Customization

### Styling
- Modify the CSS in each PHP file to match your brand
- All styles are embedded for easy customization
- Uses modern CSS with gradients and animations

### Functionality
- Add password reset functionality
- Implement email verification
- Add user roles and permissions
- Integrate with external authentication providers

## ⚠️ Important Notes

1. **Production Security**: 
   - Change default database credentials
   - Use HTTPS in production
   - Implement rate limiting for login attempts
   - Add CSRF protection

2. **Database**: 
   - Ensure MySQL is running
   - Grant proper permissions to the database user
   - Consider using environment variables for credentials

3. **Error Handling**: 
   - Check PHP error logs for debugging
   - Ensure PDO extension is enabled
   - Verify database connection settings

## 🚀 Next Steps

- Add email verification for new accounts
- Implement password reset functionality
- Add user profile management
- Integrate with third-party authentication (Google, Facebook)
- Add admin panel for user management
- Implement API endpoints for mobile apps

## 📞 Support

If you encounter any issues:
1. Check database connection in `config.php`
2. Verify web server is running PHP 7.0+
3. Ensure MySQL/MariaDB is running
4. Check file permissions on your web server
