<?php
/**
 * VULNERABLE SAMPLE CODE - FOR TESTING ONLY
 * This PHP file contains intentional security vulnerabilities.
 * DO NOT USE IN PRODUCTION!
 */

// VULNERABILITY: PWD001 - Plaintext password storage
function insecureLogin($username, $password) {
    $users = array(
        'admin' => 'AdminPassword123',  // VULNERABLE: plaintext password
        'user' => 'UserPassword456'      // VULNERABLE: plaintext password
    );
    return isset($users[$username]) && $users[$username] === $password;
}

// VULNERABILITY: PWD004 - Hardcoded credentials
$API_KEY = 'sk_test_REDACTED';                    // VULNERABLE: hardcoded secret
$DATABASE_PASSWORD = 'prod_db_password_12345';     // VULNERABLE: hardcoded secret
$DATABASE_USER = 'admin';

// VULNERABILITY: PWD002 - MD5 hashing (cryptographically broken)
function storePasswordMD5($password) {
    return md5($password);  // VULNERABLE: MD5 is broken for passwords
}

// VULNERABILITY: PWD003 - SHA1 hashing (weak)
function storePasswordSHA1($password) {
    return sha1($password);  // VULNERABLE: SHA1 is weak for passwords
}

// VULNERABILITY: PWD005 - Unsalted SHA256
function storePasswordUnsalted($password) {
    return hash('sha256', $password);  // VULNERABLE: no salt
}

// VULNERABILITY: PWD001 - Config with plaintext passwords
$config = array(
    'database_host' => 'localhost',
    'database_user' => 'admin',
    'database_password' => 'secretPassword123'  // VULNERABLE: hardcoded
);

// VULNERABILITY: Passwords stored in session without hashing
session_start();
$_SESSION['password'] = $_POST['password'];  // VULNERABLE: storing plaintext
$_SESSION['api_key'] = 'token_xyz789';       // VULNERABLE: storing secret

// VULNERABILITY: Insecure user class
class VulnerableUser {
    private $password;
    
    public function setPassword($password) {
        // VULNERABLE: storing password directly
        $this->password = $password;
    }
    
    public function authenticate($inputPassword) {
        // VULNERABLE: comparing plaintext passwords
        return $this->password === $inputPassword;
    }
    
    public function getPassword() {
        // VULNERABLE: exposing password
        return $this->password;
    }
}

// VULNERABILITY: Storing credentials in database without hashing
function registerUser($username, $password) {
    global $pdo;
    
    // VULNERABLE: storing password directly
    $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$username, $password]);
}

// VULNERABILITY: Password in query string (very bad!)
if (isset($_GET['password'])) {
    // VULNERABLE: password exposed in URL/logs
    $password = $_GET['password'];
}

// VULNERABLE: Direct assignment without hashing
$stored_password = $user_input;

// VULNERABLE: Using crypt() with wrong algorithm
$hash = crypt($password);  // Uses default algorithm

// DO NOT DO THIS - Showing why it's vulnerable
echo "User password: " . $password;  // VULNERABLE: exposing password
