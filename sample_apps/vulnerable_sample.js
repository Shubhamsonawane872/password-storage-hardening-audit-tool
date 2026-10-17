/**
 * VULNERABLE SAMPLE CODE - FOR TESTING ONLY
 * This JavaScript file contains intentional security vulnerabilities.
 * DO NOT USE IN PRODUCTION!
 */

// VULNERABILITY: PWD001 - Plaintext password storage
const insecureLogin = (username, password) => {
    const users = {
        'admin': 'AdminPassword123',  // VULNERABLE: plaintext password
        'user': 'UserPassword456'      // VULNERABLE: plaintext password
    };
    return users[username] === password;
};

// VULNERABILITY: PWD004 - Hardcoded API keys and secrets
const API_KEY = 'sk_test_REDACTED';                    // VULNERABLE
const DATABASE_PASSWORD = 'prod_db_password_12345';     // VULNERABLE
const JWT_SECRET = 'super_secret_jwt_key_12345';        // VULNERABLE

// VULNERABILITY: PWD002 - MD5 hashing (insecure)
// Note: This requires md5 library
const md5 = require('md5');

const storePasswordMD5 = (password) => {
    return md5(password);  // VULNERABLE: MD5 is broken
};

// VULNERABILITY: PWD003 - SHA1 hashing (weak)
const crypto = require('crypto');

const storePasswordSHA1 = (password) => {
    return crypto.createHash('sha1').update(password).digest('hex');  // VULNERABLE
};

// VULNERABILITY: PWD005 - Unsalted SHA256
const storePasswordUnsalted = (password) => {
    return crypto.createHash('sha256').update(password).digest('hex');  // VULNERABLE: no salt
};

// VULNERABILITY: PWD001 - Config with passwords
const config = {
    database: {
        host: 'localhost',
        user: 'admin',
        password: 'secretPassword123'  // VULNERABLE: hardcoded
    },
    api: {
        token: 'token_xyz789',  // VULNERABLE: hardcoded
        secret: 'api_secret_abc123'  // VULNERABLE: hardcoded
    }
};

// VULNERABILITY: Insecure user storage
class VulnerableUserManager {
    constructor() {
        this.users = {};
    }
    
    registerUser(username, password) {
        // VULNERABLE: storing password directly
        this.users[username] = password;
        return true;
    }
    
    authenticate(username, password) {
        // VULNERABLE: comparing plaintext passwords
        return this.users[username] === password;
    }
    
    getPassword(username) {
        // VULNERABLE: exposing password
        return this.users[username];
    }
}

// VULNERABILITY: Storing credentials in localStorage (for web)
const saveCredentials = (email, password) => {
    localStorage.setItem('userEmail', email);
    localStorage.setItem('userPassword', password);  // VULNERABLE: never do this!
};

// VULNERABILITY: Cookie with sensitive data
const setCookie = (password) => {
    // VULNERABLE: storing password in cookie
    document.cookie = `password=${password}; path=/`;
};
