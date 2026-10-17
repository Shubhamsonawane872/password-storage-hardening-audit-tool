"""API token generation and management for programmatic access"""
import secrets
import hashlib
from datetime import datetime, timedelta
from flask import current_app
from app.db import get_db_connection


class APITokenManager:
    """Manage API tokens for authenticated API access"""
    
    @staticmethod
    def generate_token(user_id: int, name: str = "API Token", expires_in_days: int = 90) -> str:
        """
        Generate a new API token for a user
        
        Args:
            user_id: User ID
            name: Token name/description
            expires_in_days: Token expiration in days
            
        Returns:
            Generated token string
        """
        # Generate random token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store in database
        db = get_db_connection(current_app.config['DATABASE_PATH'])
        cursor = db.cursor()
        
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        cursor.execute('''
            INSERT INTO api_tokens (user_id, token_hash, name, expires_at, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, token_hash, name, expires_at.isoformat()))
        
        db.commit()
        db.close()
        
        return token
    
    @staticmethod
    def verify_token(token: str) -> dict:
        """
        Verify an API token and return associated user
        
        Args:
            token: API token to verify
            
        Returns:
            Dict with user_id if valid, None if invalid/expired
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        db = get_db_connection(current_app.config['DATABASE_PATH'])
        cursor = db.cursor()
        
        cursor.execute('''
            SELECT user_id, expires_at FROM api_tokens 
            WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP
        ''', (token_hash,))
        
        result = cursor.fetchone()
        db.close()
        
        if result:
            return {'user_id': result['user_id'], 'valid': True}
        
        return {'valid': False}
    
    @staticmethod
    def list_tokens(user_id: int) -> list:
        """List all API tokens for a user"""
        db = get_db_connection(current_app.config['DATABASE_PATH'])
        cursor = db.cursor()
        
        cursor.execute('''
            SELECT id, name, created_at, expires_at, last_used_at
            FROM api_tokens
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (user_id,))
        
        tokens = [dict(row) for row in cursor.fetchall()]
        db.close()
        
        return tokens
    
    @staticmethod
    def revoke_token(user_id: int, token_id: int) -> bool:
        """Revoke an API token"""
        db = get_db_connection(current_app.config['DATABASE_PATH'])
        cursor = db.cursor()
        
        cursor.execute('''
            DELETE FROM api_tokens
            WHERE id = ? AND user_id = ?
        ''', (token_id, user_id))
        
        db.commit()
        db.close()
        
        return cursor.rowcount > 0
    
    @staticmethod
    def update_last_used(token: str):
        """Update last used timestamp for a token"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        db = get_db_connection(current_app.config['DATABASE_PATH'])
        cursor = db.cursor()
        
        cursor.execute('''
            UPDATE api_tokens
            SET last_used_at = CURRENT_TIMESTAMP
            WHERE token_hash = ?
        ''', (token_hash,))
        
        db.commit()
        db.close()


def create_api_tokens_table(cursor):
    """Create api_tokens table"""
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            last_used_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)')
