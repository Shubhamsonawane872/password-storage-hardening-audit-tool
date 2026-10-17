"""Seed demo data for testing"""
import os
import sys
from app import create_app
from app.config import Config
from app.db import get_db_connection
from app.auth.utils import hash_password
import json

def seed_demo_data():
    """Create demo users and scans"""
    print("Seeding demo data...")
    
    app = create_app(Config)
    
    with app.app_context():
        db = get_db_connection(app.config['DATABASE_PATH'])
        cursor = db.cursor()
        
        # Create demo users
        demo_users = [
            {
                'name': 'Demo User',
                'email': 'demo@example.com',
                'password': 'DemoPass123!',
                'role': 'user'
            },
            {
                'name': 'Demo Admin',
                'email': 'admin@example.com',
                'password': 'AdminPass123!',
                'role': 'admin'
            }
        ]
        
        user_ids = []
        for user in demo_users:
            password_hash = hash_password(user['password'])
            
            try:
                cursor.execute('''
                    INSERT INTO users (name, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                ''', (user['name'], user['email'], password_hash, user['role']))
                user_ids.append(cursor.lastrowid)
                print(f"Created user: {user['email']}")
            except Exception as e:
                print(f"User already exists: {user['email']}")
        
        db.commit()
        
        # Create demo scans with findings
        if user_ids:
            demo_scans = [
                {
                    'user_id': user_ids[0],
                    'filename': 'vulnerable_sample.py',
                    'findings': [
                        {'rule_id': 'PWD001', 'severity': 'critical', 'file': 'auth.py', 'line': 42},
                        {'rule_id': 'PWD002', 'severity': 'high', 'file': 'crypto.py', 'line': 15},
                        {'rule_id': 'PWD005', 'severity': 'high', 'file': 'hash.py', 'line': 23},
                    ]
                },
                {
                    'user_id': user_ids[0],
                    'filename': 'safer_sample.py',
                    'findings': [
                        {'rule_id': 'PWD007', 'severity': 'info', 'file': 'secure_auth.py', 'line': 10},
                    ]
                }
            ]
            
            for scan_data in demo_scans:
                cursor.execute('''
                    INSERT INTO scans (
                        user_id, original_filename, scan_status,
                        total_files_scanned, total_findings,
                        high_count, medium_count, low_count, info_count,
                        completed_at
                    )
                    VALUES (?, ?, 'completed', 1, ?, 2, 0, 0, 0, CURRENT_TIMESTAMP)
                ''', (scan_data['user_id'], scan_data['filename'], len(scan_data['findings'])))
                
                scan_id = cursor.lastrowid
                
                for finding in scan_data['findings']:
                    rule_titles = {
                        'PWD001': 'Possible plaintext password storage',
                        'PWD002': 'MD5 used for password hashing',
                        'PWD003': 'SHA-1 used for password hashing',
                        'PWD004': 'Hardcoded password or secret',
                        'PWD005': 'Possible unsalted password hashing',
                        'PWD006': 'Weak or obsolete password-storage pattern',
                        'PWD007': 'Modern password hashing detected',
                    }
                    
                    rule_descriptions = {
                        'PWD001': 'Password stored without hashing',
                        'PWD002': 'MD5 is cryptographically broken',
                        'PWD003': 'SHA-1 is cryptographically weak',
                        'PWD004': 'Hardcoded credentials detected',
                        'PWD005': 'Hash without proper salt',
                        'PWD006': 'Weak hashing pattern',
                        'PWD007': 'Secure hashing algorithm detected',
                    }
                    
                    cursor.execute('''
                        INSERT INTO findings (
                            scan_id, rule_id, rule_title, severity,
                            file_name, line_number, evidence, description, recommendation
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        finding['rule_id'],
                        rule_titles.get(finding['rule_id'], 'Unknown'),
                        finding['severity'],
                        finding['file'],
                        finding['line'],
                        'Sample evidence code snippet',
                        rule_descriptions.get(finding['rule_id'], ''),
                        'See recommendation for this rule'
                    ))
                
                print(f"Created scan: {scan_data['filename']} with {len(scan_data['findings'])} findings")
        
        db.commit()
        db.close()
        
        print("\nDemo data created successfully!")
        print("\nDemo credentials:")
        for user in demo_users:
            print(f"  Email: {user['email']}")
            print(f"  Password: {user['password']}")
            print(f"  Role: {user['role']}")
            print()

if __name__ == '__main__':
    seed_demo_data()
