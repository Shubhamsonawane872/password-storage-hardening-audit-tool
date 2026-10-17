"""Initialize the database"""
import os
import sys
from app import create_app
from app.config import Config

def main():
    """Initialize database"""
    print("Initializing database...")
    
    app = create_app(Config)
    
    with app.app_context():
        db_path = app.config['DATABASE_PATH']
        print(f"Database path: {db_path}")
        print("Database initialized successfully!")

if __name__ == '__main__':
    main()
