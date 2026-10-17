"""Application entry point"""
from app import create_app
from app.config import get_config

if __name__ == '__main__':
    app = create_app(get_config())
    app.run(debug=True, host='127.0.0.1', port=5000)
