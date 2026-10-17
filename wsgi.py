"""WSGI entry point for production servers."""
from app import create_app
from app.config import get_config

app = create_app(get_config())