"""ASGI entry point:  uvicorn kybergate.web.asgi:app"""
from .app import create_app

app = create_app()
