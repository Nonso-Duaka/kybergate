"""Vercel entry point (FastAPI zero-config). Locally use: uvicorn kybergate.web.asgi:app"""
from kybergate.web.app import create_app

app = create_app()
