"""
wsgi.py
-------
Production WSGI application entrypoint for Gunicorn, Waitress, or uWSGI.
Usage:
    gunicorn --bind 0.0.0.0:5000 wsgi:app
"""

from app import app

if __name__ == "__main__":
    app.run()
