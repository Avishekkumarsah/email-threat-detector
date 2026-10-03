"""
wsgi.py
-------
Production WSGI application entrypoint for Gunicorn, Waitress, or uWSGI.
Usage:
    gunicorn --bind 0.0.0.0:5000 wsgi:app
"""

from app import app

if __name__ == "__main__":
    import os
    host  = os.getenv("FLASK_RUN_HOST", "0.0.0.0")
    port  = int(os.getenv("FLASK_RUN_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)
