"""
backend/app/database/session.py
--------------------------------
SQLAlchemy async-compatible engine + session factory.
PostgreSQL ONLY — no SQLite fallback.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session
from typing import Generator
from backend.app.core.config import get_settings


settings = get_settings()


def get_engine():
    url = settings.DATABASE_URL
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "This application requires PostgreSQL. "
            "Please configure your .env file with a valid PostgreSQL connection string."
        )
    if url.startswith("sqlite"):
        raise RuntimeError(
            "SQLite is not supported. Please configure DATABASE_URL with a PostgreSQL connection string."
        )
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=10,
        max_overflow=20,
        echo=settings.DEBUG,
    )


engine = get_engine()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
