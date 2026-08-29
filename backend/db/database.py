"""SQLAlchemy setup shared by the API and Alembic migrations."""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


# Production should set DATABASE_URL to a PostgreSQL connection string.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv(
    "DATABASE_URL", f"sqlite:///{os.path.join(_BASE_DIR, '..', '..', 'test.db')}"
)
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
