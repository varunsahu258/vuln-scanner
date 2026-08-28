"""SQLAlchemy setup shared by the API and Alembic migrations."""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


# Production should set DATABASE_URL to a PostgreSQL connection string.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
