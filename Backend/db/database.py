import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base


def _get_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./sentinelx.db")


DATABASE_URL = _get_database_url()

# sqlite needs this extra arg to allow multi-threaded access
engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)
