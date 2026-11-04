from __future__ import annotations

import os
from pathlib import Path
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

CODE_DIR = Path(__file__).resolve().parents[1]
DB_URL = os.getenv("GHOSTGUARD_DATABASE_URL", f"sqlite:///{(CODE_DIR / 'backend' / 'ghostguard.sqlite3').as_posix()}")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Investigation(Base):
    __tablename__ = "investigations"
    case_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    deletion_status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(String(24), nullable=False, default="UNKNOWN", index=True)
    request: Mapped[dict] = mapped_column(JSON, nullable=False)
    identity: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    graph: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DatasetFile(Base):
    __tablename__ = "dataset_files"
    file_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    captured_at: Mapped[str] = mapped_column(String(48), nullable=False, default="")
    readable: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    error: Mapped[str | None] = mapped_column(Text)


class UploadedFile(Base):
    __tablename__ = "uploaded_files"
    file_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    safe_path: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), server_default=func.now())


def init_db() -> None:
    Base.metadata.create_all(engine)
