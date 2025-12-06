from sqlmodel import SQLModel, Field, create_engine, Session
from datetime import datetime
from typing import Optional
import os

DATABASE_URL = "sqlite:///./nis2_platform.db"

class ScanResult(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    target_name: str
    target_url: Optional[str] = None
    compliance_score: float # 0-100
    ssl_status: str # PASS/FAIL/WARN
    critical_issues_count: int
    details: str # JSON string or summary

engine = create_engine(DATABASE_URL, echo=False)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
