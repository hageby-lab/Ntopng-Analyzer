from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from config import config

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    message = Column(Text)
    severity = Column(String(20))
    alert_type = Column(String(50))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    protocol = Column(String(20))
    risk_score = Column(Integer)
    interface = Column(String(100))
    category = Column(String(50))
    resolved = Column(Integer, default=0)

engine = create_engine(config.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()