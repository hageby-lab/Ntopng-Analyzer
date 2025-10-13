from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
from settings import get_settings
from loguru import logger

Base = declarative_base()
settings = get_settings()

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    alert_type = Column(String(50), nullable=False)
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    protocol = Column(String(20))
    risk_score = Column(Integer, default=0)
    interface = Column(String(100))
    category = Column(String(50))
    resolved = Column(Boolean, default=False, index=True)

# Use synchronous SQLite
engine = create_engine(
    "sqlite:///./ntopng_alerts.db",
    echo=settings.debug,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized successfully")

def save_alert_sync(alert_data: dict) -> int:
    session = SessionLocal()
    try:
        alert = Alert(**alert_data)
        session.add(alert)
        session.commit()
        session.refresh(alert)
        logger.info(f"Alert saved with ID: {alert.id}")
        return alert.id
    except Exception as e:
        session.rollback()
        logger.error(f"Error saving alert: {e}")
        raise
    finally:
        session.close()