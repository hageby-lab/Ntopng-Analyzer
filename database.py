from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from datetime import datetime
from contextlib import asynccontextmanager
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

class DatabaseManager:
    def __init__(self):
        self.engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            future=True,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False}
        )
        self.async_session = sessionmaker(
            self.engine, 
            class_=AsyncSession, 
            expire_on_commit=False
        )

    async def init_db(self) -> None:
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise

    @asynccontextmanager
    async def get_session(self) -> AsyncSession:
        async with self.async_session() as session:
            try:
                yield session
            except Exception as e:
                await session.rollback()
                logger.error(f"Database session error: {e}")
                raise
            finally:
                await session.close()

    async def save_alert(self, alert_data: dict) -> int:
        async with self.get_session() as session:
            try:
                alert = Alert(**alert_data)
                session.add(alert)
                await session.commit()
                await session.refresh(alert)
                logger.info(f"Alert saved with ID: {alert.id}")
                return alert.id
            except Exception as e:
                await session.rollback()
                logger.error(f"Error saving alert: {e}")
                raise

db_manager = DatabaseManager()
