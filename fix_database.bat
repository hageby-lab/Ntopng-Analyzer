@echo off
echo Fixing database configuration...

:: Create fixed database.py
(
echo from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
echo from sqlalchemy.orm import sessionmaker, declarative_base
echo from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
echo from datetime import datetime
echo from contextlib import asynccontextmanager
echo from settings import get_settings
echo from loguru import logger
echo.
echo Base = declarative_base^(^)
echo settings = get_settings^(^)
echo.
echo class Alert^(Base^):
echo     __tablename__ = "alerts"
echo.    
echo     id = Column^(Integer, primary_key=True, index=True^)
echo     timestamp = Column^(DateTime, default=datetime.utcnow, index=True^)
echo     message = Column^(Text, nullable=False^)
echo     severity = Column^(String^(20^), nullable=False^)
echo     alert_type = Column^(String^(50^), nullable=False^)
echo     source_ip = Column^(String^(45^)^)
echo     destination_ip = Column^(String^(45^)^)
echo     protocol = Column^(String^(20^)^)
echo     risk_score = Column^(Integer, default=0^)
echo     interface = Column^(String^(100^)^)
echo     category = Column^(String^(50^)^)
echo     resolved = Column^(Boolean, default=False, index=True^)
echo.
echo class DatabaseManager:
echo     def __init__^(self^):
echo         self.engine = create_async_engine^(
echo             settings.database_url,
echo             echo=settings.debug,
echo             future=True,
echo             pool_pre_ping=True,
echo             connect_args=^{"check_same_thread": False^}
echo         ^)
echo         self.async_session = sessionmaker^(
echo             self.engine, 
echo             class_=AsyncSession, 
echo             expire_on_commit=False
echo         ^)
echo.
echo     async def init_db^(self^) -^> None:
echo         try:
echo             async with self.engine.begin^(^) as conn:
echo                 await conn.run_sync^(Base.metadata.create_all^)
echo             logger.info^("Database initialized successfully"^)
echo         except Exception as e:
echo             logger.error^(f"Database initialization error: {e}"^)
echo             raise
echo.
echo     @asynccontextmanager
echo     async def get_session^(self^) -^> AsyncSession:
echo         async with self.async_session^(^) as session:
echo             try:
echo                 yield session
echo             except Exception as e:
echo                 await session.rollback^(^)
echo                 logger.error^(f"Database session error: {e}"^)
echo                 raise
echo             finally:
echo                 await session.close^(^)
echo.
echo     async def save_alert^(self, alert_data: dict^) -^> int:
echo         async with self.get_session^(^) as session:
echo             try:
echo                 alert = Alert^(**alert_data^)
echo                 session.add^(alert^)
echo                 await session.commit^(^)
echo                 await session.refresh^(alert^)
echo                 logger.info^(f"Alert saved with ID: {alert.id}"^)
echo                 return alert.id
echo             except Exception as e:
echo                 await session.rollback^(^)
echo                 logger.error^(f"Error saving alert: {e}"^)
echo                 raise
echo.
echo db_manager = DatabaseManager^(^)
) > database.py

echo Fixed database.py
echo Now try: python app.py
pause