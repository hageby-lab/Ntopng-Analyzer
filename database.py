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
    """
    ������ ������ ��� �������� � ���� ������.
    
    Attributes:
        id: ���������� ������������� ������
        timestamp: ����� ��������� ������
        message: ������������ ��������� �� ntopng
        severity: ������� ����������� (critical/warning/info)
        alert_type: ��� ������ (ddos_attack, scan_detected � �.�.)
        source_ip: IP-����� ��������� ��������
        destination_ip: IP-����� ����������
        protocol: ������� ��������
        risk_score: �������� ������ ����� (0-100)
        interface: ������� ���������
        category: ��������� ������ (security/performance/infrastructure/network)
        resolved: ���� ���������� ������
    """
    
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
    """
    �������� ��� ������ � ����� ������.
    
    ������������ ����������� ����������� � �� � ���������� ��������.
    """
    
    def __init__(self):
        """������������� ��������� ���� ������."""
        self.engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            future=True,
            pool_pre_ping=True
        )
        self.async_session = sessionmaker(
            self.engine, 
            class_=AsyncSession, 
            expire_on_commit=False
        )

    async def init_db(self) -> None:
        """
        ������������� ���� ������.
        
        ������� ��� �������, ���� ��� �� ����������.
        
        Raises:
            Exception: ���� ��������� ������ ��� �������� ������
        """
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("���� ������ ������� ����������������")
        except Exception as e:
            logger.error(f"������ ������������� ��: {e}")
            raise

    @asynccontextmanager
    async def get_session(self) -> AsyncSession:
        """
        ����������� ����������� �������� ��� ������ ��.
        
        Yields:
            AsyncSession: ����������� ������ ���� ������
            
        Raises:
            Exception: ���� ��������� ������ ��� ������ � �������
        """
        async with self.async_session() as session:
            try:
                yield session
            except Exception as e:
                await session.rollback()
                logger.error(f"������ ������ ��: {e}")
                raise
            finally:
                await session.close()

    async def save_alert(self, alert_data: dict) -> int:
        """
        ���������� ������ � ���� ������.
        
        Args:
            alert_data: ������� � ������� ������
            
        Returns:
            int: ID ������������ ������
            
        Raises:
            Exception: ���� ��������� ������ ��� ����������
        """
        async with self.get_session() as session:
            try:
                alert = Alert(**alert_data)
                session.add(alert)
                await session.commit()
                await session.refresh(alert)
                logger.info(f"����� �������� � ID: {alert.id}")
                return alert.id
            except Exception as e:
                await session.rollback()
                logger.error(f"������ ���������� ������: {e}")
                raise

    async def mark_alert_resolved(self, alert_id: int) -> bool:
        """
        �������� ����� ��� �����������.
        
        Args:
            alert_id: ID ������ ��� �������
            
        Returns:
            bool: True ���� �������, False ���� ����� �� ������
            
        Raises:
            Exception: ���� ��������� ������ ��� ����������
        """
        async with self.get_session() as session:
            try:
                from sqlalchemy import update
                stmt = (
                    update(Alert)
                    .where(Alert.id == alert_id)
                    .values(resolved=True)
                )
                result = await session.execute(stmt)
                await session.commit()
                
                if result.rowcount > 0:
                    logger.info(f"����� {alert_id} ������� ��� �����������")
                    return True
                else:
                    logger.warning(f"����� {alert_id} �� ������")
                    return False
                    
            except Exception as e:
                await session.rollback()
                logger.error(f"������ ������� ������ ��� ������������: {e}")
                raise

# ���������� ��������� ��������� ��
db_manager = DatabaseManager()