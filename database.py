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
    Модель алерта для хранения в базе данных.
    
    Attributes:
        id: Уникальный идентификатор алерта
        timestamp: Время получения алерта
        message: Оригинальное сообщение от ntopng
        severity: Уровень серьезности (critical/warning/info)
        alert_type: Тип алерта (ddos_attack, scan_detected и т.д.)
        source_ip: IP-адрес источника проблемы
        destination_ip: IP-адрес назначения
        protocol: Сетевой протокол
        risk_score: Числовая оценка риска (0-100)
        interface: Сетевой интерфейс
        category: Категория алерта (security/performance/infrastructure/network)
        resolved: Флаг разрешения алерта
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
    Менеджер для работы с базой данных.
    
    Обеспечивает асинхронное подключение к БД и управление сессиями.
    """
    
    def __init__(self):
        """Инициализация менеджера базы данных."""
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
        Инициализация базы данных.
        
        Создает все таблицы, если они не существуют.
        
        Raises:
            Exception: Если произошла ошибка при создании таблиц
        """
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("База данных успешно инициализирована")
        except Exception as e:
            logger.error(f"Ошибка инициализации БД: {e}")
            raise

    @asynccontextmanager
    async def get_session(self) -> AsyncSession:
        """
        Асинхронный контекстный менеджер для сессии БД.
        
        Yields:
            AsyncSession: Асинхронная сессия базы данных
            
        Raises:
            Exception: Если произошла ошибка при работе с сессией
        """
        async with self.async_session() as session:
            try:
                yield session
            except Exception as e:
                await session.rollback()
                logger.error(f"Ошибка сессии БД: {e}")
                raise
            finally:
                await session.close()

    async def save_alert(self, alert_data: dict) -> int:
        """
        Сохранение алерта в базу данных.
        
        Args:
            alert_data: Словарь с данными алерта
            
        Returns:
            int: ID сохраненного алерта
            
        Raises:
            Exception: Если произошла ошибка при сохранении
        """
        async with self.get_session() as session:
            try:
                alert = Alert(**alert_data)
                session.add(alert)
                await session.commit()
                await session.refresh(alert)
                logger.info(f"Алерт сохранен с ID: {alert.id}")
                return alert.id
            except Exception as e:
                await session.rollback()
                logger.error(f"Ошибка сохранения алерта: {e}")
                raise

    async def mark_alert_resolved(self, alert_id: int) -> bool:
        """
        Пометить алерт как разрешенный.
        
        Args:
            alert_id: ID алерта для пометки
            
        Returns:
            bool: True если успешно, False если алерт не найден
            
        Raises:
            Exception: Если произошла ошибка при обновлении
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
                    logger.info(f"Алерт {alert_id} помечен как разрешенный")
                    return True
                else:
                    logger.warning(f"Алерт {alert_id} не найден")
                    return False
                    
            except Exception as e:
                await session.rollback()
                logger.error(f"Ошибка пометки алерта как разрешенного: {e}")
                raise

# Глобальный экземпляр менеджера БД
db_manager = DatabaseManager()