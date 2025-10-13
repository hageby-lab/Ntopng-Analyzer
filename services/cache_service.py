import redis.asyncio as redis
import json
from datetime import datetime
from typing import Optional, Any, Dict
from loguru import logger
from settings import get_settings

settings = get_settings()

class CacheService:
    """
    Сервис для кэширования часто запрашиваемых данных.
    
    Использует Redis для хранения кэшированных отчетов и результатов анализа.
    """
    
    def __init__(self):
        """Инициализация сервиса кэширования."""
        self.redis_client: Optional[redis.Redis] = None
        self.is_connected = False

    async def connect(self) -> None:
        """
        Подключение к Redis.
        
        Raises:
            Exception: Если не удалось подключиться к Redis
        """
        try:
            self.redis_client = redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            # Проверяем подключение
            await self.redis_client.ping()
            self.is_connected = True
            logger.info("Успешное подключение к Redis")
        except Exception as e:
            logger.warning(f"Не удалось подключиться к Redis: {e}. Кэширование отключено.")
            self.is_connected = False

    async def disconnect(self) -> None:
        """Закрытие соединения с Redis."""
        if self.redis_client and self.is_connected:
            await self.redis_client.close()
            self.is_connected = False
            logger.info("Соединение с Redis закрыто")

    async def get_cached_report(self, timeframe_minutes: int) -> Optional[Dict[str, Any]]:
        """
        Получение кэшированного отчета.
        
        Args:
            timeframe_minutes: Период анализа в минутах
            
        Returns:
            Optional[Dict]: Кэшированный отчет или None
        """
        if not self.is_connected:
            return None
            
        try:
            key = f"report:{timeframe_minutes}"
            cached_data = await self.redis_client.get(key)
            
            if cached_data:
                report = json.loads(cached_data)
                # Конвертируем строки времени обратно в datetime
                report['start_time'] = datetime.fromisoformat(report['start_time'])
                report['end_time'] = datetime.fromisoformat(report['end_time'])
                logger.debug(f"Кэшированный отчет для {timeframe_minutes} минут найден")
                return report
                
        except Exception as e:
            logger.warning(f"Ошибка получения кэшированного отчета: {e}")
            
        return None

    async def set_cached_report(
        self, 
        timeframe_minutes: int, 
        report: Dict[str, Any]
    ) -> bool:
        """
        Сохранение отчета в кэш.
        
        Args:
            timeframe_minutes: Период анализа в минутах
            report: Данные отчета для кэширования
            
        Returns:
            bool: True если успешно, False если ошибка
        """
        if not self.is_connected:
            return False
            
        try:
            # Конвертируем datetime в строки для JSON сериализации
            cache_report = report.copy()
            cache_report['start_time'] = report['start_time'].isoformat()
            cache_report['end_time'] = report['end_time'].isoformat()
            
            key = f"report:{timeframe_minutes}"
            await self.redis_client.setex(
                key,
                settings.cache_ttl,
                json.dumps(cache_report)
            )
            logger.debug(f"Отчет для {timeframe_minutes} минут сохранен в кэш")
            return True
            
        except Exception as e:
            logger.warning(f"Ошибка сохранения отчета в кэш: {e}")
            return False

    async def invalidate_report_cache(self, timeframe_minutes: int) -> bool:
        """
        Удаление отчета из кэша.
        
        Args:
            timeframe_minutes: Период анализа в минутах
            
        Returns:
            bool: True если успешно, False если ошибка
        """
        if not self.is_connected:
            return False
            
        try:
            key = f"report:{timeframe_minutes}"
            result = await self.redis_client.delete(key)
            if result > 0:
                logger.debug(f"Кэш отчета для {timeframe_minutes} минут очищен")
            return result > 0
            
        except Exception as e:
            logger.warning(f"Ошибка очистки кэша отчета: {e}")
            return False

    async def get_cache_stats(self) -> Dict[str, Any]:
        """
        Получение статистики кэша.
        
        Returns:
            Dict: Статистика использования кэша
        """
        if not self.is_connected:
            return {'connected': False}
            
        try:
            keys = await self.redis_client.keys("report:*")
            return {
                'connected': True,
                'total_cached_reports': len(keys),
                'cache_ttl': settings.cache_ttl
            }
        except Exception as e:
            logger.warning(f"Ошибка получения статистики кэша: {e}")
            return {'connected': False, 'error': str(e)}

# Глобальный экземпляр сервиса кэширования
cache_service = CacheService()