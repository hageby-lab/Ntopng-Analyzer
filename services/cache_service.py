import redis.asyncio as redis
import json
from datetime import datetime
from typing import Optional, Any, Dict
from loguru import logger
from settings import get_settings

settings = get_settings()

class CacheService:
    """
    ������ ��� ����������� ����� ������������� ������.
    
    ���������� Redis ��� �������� ������������ ������� � ����������� �������.
    """
    
    def __init__(self):
        """������������� ������� �����������."""
        self.redis_client: Optional[redis.Redis] = None
        self.is_connected = False

    async def connect(self) -> None:
        """
        ����������� � Redis.
        
        Raises:
            Exception: ���� �� ������� ������������ � Redis
        """
        try:
            self.redis_client = redis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            # ��������� �����������
            await self.redis_client.ping()
            self.is_connected = True
            logger.info("�������� ����������� � Redis")
        except Exception as e:
            logger.warning(f"�� ������� ������������ � Redis: {e}. ����������� ���������.")
            self.is_connected = False

    async def disconnect(self) -> None:
        """�������� ���������� � Redis."""
        if self.redis_client and self.is_connected:
            await self.redis_client.close()
            self.is_connected = False
            logger.info("���������� � Redis �������")

    async def get_cached_report(self, timeframe_minutes: int) -> Optional[Dict[str, Any]]:
        """
        ��������� ������������� ������.
        
        Args:
            timeframe_minutes: ������ ������� � �������
            
        Returns:
            Optional[Dict]: ������������ ����� ��� None
        """
        if not self.is_connected:
            return None
            
        try:
            key = f"report:{timeframe_minutes}"
            cached_data = await self.redis_client.get(key)
            
            if cached_data:
                report = json.loads(cached_data)
                # ������������ ������ ������� ������� � datetime
                report['start_time'] = datetime.fromisoformat(report['start_time'])
                report['end_time'] = datetime.fromisoformat(report['end_time'])
                logger.debug(f"������������ ����� ��� {timeframe_minutes} ����� ������")
                return report
                
        except Exception as e:
            logger.warning(f"������ ��������� ������������� ������: {e}")
            
        return None

    async def set_cached_report(
        self, 
        timeframe_minutes: int, 
        report: Dict[str, Any]
    ) -> bool:
        """
        ���������� ������ � ���.
        
        Args:
            timeframe_minutes: ������ ������� � �������
            report: ������ ������ ��� �����������
            
        Returns:
            bool: True ���� �������, False ���� ������
        """
        if not self.is_connected:
            return False
            
        try:
            # ������������ datetime � ������ ��� JSON ������������
            cache_report = report.copy()
            cache_report['start_time'] = report['start_time'].isoformat()
            cache_report['end_time'] = report['end_time'].isoformat()
            
            key = f"report:{timeframe_minutes}"
            await self.redis_client.setex(
                key,
                settings.cache_ttl,
                json.dumps(cache_report)
            )
            logger.debug(f"����� ��� {timeframe_minutes} ����� �������� � ���")
            return True
            
        except Exception as e:
            logger.warning(f"������ ���������� ������ � ���: {e}")
            return False

    async def invalidate_report_cache(self, timeframe_minutes: int) -> bool:
        """
        �������� ������ �� ����.
        
        Args:
            timeframe_minutes: ������ ������� � �������
            
        Returns:
            bool: True ���� �������, False ���� ������
        """
        if not self.is_connected:
            return False
            
        try:
            key = f"report:{timeframe_minutes}"
            result = await self.redis_client.delete(key)
            if result > 0:
                logger.debug(f"��� ������ ��� {timeframe_minutes} ����� ������")
            return result > 0
            
        except Exception as e:
            logger.warning(f"������ ������� ���� ������: {e}")
            return False

    async def get_cache_stats(self) -> Dict[str, Any]:
        """
        ��������� ���������� ����.
        
        Returns:
            Dict: ���������� ������������� ����
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
            logger.warning(f"������ ��������� ���������� ����: {e}")
            return {'connected': False, 'error': str(e)}

# ���������� ��������� ������� �����������
cache_service = CacheService()