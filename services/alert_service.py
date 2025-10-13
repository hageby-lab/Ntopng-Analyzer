from sqlalchemy import desc
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import re
from loguru import logger

from database import Alert
from settings import (
    get_settings, 
    AlertTypes, 
    SeverityLevels, 
    Categories,
    REGEX_PATTERNS,
    ANALYSIS_CONFIG,
    ALERT_PATTERNS,
    SEVERITY_KEYWORDS,
    PROTOCOLS
)

settings = get_settings()

class AlertAnalysisService:
    """
    Сервис для анализа и классификации алертов ntopng.
    
    Обеспечивает парсинг сообщений, определение типа алерта,
    уровня серьезности и расчет оценки риска.
    """
    
    def __init__(self):
        """Инициализация сервиса анализа алертов."""
        self.alert_patterns = ALERT_PATTERNS
        self.severity_keywords = SEVERITY_KEYWORDS

    async def parse_alert_message(self, message: str) -> Dict:
        """
        Парсинг и анализ сообщения от ntopng.
        
        Args:
            message: Текст алерта от ntopng
            
        Returns:
            Dict: Словарь с результатами анализа:
                - message: оригинальное сообщение
                - severity: уровень серьезности
                - alert_type: тип алерта
                - source_ip: IP источник
                - destination_ip: IP назначения
                - protocol: сетевой протокол
                - risk_score: оценка риска
                - category: категория алерта
                - interface: сетевой интерфейс
                
        Raises:
            Exception: Если произошла ошибка при анализе
        """
        try:
            analysis = {
                'message': message,
                'severity': SeverityLevels.INFO,
                'alert_type': AlertTypes.UNKNOWN,
                'source_ip': None,
                'destination_ip': None,
                'protocol': None,
                'risk_score': 0,
                'category': Categories.NETWORK,
                'interface': 'unknown'
            }
            
            # Поиск IP-адресов
            ips = re.findall(REGEX_PATTERNS['ip_address'], message)
            if len(ips) >= 1:
                analysis['source_ip'] = ips[0]
            if len(ips) >= 2:
                analysis['destination_ip'] = ips[1]
            
            # Определение типа алерта
            analysis.update(await self._detect_alert_type(message, analysis))
            
            # Определение уровня серьезности
            analysis.update(await self._detect_severity(message, analysis))
            
            # Поиск протоколов и интерфейса
            analysis.update(await self._extract_additional_info(message))
            
            logger.info(
                f"Алерт проанализирован: {analysis['alert_type']} - "
                f"{analysis['severity']} (риск: {analysis['risk_score']}%)"
            )
            return analysis
            
        except Exception as e:
            logger.error(f"Ошибка анализа алерта: {e}")
            raise

    async def _detect_alert_type(self, message: str, analysis: Dict) -> Dict:
        """
        Определение типа алерта на основе паттернов.
        
        Args:
            message: Текст алерта
            analysis: Текущий анализ
            
        Returns:
            Dict: Обновленный анализ с типом алерта и оценкой риска
        """
        result = {}
        for alert_type, pattern in self.alert_patterns.items():
            if re.search(pattern, message, re.IGNORECASE):
                result['alert_type'] = alert_type
                result['risk_score'] = (
                    analysis['risk_score'] + 
                    ANALYSIS_CONFIG['risk_scores']['base_alert_type']
                )
                break
        
        if 'alert_type' not in result:
            result['alert_type'] = AlertTypes.UNKNOWN
            
        return result

    async def _detect_severity(self, message: str, analysis: Dict) -> Dict:
        """
        Определение уровня серьезности алерта.
        
        Args:
            message: Текст алерта
            analysis: Текущий анализ
            
        Returns:
            Dict: Обновленный анализ с уровнем серьезности и оценкой риска
        """
        result = {}
        message_lower = message.lower()
        
        for severity, keywords in self.severity_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                result['severity'] = severity
                risk_score = analysis['risk_score']
                
                if severity == SeverityLevels.CRITICAL:
                    result['risk_score'] = (
                        risk_score + 
                        ANALYSIS_CONFIG['risk_scores']['critical']
                    )
                elif severity == SeverityLevels.WARNING:
                    result['risk_score'] = (
                        risk_score + 
                        ANALYSIS_CONFIG['risk_scores']['warning']
                    )
                break
        
        return result

    async def _extract_additional_info(self, message: str) -> Dict:
        """
        Извлечение дополнительной информации из алерта.
        
        Args:
            message: Текст алерта
            
        Returns:
            Dict: Дополнительная информация (протокол, категория, интерфейс)
        """
        result = {}
        
        # Поиск протоколов
        for protocol in PROTOCOLS:
            if protocol.upper() in message.upper():
                result['protocol'] = protocol
                break
        
        # Определение категории
        message_lower = message.lower()
        if any(word in message_lower for word in ['attack', 'security', 'threat', 'malicious']):
            result['category'] = Categories.SECURITY
        elif any(word in message_lower for word in ['bandwidth', 'throughput', 'traffic', 'flow']):
            result['category'] = Categories.PERFORMANCE
        elif any(word in message_lower for word in ['interface', 'host', 'device']):
            result['category'] = Categories.INFRASTRUCTURE
        
        # Поиск интерфейса
        interface_match = re.search(REGEX_PATTERNS['interface'], message_lower)
        if interface_match:
            result['interface'] = interface_match.group(1)
        
        return result

class AlertQueryService:
    """
    Сервис для выполнения запросов к алертам в базе данных.
    
    Обеспечивает получение алертов по различным критериям.
    """
    
    async def get_alerts_by_timeframe(
        self, 
        session: AsyncSession, 
        minutes: int
    ) -> List[Alert]:
        """
        Получение алертов за указанный промежуток времени.
        
        Args:
            session: Асинхронная сессия БД
            minutes: Период в минутах
            
        Returns:
            List[Alert]: Список алертов за указанный период
            
        Raises:
            Exception: Если произошла ошибка при запросе
        """
        try:
            since = datetime.utcnow() - timedelta(minutes=minutes)
            from sqlalchemy import select
            query = select(Alert).filter(Alert.timestamp >= since)
            result = await session.execute(query)
            alerts = result.scalars().all()
            
            logger.info(f"Получено {len(alerts)} алертов за {minutes} минут")
            return alerts
            
        except Exception as e:
            logger.error(f"Ошибка получения алертов: {e}")
            raise

    async def get_recent_alerts(
        self, 
        session: AsyncSession, 
        limit: int = 50
    ) -> List[Alert]:
        """
        Получение последних алертов.
        
        Args:
            session: Асинхронная сессия БД
            limit: Максимальное количество алертов
            
        Returns:
            List[Alert]: Список последних алертов
            
        Raises:
            Exception: Если произошла ошибка при запросе
        """
        try:
            from sqlalchemy import select
            query = (
                select(Alert)
                .order_by(desc(Alert.timestamp))
                .limit(limit)
            )
            result = await session.execute(query)
            alerts = result.scalars().all()
            
            logger.info(f"Получено {len(alerts)} последних алертов")
            return alerts
            
        except Exception as e:
            logger.error(f"Ошибка получения последних алертов: {e}")
            raise

# Глобальные экземпляры сервисов
alert_analysis_service = AlertAnalysisService()
alert_query_service = AlertQueryService()