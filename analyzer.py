from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import re
from collections import Counter
from loguru import logger

from database import Alert
from settings import (
    get_settings, 
    AlertTypes, 
    SeverityLevels, 
    Categories,
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
        """Инициализация сервиса анализа алертов с предкомпилированными regex."""
        self.alert_patterns = ALERT_PATTERNS
        self.severity_keywords = SEVERITY_KEYWORDS
        
        # Предкомпилированные регулярные выражения для повышения производительности
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.interface_pattern = re.compile(r'interface[:\s]+([^\s,]+)', re.IGNORECASE)
        
        # Предкомпилированные паттерны для типов алертов
        self.compiled_alert_patterns = {
            alert_type: re.compile(pattern, re.IGNORECASE)
            for alert_type, pattern in self.alert_patterns.items()
        }

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
            
            # Поиск IP-адресов с предкомпилированным regex
            ips = self.ip_pattern.findall(message)
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
        Определение типа алерта на основе предкомпилированных паттернов.
        
        Args:
            message: Текст алерта
            analysis: Текущий анализ
            
        Returns:
            Dict: Обновленный анализ с типом алерта и оценкой риска
        """
        result = {}
        for alert_type, pattern in self.compiled_alert_patterns.items():
            if pattern.search(message):
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
        
        # Поиск интерфейса с предкомпилированным regex
        interface_match = self.interface_pattern.search(message_lower)
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
                .order_by(Alert.timestamp.desc())
                .limit(limit)
            )
            result = await session.execute(query)
            alerts = result.scalars().all()
            
            logger.info(f"Получено {len(alerts)} последних алертов")
            return alerts
            
        except Exception as e:
            logger.error(f"Ошибка получения последних алертов: {e}")
            raise

class TimeframeAnalysisService:
    """
    Сервис для анализа временных промежутков.
    
    Оптимизирован для быстрой обработки больших объемов данных
    с использованием Counter и однопроходных алгоритмов.
    """

    def __init__(self):
        """Инициализация сервиса анализа временных промежутков."""
        self.max_top_items = ANALYSIS_CONFIG['max_top_items']

    async def analyze_timeframe(self, session: AsyncSession, minutes: int) -> Dict:
        """
        Анализ алертов за указанный промежуток времени.
        
        Args:
            session: Асинхронная сессия БД
            minutes: Период анализа в минутах
            
        Returns:
            Dict: Результаты анализа с расширенной статистикой
            
        Raises:
            Exception: Если произошла ошибка при анализе
        """
        try:
            from services.alert_service import alert_query_service
            alerts = await alert_query_service.get_alerts_by_timeframe(session, minutes)
            
            if not alerts:
                return await self._empty_analysis_result(minutes)
            
            # Оптимизированный однопроходный анализ с использованием Counter
            analysis_result = await self._perform_optimized_analysis(alerts, minutes)
            
            logger.info(
                f"Анализ завершен для {minutes} минут: {len(alerts)} алертов, "
                f"критических: {analysis_result['critical_alerts_count']}"
            )
            return analysis_result
            
        except Exception as e:
            logger.error(f"Ошибка анализа временного промежутка: {e}")
            raise

    async def _perform_optimized_analysis(self, alerts: List[Alert], minutes: int) -> Dict:
        """
        Выполнение оптимизированного анализа алертов за один проход.
        
        Args:
            alerts: Список алертов для анализа
            minutes: Период анализа в минутах
            
        Returns:
            Dict: Полные результаты анализа
        """
        # Использование Counter для эффективного подсчета статистики
        severity_stats = Counter()
        alert_type_stats = Counter()
        source_ip_stats = Counter()
        destination_ip_stats = Counter()
        protocol_stats = Counter()
        category_stats = Counter()
        
        total_risk_score = 0
        critical_count = 0
        warning_count = 0
        
        # Однопроходный анализ всех алертов
        for alert in alerts:
            # Статистика по серьезности
            severity_stats[alert.severity] += 1
            
            # Подсчет критических и предупреждений
            if alert.severity == SeverityLevels.CRITICAL:
                critical_count += 1
            elif alert.severity == SeverityLevels.WARNING:
                warning_count += 1
            
            # Статистика по типам алертов
            alert_type_stats[alert.alert_type] += 1
            
            # Статистика по IP-адресам
            if alert.source_ip:
                source_ip_stats[alert.source_ip] += 1
            if alert.destination_ip:
                destination_ip_stats[alert.destination_ip] += 1
            
            # Статистика по протоколам и категориям
            if alert.protocol:
                protocol_stats[alert.protocol] += 1
            if alert.category:
                category_stats[alert.category] += 1
            
            # Суммирование оценок риска
            total_risk_score += alert.risk_score
        
        # Расчет среднего риска
        avg_risk = total_risk_score / len(alerts) if alerts else 0
        
        # Получение топ элементов
        top_alert_types = alert_type_stats.most_common(self.max_top_items)
        top_source_ips = source_ip_stats.most_common(self.max_top_items)
        top_destination_ips = destination_ip_stats.most_common(self.max_top_items)
        top_protocols = protocol_stats.most_common(self.max_top_items)
        top_categories = category_stats.most_common(self.max_top_items)
        
        return {
            'timeframe_minutes': minutes,
            'timeframe_human': self._minutes_to_human(minutes),
            'total_alerts': len(alerts),
            'severity_stats': dict(severity_stats),
            'alert_type_stats': dict(alert_type_stats),
            'source_ip_stats': dict(source_ip_stats),
            'destination_ip_stats': dict(destination_ip_stats),
            'protocol_stats': dict(protocol_stats),
            'category_stats': dict(category_stats),
            'average_risk_score': round(avg_risk, 2),
            'top_alert_types': top_alert_types,
            'top_source_ips': top_source_ips,
            'top_destination_ips': top_destination_ips,
            'top_protocols': top_protocols,
            'top_categories': top_categories,
            'critical_alerts_count': critical_count,
            'warning_alerts_count': warning_count,
            'start_time': datetime.utcnow() - timedelta(minutes=minutes),
            'end_time': datetime.utcnow()
        }

    async def _empty_analysis_result(self, minutes: int) -> Dict:
        """
        Результат анализа при отсутствии алертов.
        
        Args:
            minutes: Период анализа в минутах
            
        Returns:
            Dict: Пустой результат анализа
        """
        return {
            'timeframe_minutes': minutes,
            'timeframe_human': self._minutes_to_human(minutes),
            'total_alerts': 0,
            'severity_stats': {},
            'alert_type_stats': {},
            'source_ip_stats': {},
            'destination_ip_stats': {},
            'protocol_stats': {},
            'category_stats': {},
            'average_risk_score': 0,
            'top_alert_types': [],
            'top_source_ips': [],
            'top_destination_ips': [],
            'top_protocols': [],
            'top_categories': [],
            'critical_alerts_count': 0,
            'warning_alerts_count': 0,
            'start_time': datetime.utcnow() - timedelta(minutes=minutes),
            'end_time': datetime.utcnow()
        }

    def _minutes_to_human(self, minutes: int) -> str:
        """
        Конвертация минут в человеко-читаемый формат.
        
        Args:
            minutes: Количество минут
            
        Returns:
            str: Человеко-читаемое представление времени
        """
        if minutes < 60:
            return f"{minutes} минут"
        elif minutes < 1440:
            hours = minutes // 60
            minutes_remainder = minutes % 60
            if minutes_remainder > 0:
                return f"{hours} ч {minutes_remainder} мин"
            else:
                return f"{hours} часов"
        else:
            days = minutes // 1440
            hours_remainder = (minutes % 1440) // 60
            if hours_remainder > 0:
                return f"{days} д {hours_remainder} ч"
            else:
                return f"{days} дней"

class ReportGenerationService:
    """
    Сервис для генерации отчетов.
    
    Создает читаемые отчеты для Telegram и других каналов.
    """

    async def generate_telegram_report(self, analysis: Dict) -> str:
        """
        Генерация отчета для Telegram.
        
        Args:
            analysis: Результаты анализа
            
        Returns:
            str: Форматированный отчет для Telegram
        """
        try:
            timeframe = analysis['timeframe_human']
            
            if analysis['total_alerts'] == 0:
                return f"📊 Отчет за {timeframe}\n✅ Нет алертов за этот период"
            
            message = f"📊 ОТЧЕТ ЗА {timeframe.upper()}\n\n"
            message += f"📈 Всего алертов: {analysis['total_alerts']}\n"
            message += f"🚨 Критических: {analysis['critical_alerts_count']}\n"
            message += f"⚠️ Предупреждений: {analysis['warning_alerts_count']}\n"
            message += f"📊 Средний риск: {analysis['average_risk_score']}%\n\n"
            
            # Топ типов алертов
            if analysis['top_alert_types']:
                message += "🔝 Топ типов алертов:\n"
                for alert_type, count in analysis['top_alert_types']:
                    message += f"  • {alert_type}: {count}\n"
            
            # Топ источников
            if analysis['top_source_ips']:
                message += "\n🔍 Топ источников проблем:\n"
                for ip, count in analysis['top_source_ips'][:3]:
                    message += f"  • {ip}: {count} алертов\n"
            
            # Топ назначений
            if analysis['top_destination_ips']:
                message += "\n🎯 Топ целей атак:\n"
                for ip, count in analysis['top_destination_ips'][:2]:
                    message += f"  • {ip}: {count} алертов\n"
            
            # Топ протоколов
            if analysis['top_protocols']:
                message += "\n🌐 Топ протоколов:\n"
                for protocol, count in analysis['top_protocols'][:3]:
                    message += f"  • {protocol}: {count}\n"
            
            # Рекомендации
            if analysis['critical_alerts_count'] > 0:
                message += "\n🚨 ВНИМАНИЕ: Критические алерты требуют немедленного вмешательства!"
            elif analysis['warning_alerts_count'] > 10:
                message += "\n⚠️ Рекомендуется проверить систему: много предупреждений"
            else:
                message += "\n✅ Ситуация под контролем"
            
            message += f"\n⏰ Период: {analysis['start_time'].strftime('%H:%M')} - {analysis['end_time'].strftime('%H:%M')}"
            
            logger.info(f"Сгенерирован отчет для Telegram: {timeframe}")
            return message
            
        except Exception as e:
            logger.error(f"Ошибка генерации отчета: {e}")
            return f"❌ Ошибка генерации отчета за {analysis.get('timeframe_human', 'неизвестный период')}"

# Глобальные экземпляры сервисов
alert_analysis_service = AlertAnalysisService()
alert_query_service = AlertQueryService()
timeframe_analysis_service = TimeframeAnalysisService()
report_generation_service = ReportGenerationService()