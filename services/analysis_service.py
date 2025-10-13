from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
from typing import Dict, List
from loguru import logger

from database import Alert
from settings import ANALYSIS_CONFIG

class TimeframeAnalysisService:
    """Сервис для анализа временных промежутков"""
    
    async def analyze_timeframe(self, session: AsyncSession, minutes: int) -> Dict:
        """Анализ алертов за указанный промежуток времени"""
        try:
            from services.alert_service import alert_query_service
            alerts = await alert_query_service.get_alerts_by_timeframe(session, minutes)
            
            if not alerts:
                return await self._empty_analysis_result(minutes)
            
            # Сбор статистики
            severity_stats = await self._calculate_severity_stats(alerts)
            alert_type_stats = await self._calculate_alert_type_stats(alerts)
            source_ip_stats = await self._calculate_source_ip_stats(alerts)
            avg_risk = await self._calculate_average_risk(alerts)
            top_alerts = await self._get_top_alert_types(alert_type_stats)
            
            analysis_result = {
                'timeframe_minutes': minutes,
                'timeframe_human': self._minutes_to_human(minutes),
                'total_alerts': len(alerts),
                'severity_stats': severity_stats,
                'alert_type_stats': alert_type_stats,
                'source_ip_stats': dict(sorted(source_ip_stats.items(), 
                                             key=lambda x: x[1], reverse=True)[:ANALYSIS_CONFIG['max_top_items']]),
                'average_risk_score': round(avg_risk, 2),
                'top_alert_types': top_alerts,
                'critical_alerts_count': severity_stats.get('critical', 0),
                'warning_alerts_count': severity_stats.get('warning', 0),
                'start_time': datetime.utcnow() - timedelta(minutes=minutes),
                'end_time': datetime.utcnow()
            }
            
            logger.info(f"Анализ завершен для {minutes} минут: {len(alerts)} алертов")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Ошибка анализа временного промежутка: {e}")
            raise

    async def _empty_analysis_result(self, minutes: int) -> Dict:
        """Результат анализа при отсутствии алертов"""
        return {
            'timeframe_minutes': minutes,
            'timeframe_human': self._minutes_to_human(minutes),
            'total_alerts': 0,
            'severity_stats': {},
            'alert_type_stats': {},
            'source_ip_stats': {},
            'average_risk_score': 0,
            'top_alert_types': [],
            'critical_alerts_count': 0,
            'warning_alerts_count': 0,
            'start_time': datetime.utcnow() - timedelta(minutes=minutes),
            'end_time': datetime.utcnow()
        }

    async def _calculate_severity_stats(self, alerts: List[Alert]) -> Dict[str, int]:
        """Расчет статистики по серьезности"""
        stats = {}
        for alert in alerts:
            stats[alert.severity] = stats.get(alert.severity, 0) + 1
        return stats

    async def _calculate_alert_type_stats(self, alerts: List[Alert]) -> Dict[str, int]:
        """Расчет статистики по типам алертов"""
        stats = {}
        for alert in alerts:
            stats[alert.alert_type] = stats.get(alert.alert_type, 0) + 1
        return stats

    async def _calculate_source_ip_stats(self, alerts: List[Alert]) -> Dict[str, int]:
        """Расчет статистики по IP-адресам"""
        stats = {}
        for alert in alerts:
            if alert.source_ip:
                stats[alert.source_ip] = stats.get(alert.source_ip, 0) + 1
        return stats

    async def _calculate_average_risk(self, alerts: List[Alert]) -> float:
        """Расчет среднего уровня риска"""
        if not alerts:
            return 0.0
        return sum(alert.risk_score for alert in alerts) / len(alerts)

    async def _get_top_alert_types(self, alert_type_stats: Dict) -> List[tuple]:
        """Получение топ типов алертов"""
        return sorted(alert_type_stats.items(), key=lambda x: x[1], reverse=True)[:ANALYSIS_CONFIG['max_top_items']]

    def _minutes_to_human(self, minutes: int) -> str:
        """Конвертация минут в человеко-читаемый формат"""
        if minutes < 60:
            return f"{minutes} минут"
        elif minutes < 1440:
            hours = minutes // 60
            return f"{hours} часов"
        else:
            days = minutes // 1440
            return f"{days} дней"

class ReportGenerationService:
    """Сервис для генерации отчетов"""
    
    async def generate_telegram_report(self, analysis: Dict) -> str:
        """Генерация отчета для Telegram"""
        try:
            timeframe = analysis['timeframe_human']
            
            if analysis['total_alerts'] == 0:
                return f"📊 Отчет за {timeframe}\n✅ Нет алертов за этот период"
            
            message = f"📊 ОТЧЕТ ЗА {timeframe.upper()}\n\n"
            message += f"📈 Всего алертов: {analysis['total_alerts']}\n"
            message += f"🚨 Критических: {analysis['critical_alerts_count']}\n"
            message += f"⚠️ Предупреждений: {analysis['warning_alerts_count']}\n"
            message += f"📊 Средний риск: {analysis['average_risk_score']}%\n\n"
            
            message += "🔝 Топ типов алертов:\n"
            for alert_type, count in analysis['top_alert_types']:
                message += f"  • {alert_type}: {count}\n"
            
            if analysis['source_ip_stats']:
                message += "\n🔍 Проблемные IP:\n"
                for ip, count in list(analysis['source_ip_stats'].items())[:3]:
                    message += f"  • {ip}: {count} алертов\n"
            
            # Рекомендации
            if analysis['critical_alerts_count'] > 0:
                message += "\n🚨 ВНИМАНИЕ: Критические алерты требуют немедленного вмешательства!"
            
            message += f"\n⏰ Период: {analysis['start_time'].strftime('%H:%M')} - {analysis['end_time'].strftime('%H:%M')}"
            
            logger.info(f"Сгенерирован отчет для Telegram: {timeframe}")
            return message
            
        except Exception as e:
            logger.error(f"Ошибка генерации отчета: {e}")
            return f"❌ Ошибка генерации отчета за {analysis.get('timeframe_human', 'неизвестный период')}"

# Глобальные экземпляры сервисов
timeframe_analysis_service = TimeframeAnalysisService()
report_generation_service = ReportGenerationService()