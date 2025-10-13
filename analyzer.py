from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
import pandas as pd
from database import Alert
import re
from typing import Dict, List

class NtopngAnalyzer:
    def __init__(self):
        self.alert_patterns = {
            'flow_flood': r'Flow Flood|flow flood',
            'scan_detected': r'Scan|scan|Port Scan',
            'ddos_attack': r'DDoS|Flood|DDoS Attack',
            'suspicious_traffic': r'Suspicious|Anomaly|Anomalous',
            'bandwidth_alert': r'Bandwidth|Throughput|Traffic',
            'security_alert': r'Security|Alert|Threat|Malicious',
            'host_alert': r'Host|host',
            'interface_alert': r'Interface|interface'
        }
        
        self.severity_levels = {
            'critical': ['emergency', 'alert', 'critical', 'error'],
            'warning': ['warning', 'notice'],
            'info': ['info', 'debug', 'information']
        }

    def parse_alert_message(self, message: str) -> Dict:
        """Парсинг сообщения от ntopng"""
        analysis = {
            'message': message,
            'severity': 'info',
            'alert_type': 'unknown',
            'source_ip': None,
            'destination_ip': None,
            'protocol': None,
            'risk_score': 0,
            'category': 'network',
            'interface': 'unknown'
        }
        
        # Поиск IP-адресов
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, message)
        if len(ips) >= 1:
            analysis['source_ip'] = ips[0]
        if len(ips) >= 2:
            analysis['destination_ip'] = ips[1]
        
        # Определение типа алерта
        for alert_type, pattern in self.alert_patterns.items():
            if re.search(pattern, message, re.IGNORECASE):
                analysis['alert_type'] = alert_type
                analysis['risk_score'] += 20
                break
        
        # Определение уровня серьезности
        message_lower = message.lower()
        for severity, keywords in self.severity_levels.items():
            if any(keyword in message_lower for keyword in keywords):
                analysis['severity'] = severity
                if severity == 'critical':
                    analysis['risk_score'] += 50
                elif severity == 'warning':
                    analysis['risk_score'] += 25
                break
        
        # Поиск протоколов
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
        for protocol in protocols:
            if protocol.upper() in message.upper():
                analysis['protocol'] = protocol
                break
        
        # Определение категории
        if any(word in message_lower for word in ['attack', 'security', 'threat', 'malicious']):
            analysis['category'] = 'security'
        elif any(word in message_lower for word in ['bandwidth', 'throughput', 'traffic', 'flow']):
            analysis['category'] = 'performance'
        elif any(word in message_lower for word in ['interface', 'host', 'device']):
            analysis['category'] = 'infrastructure'
        
        # Поиск интерфейса
        interface_match = re.search(r'interface[:\s]+([^\s,]+)', message_lower)
        if interface_match:
            analysis['interface'] = interface_match.group(1)
        
        return analysis

    def get_alerts_by_timeframe(self, db: Session, minutes: int) -> List[Alert]:
        """Получение алертов за указанный промежуток времени"""
        since = datetime.utcnow() - timedelta(minutes=minutes)
        return db.query(Alert).filter(Alert.timestamp >= since).all()

    def analyze_timeframe(self, db: Session, minutes: int) -> Dict:
        """Анализ алертов за указанный промежуток времени"""
        alerts = self.get_alerts_by_timeframe(db, minutes)
        
        if not alerts:
            return {
                'timeframe_minutes': minutes,
                'total_alerts': 0,
                'message': 'Нет алертов за указанный период'
            }
        
        # Статистика по severity
        severity_stats = {}
        for alert in alerts:
            severity_stats[alert.severity] = severity_stats.get(alert.severity, 0) + 1
        
        # Статистика по типам алертов
        alert_type_stats = {}
        for alert in alerts:
            alert_type_stats[alert.alert_type] = alert_type_stats.get(alert.alert_type, 0) + 1
        
        # Топ источников проблем
        source_ip_stats = {}
        for alert in alerts:
            if alert.source_ip:
                source_ip_stats[alert.source_ip] = source_ip_stats.get(alert.source_ip, 0) + 1
        
        # Средний риск
        avg_risk = sum(alert.risk_score for alert in alerts) / len(alerts)
        
        # Самые частые алерты
        top_alerts = sorted(alert_type_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'timeframe_minutes': minutes,
            'timeframe_human': self._minutes_to_human(minutes),
            'total_alerts': len(alerts),
            'severity_stats': severity_stats,
            'alert_type_stats': alert_type_stats,
            'source_ip_stats': dict(sorted(source_ip_stats.items(), 
                                         key=lambda x: x[1], reverse=True)[:5]),
            'average_risk_score': round(avg_risk, 2),
            'top_alert_types': top_alerts,
            'critical_alerts_count': severity_stats.get('critical', 0),
            'warning_alerts_count': severity_stats.get('warning', 0),
            'start_time': datetime.utcnow() - timedelta(minutes=minutes),
            'end_time': datetime.utcnow()
        }

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

    def generate_report_message(self, analysis: Dict) -> str:
        """Генерация сообщения для Telegram"""
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
        
        return message