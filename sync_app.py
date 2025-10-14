from fastapi import FastAPI, Request, HTTPException
from contextlib import asynccontextmanager
import logging
import json
import os
import datetime
import ipaddress
import socket
from collections import defaultdict
from sync_database import init_db
from settings import get_settings

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

settings = get_settings()

# Импорт Telegram сервиса с обработкой ошибок
telegram_service = None
try:
    from services.telegram_service import get_telegram_service
    telegram_service = get_telegram_service()
    if telegram_service:
        logger.info("✅ Telegram service imported successfully")
    else:
        logger.warning("⚠️ Telegram service is not available")
except ImportError as e:
    logger.warning(f"⚠️ Telegram service not found: {e}")
except Exception as e:
    logger.error(f"❌ Error importing Telegram service: {e}")

# Глобальные переменные для хранения исторических данных
historical_alerts = []
baseline_metrics = defaultdict(lambda: {'avg_bytes': 100000, 'avg_packets': 1000})

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 Starting ntopng analyzer application...")
    init_db()
    
    # Проверяем Telegram сервис при старте
    if telegram_service:
        try:
            logger.info("Testing Telegram connection...")
            test_result = await telegram_service.test_connection()
            if test_result['success']:
                logger.info(f"✅ Telegram сервис работает корректно. Бот: {test_result.get('bot_username')}")
            else:
                logger.warning(f"⚠️ Проблемы с Telegram: {test_result.get('error')}")
        except Exception as e:
            logger.error(f"❌ Ошибка тестирования Telegram: {e}")
    else:
        logger.warning("⚠️ Telegram сервис не доступен - уведомления отправляться не будут")
    
    logger.info("✅ Application started successfully!")
    yield
    # Shutdown
    logger.info("🛑 Application shutting down")

app = FastAPI(lifespan=lifespan, title="Ntopng Analyzer API", version="1.0.0")

def parse_timestamp(timestamp):
    """Парсит timestamp в читаемый формат DD.MM.YYYY HH:MM:SS"""
    try:
        if isinstance(timestamp, (int, float)) and timestamp > 1000000000:
            # UNIX timestamp
            dt = datetime.datetime.fromtimestamp(timestamp)
            return dt.strftime("%d.%m.%Y %H:%M:%S")
        elif isinstance(timestamp, str):
            # Пробуем разные форматы дат
            if timestamp.isdigit() and len(timestamp) == 10:
                dt = datetime.datetime.fromtimestamp(int(timestamp))
                return dt.strftime("%d.%m.%Y %H:%M:%S")
            else:
                return timestamp
        else:
            return str(timestamp)
    except:
        return str(timestamp)

def map_alert_type(alert_type_id: int) -> str:
    """Преобразует числовой тип алерта в читаемый формат"""
    alert_type_map = {
        1: "📊 Flow Alert",
        2: "🖥️ Host Alert", 
        3: "🌐 Network Alert",
        4: "🔌 Interface Alert",
        5: "⚙️ System Alert",
        6: "📡 Mac Alert",
        7: "🔧 SNMP Alert",
        8: "🐳 Container Alert",
        9: "💾 Pool Alert"
    }
    return alert_type_map.get(alert_type_id, f"❓ Unknown ({alert_type_id})")

def map_severity(severity_id: int) -> str:
    """Преобразует числовую серьезность в читаемый формат"""
    severity_map = {
        1: "🚨 Emergency",
        2: "🔴 Alert", 
        3: "🔴 Critical",
        4: "🟠 Error",
        5: "🟡 Warning", 
        6: "🔵 Notice",
        7: "ℹ️ Info",
        8: "🔍 Debug"
    }
    return severity_map.get(severity_id, f"❓ Unknown ({severity_id})")

def is_internal_ip(ip_str: str) -> bool:
    """Проверяет, является ли IP адрес внутренним"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Внутренние диапазоны IP
        internal_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ]
        return any(ip in network for network in internal_ranges)
    except:
        return False

def get_device_info(alert: dict, ip_field: str) -> str:
    """Получает информацию об устройстве для внутренних IP"""
    device_fields = ['device', 'hostname', 'name', 'entity_name', 'cli_name', 'srv_name']
    
    for field in device_fields:
        if field in alert and alert[field]:
            return f" - {alert[field]}"
    
    # Пробуем найти вложенные поля
    for key, value in alert.items():
        if isinstance(value, dict):
            for device_field in device_fields:
                if device_field in value and value[device_field]:
                    return f" - {value[device_field]}"
    
    return ""

def get_external_service_info(ip_str: str) -> str:
    """Получает информацию о сервисе для внешних IP"""
    try:
        # Известные сервисы и их IP
        known_services = {
            '8.8.8.8': 'Google DNS',
            '8.8.4.4': 'Google DNS',
            '1.1.1.1': 'Cloudflare DNS',
            '1.0.0.1': 'Cloudflare DNS',
            '9.9.9.9': 'Quad9 DNS',
            '208.67.222.222': 'OpenDNS',
            '208.67.220.220': 'OpenDNS',
            '104.18.27.90': 'chat.deepseek.com',
            '104.18.26.90': 'chat.deepseek.com',
            '20.112.52.29': 'Microsoft Azure',
            '20.50.2.244': 'Microsoft Office',
            '52.114.128.0': 'Microsoft Teams',
            '142.250.185.206': 'Google',
            '172.217.16.206': 'Google',
            '13.107.42.12': 'Microsoft',
            '40.90.136.183': 'Microsoft',
            '52.96.0.0': 'Microsoft',
            '104.16.0.0': 'Cloudflare',
            '104.17.0.0': 'Cloudflare',
            '151.101.0.0': 'Fastly CDN',
            '23.43.61.0': 'Akamai CDN',
            '185.60.216.0': 'Facebook',
            '31.13.64.0': 'Facebook',
            '199.96.57.0': 'Twitter',
            '104.244.42.0': 'Twitter',
            '74.125.0.0': 'YouTube',
            '173.194.0.0': 'YouTube',
            '13.33.0.0': 'Amazon AWS',
            '52.0.0.0': 'Amazon AWS',
            '54.0.0.0': 'Amazon AWS',
        }
        
        # Проверяем известные сервисы
        if ip_str in known_services:
            return f" - {known_services[ip_str]}"
        
        # Пробуем обратный DNS lookup (с таймаутом)
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
            if hostname and hostname != ip_str:
                # Обрезаем длинные доменные имена
                if len(hostname) > 30:
                    hostname = hostname[:27] + "..."
                return f" - {hostname}"
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        
        # Проверяем по подсетям
        ip = ipaddress.ip_address(ip_str)
        for network, service in [
            (ipaddress.ip_network('8.8.0.0/16'), 'Google'),
            (ipaddress.ip_network('1.1.0.0/16'), 'Cloudflare'),
            (ipaddress.ip_network('9.9.0.0/16'), 'Quad9'),
            (ipaddress.ip_network('208.67.220.0/24'), 'OpenDNS'),
            (ipaddress.ip_network('20.0.0.0/8'), 'Microsoft Azure'),
            (ipaddress.ip_network('52.0.0.0/8'), 'Amazon AWS'),
            (ipaddress.ip_network('54.0.0.0/8'), 'Amazon AWS'),
            (ipaddress.ip_network('104.16.0.0/12'), 'Cloudflare'),
            (ipaddress.ip_network('172.217.0.0/16'), 'Google'),
            (ipaddress.ip_network('142.250.0.0/16'), 'Google'),
        ]:
            if ip in network:
                return f" - {service}"
        
        return ""
        
    except:
        return ""

def get_ip_info(ip_str: str, alert: dict = None, is_source: bool = True) -> tuple:
    """Возвращает информацию о типе IP адреса и дополнительную информацию"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        base_info = ""
        additional_info = ""
        
        if ip.is_private:
            base_info = "🛡️ Внутренняя сеть"
            # Для внутренних IP добавляем информацию об устройстве
            if alert:
                additional_info = get_device_info(alert, 'src_ip' if is_source else 'dst_ip')
        elif ip.is_multicast:
            base_info = "📢 Multicast"
        elif ip.is_loopback:
            base_info = "🔁 Loopback"
        elif ip.is_link_local:
            base_info = "🔗 Link-local"
        elif ip.is_unspecified:
            base_info = "❓ Неопределенный"
        elif ip.is_global:
            # Проверяем специальные диапазоны
            if ip in ipaddress.ip_network('224.0.0.0/4'):
                base_info = "📢 Multicast"
            elif ip in ipaddress.ip_network('240.0.0.0/4'):
                base_info = "🚫 Зарезервировано"
            else:
                base_info = "🌐 Внешний интернет"
                # Для внешних IP добавляем информацию о сервисе
                additional_info = get_external_service_info(ip_str)
        else:
            base_info = "🌐 Внешний адрес"
            additional_info = get_external_service_info(ip_str)
        
        return base_info, additional_info
        
    except:
        return "❓ Неизвестный адрес", ""

def analyze_connection_direction(source: str, target: str, alert: dict) -> dict:
    """Анализирует направление соединения"""
    source_internal = is_internal_ip(source)
    target_internal = is_internal_ip(target)
    
    source_type, source_info = get_ip_info(source, alert, is_source=True)
    target_type, target_info = get_ip_info(target, alert, is_source=False)
    
    analysis = {
        "direction": "❓ Неизвестно",
        "description": "",
        "source_type": source_type,
        "source_info": source_info,
        "target_type": target_type, 
        "target_info": target_info
    }
    
    if source_internal and target_internal:
        analysis["direction"] = "🔄 Внутреннее"
        analysis["description"] = "Соединение между внутренними узлами"
    elif source_internal and not target_internal:
        analysis["direction"] = "📤 Исходящее"
        analysis["description"] = "Исходящее соединение во внешнюю сеть"
    elif not source_internal and target_internal:
        analysis["direction"] = "📥 Входящее" 
        analysis["description"] = "Входящее соединение из внешней сети"
    else:
        analysis["direction"] = "🌐 Внешнее"
        analysis["description"] = "Соединение между внешними узлами"
    
    return analysis

def analyze_traffic_behavior(alert: dict, historical_data: list) -> dict:
    """Анализ поведенческих паттернов трафика"""
    analysis = {
        "traffic_pattern": "Нормальный",
        "anomaly_score": 0,
        "behavior_insights": []
    }
    
    # Анализ временных паттернов
    current_hour = datetime.datetime.now().hour
    bytes_sent = alert.get('bytes', 0)
    
    if current_hour in [2, 3, 4] and bytes_sent > 1000000:  # Ночной трафик
        analysis["traffic_pattern"] = "⚠️ Ночная активность"
        analysis["anomaly_score"] += 30
        analysis["behavior_insights"].append("Высокий трафик в нерабочее время")
    
    # Анализ протоколов
    protocol = str(alert.get('protocol', '')).upper()
    if protocol in ['SSH', 'RDP', 'TELNET'] and is_internal_ip(alert.get('src_ip', '')):
        analysis["traffic_pattern"] = "🔐 Управляющий трафик"
        analysis["behavior_insights"].append(f"Трафик управления ({protocol})")
    
    # Анализ объемов данных
    if bytes_sent > 500000000:  # 500MB
        analysis["traffic_pattern"] = "📦 Крупная передача"
        analysis["anomaly_score"] += 20
        analysis["behavior_insights"].append(f"Передано {bytes_sent//1000000}MB данных")
    
    # Анализ частоты пакетов
    packets = alert.get('packets', 0)
    if packets > 10000:
        analysis["traffic_pattern"] = "⚡ Высокая частота пакетов"
        analysis["anomaly_score"] += 15
        analysis["behavior_insights"].append(f"Высокая частота: {packets} пакетов")
    
    return analysis

def analyze_threat_intelligence(alert: dict) -> dict:
    """Анализ признаков компрометации"""
    threat_analysis = {
        "suspicious_indicators": [],
        "threat_level": "Низкий",
        "recommended_actions": []
    }
    
    src_ip = alert.get('src_ip', '')
    dst_ip = alert.get('dst_ip', '')
    port = alert.get('port', 0)
    
    # Известные порты для ботнетов и malware
    malicious_ports = [4444, 1337, 31337, 12345, 54321, 9999, 666, 999]
    if port in malicious_ports:
        threat_analysis["suspicious_indicators"].append(f"Подозрительный порт: {port}")
        threat_analysis["threat_level"] = "Высокий"
        threat_analysis["recommended_actions"].append("Проверить систему на наличие malware")
    
    # Аномальные DNS запросы
    if port == 53 and alert.get('bytes', 0) > 100000:
        threat_analysis["suspicious_indicators"].append("Аномально большой DNS трафик")
        threat_analysis["threat_level"] = "Средний"
        threat_analysis["recommended_actions"].append("Проверить DNS запросы на признаки DNS tunneling")
    
    # Tor трафик (известные Tor exit nodes)
    tor_prefixes = ['185.220.101.', '195.176.3.', '178.20.55.', '85.248.227.']
    if any(src_ip.startswith(prefix) for prefix in tor_prefixes):
        threat_analysis["suspicious_indicators"].append("Трафик через Tor сеть")
        threat_analysis["threat_level"] = "Высокий"
        threat_analysis["recommended_actions"].append("Проверить легитимность использования Tor")
    
    # Порт сканирования
    if alert.get('packets', 0) > 1000 and port in range(1, 1000):
        threat_analysis["suspicious_indicators"].append("Признаки сканирования портов")
        threat_analysis["threat_level"] = "Высокий"
        threat_analysis["recommended_actions"].append("Проверить журналы безопасности на сканирование")
    
    # Необычные комбинации протоколов
    protocol = str(alert.get('protocol', '')).upper()
    if protocol == 'ICMP' and alert.get('bytes', 0) > 10000:
        threat_analysis["suspicious_indicators"].append("Подозрительный ICMP трафик")
        threat_analysis["threat_level"] = "Средний"
    
    return threat_analysis

def analyze_geo_reputation(ip: str, is_source: bool) -> dict:
    """Анализ геолокации и репутации IP"""
    geo_analysis = {
        "country": "Неизвестно",
        "risk_factors": [],
        "reputation": "Нейтральная"
    }
    
    # Простая база стран по IP диапазонам
    country_ranges = {
        'RU': ['77.', '78.', '79.', '85.', '87.', '89.', '90.', '93.', '95.'],
        'CN': ['1.', '14.', '27.', '36.', '39.', '42.', '49.', '58.', '60.'],
        'US': ['8.', '13.', '23.', '32.', '45.', '50.', '52.', '63.', '64.', '65.', '66.', '67.', '68.'],
        'DE': ['46.', '62.', '77.', '78.', '79.', '80.', '81.', '82.', '83.', '84.', '85.', '86.', '87.'],
        'NL': ['84.', '85.', '86.', '87.', '88.', '89.', '90.', '91.', '92.', '93.', '94.'],
        'UA': ['91.', '92.', '93.', '94.', '95.', '176.', '185.', '195.'],
        'TR': ['78.', '79.', '80.', '81.', '82.', '83.', '84.', '85.', '86.', '87.', '88.'],
    }
    
    for country, prefixes in country_ranges.items():
        if any(ip.startswith(prefix) for prefix in prefixes):
            geo_analysis["country"] = country
            break
    
    # Анализ рисков по стране
    high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'SY']
    medium_risk_countries = ['UA', 'TR', 'BY', 'KZ']
    
    if geo_analysis["country"] in high_risk_countries:
        geo_analysis["risk_factors"].append(f"Высокорисковая страна: {geo_analysis['country']}")
        geo_analysis["reputation"] = "Высокий риск"
    elif geo_analysis["country"] in medium_risk_countries:
        geo_analysis["risk_factors"].append(f"Среднерисковая страна: {geo_analysis['country']}")
        geo_analysis["reputation"] = "Средний риск"
    elif geo_analysis["country"] == "Неизвестно":
        geo_analysis["risk_factors"].append("Неизвестная геолокация")
        geo_analysis["reputation"] = "Подозрительная"
    
    return geo_analysis

def predict_incident_evolution(alert: dict, similar_alerts: list) -> dict:
    """Прогноз развития инцидента на основе похожих алертов"""
    prediction = {
        "likely_scenario": "Неизвестно",
        "confidence": "Низкая",
        "timeline": "Непредсказуемо",
        "escalation_probability": 0
    }
    
    alert_type = alert.get('alert_type', 0)
    severity = alert.get('severity', 7)
    message = str(alert.get('message', '')).lower()
    
    # Прогнозы на основе типа алерта
    if alert_type == 3:  # Network Alert
        if any('ddos' in str(a.get('message', '')).lower() for a in similar_alerts[:3]):
            prediction["likely_scenario"] = "DDoS атака"
            prediction["confidence"] = "Высокая"
            prediction["timeline"] = "Минуты-часы"
            prediction["escalation_probability"] = 80
        elif any('scan' in str(a.get('message', '')).lower() for a in similar_alerts[:5]):
            prediction["likely_scenario"] = "Подготовка к атаке"
            prediction["confidence"] = "Средняя"
            prediction["timeline"] = "Часы-дни"
            prediction["escalation_probability"] = 60
        elif 'flood' in message:
            prediction["likely_scenario"] = "Сетевой флуд"
            prediction["confidence"] = "Средняя"
            prediction["timeline"] = "Минуты"
            prediction["escalation_probability"] = 70
    
    elif alert_type == 2:  # Host Alert
        if severity <= 3:  # Critical alerts
            prediction["likely_scenario"] = "Компрометация системы"
            prediction["confidence"] = "Средняя"
            prediction["timeline"] = "Минуты-часы"
            prediction["escalation_probability"] = 70
        elif 'scan' in message:
            prediction["likely_scenario"] = "Реконносцировка сети"
            prediction["confidence"] = "Высокая"
            prediction["timeline"] = "Часы"
            prediction["escalation_probability"] = 60
    
    elif alert_type == 1:  # Flow Alert
        bytes_sent = alert.get('bytes', 0)
        if bytes_sent > 1000000000:  # 1GB
            prediction["likely_scenario"] = "Утечка данных"
            prediction["confidence"] = "Средняя"
            prediction["timeline"] = "Минуты"
            prediction["escalation_probability"] = 65
    
    return prediction

def generate_response_recommendations(alert: dict, threat_analysis: dict) -> list:
    """Генерация рекомендаций по реагированию"""
    recommendations = []
    
    # Базовые рекомендации по типу алерта
    alert_type = alert.get('alert_type', 0)
    if alert_type == 3:  # Network Alert
        recommendations.extend([
            "🔍 Проверить сетевые устройства на перегрузку",
            "📊 Проанализировать трафик на наличие DDoS паттернов",
            "🛡️ Временное ограничение трафика с источника"
        ])
    elif alert_type == 2:  # Host Alert
        recommendations.extend([
            "🖥️ Проверить состояние хоста",
            "📝 Анализировать логи системы",
            "🔒 Проверить правила доступа"
        ])
    
    # Рекомендации по уровню угрозы
    threat_level = threat_analysis.get('threat_level', 'Низкий')
    if threat_level == "Высокий":
        recommendations.extend([
            "🚨 Изолировать затронутые системы",
            "📞 Уведомить команду безопасности",
            "📝 Начать сбор доказательств для расследования"
        ])
    elif threat_level == "Средний":
        recommendations.extend([
            "🔍 Усилить мониторинг системы",
            "📊 Собрать дополнительные метрики",
            "🛡️ Проверить конфигурацию безопасности"
        ])
    
    # Специфические рекомендации по портам
    port = alert.get('port', 0)
    if port in [22, 3389, 23]:  # SSH, RDP, Telnet
        recommendations.append("🔐 Проверить логи аутентификации")
    elif port == 53:  # DNS
        recommendations.append("🌐 Проверить DNS запросы на аномалии")
    elif port in [80, 443, 8080]:  # HTTP/HTTPS
        recommendations.append("🌍 Проверить веб-логи на подозрительные запросы")
    
    # Рекомендации по объему трафика
    bytes_sent = alert.get('bytes', 0)
    if bytes_sent > 1000000000:  # 1GB
        recommendations.append("💾 Проверить системы на утечку данных")
    
    return recommendations[:6]  # Ограничиваем 6 рекомендациями

def calculate_composite_risk(basic_analysis: dict, threat_intel: dict, traffic_behavior: dict) -> int:
    """Расчет комплексного показателя риска"""
    risk_score = 0
    
    # Базовый риск
    risk_map = {"Низкий": 10, "Средний": 50, "Высокий": 80, "Критический": 95}
    risk_score += risk_map.get(basic_analysis.get("risk_level", "Низкий"), 10)
    
    # Угрозы
    threat_map = {"Низкий": 0, "Средний": 20, "Высокий": 40}
    risk_score += threat_map.get(threat_intel.get("threat_level", "Низкий"), 0)
    
    # Аномалии трафика
    risk_score += traffic_behavior.get("anomaly_score", 0)
    
    return min(risk_score, 100)

def enhanced_alert_analysis(alert: dict, historical_data: list = None) -> dict:
    """Полная улучшенная аналитика алерта"""
    if historical_data is None:
        historical_data = []
    
    # Базовая аналитика
    basic_analysis = analyze_alert(alert)
    
    # Расширенная аналитика
    traffic_behavior = analyze_traffic_behavior(alert, historical_data)
    threat_intel = analyze_threat_intelligence(alert)
    geo_source = analyze_geo_reputation(alert.get('src_ip', ''), True)
    geo_target = analyze_geo_reputation(alert.get('dst_ip', ''), False)
    incident_prediction = predict_incident_evolution(alert, historical_data)
    response_recommendations = generate_response_recommendations(alert, threat_intel)
    
    # Сводный анализ
    comprehensive_analysis = {
        **basic_analysis,
        "traffic_behavior": traffic_behavior,
        "threat_intelligence": threat_intel,
        "geo_analysis": {
            "source": geo_source,
            "target": geo_target
        },
        "incident_prediction": incident_prediction,
        "response_recommendations": response_recommendations,
        "composite_risk_score": calculate_composite_risk(
            basic_analysis, threat_intel, traffic_behavior
        )
    }
    
    return comprehensive_analysis

def analyze_alert(alert: dict) -> dict:
    """Анализирует алерт и возвращает аналитику"""
    analysis = {
        "problem": "Неизвестная проблема",
        "source": "Не определен",
        "target": "Не определен", 
        "recommendation": "Проверить детали алерта",
        "risk_level": "Низкий",
        "connection_direction": "❓ Неизвестно",
        "connection_description": "",
        "source_type": "",
        "source_info": "",
        "target_type": "",
        "target_info": ""
    }
    
    # Определяем источник и цель
    source_fields = ['src_ip', 'source_ip', 'src_addr', 'source', 'host', 'entity_value', 'cli_ip', 'client_ip']
    target_fields = ['dst_ip', 'dest_ip', 'dst_addr', 'destination', 'target', 'entity_value', 'srv_ip', 'server_ip']
    
    for field in source_fields:
        if field in alert and alert[field]:
            analysis["source"] = alert[field]
            break
            
    for field in target_fields:
        if field in alert and alert[field]:
            analysis["target"] = alert[field]
            break
    
    # Анализируем направление соединения
    if analysis["source"] != "Не определен" and analysis["target"] != "Не определен":
        connection_analysis = analyze_connection_direction(analysis["source"], analysis["target"], alert)
        analysis.update(connection_analysis)
    
    # Анализируем тип алерта и определяем проблему
    alert_type = alert.get('alert_type', 0)
    message = str(alert.get('message', '')).lower()
    
    if alert_type == 1:  # Flow Alert
        analysis["problem"] = "Аномалия трафика потоков"
        analysis["recommendation"] = "Проверить правила фаервола и лимиты трафика"
        analysis["risk_level"] = "Средний"
        
    elif alert_type == 2:  # Host Alert
        if any(word in message for word in ['scan', 'сканирование']):
            analysis["problem"] = "Обнаружено сканирование портов"
            analysis["recommendation"] = "Проверить безопасность хоста, обновить правила доступа"
            analysis["risk_level"] = "Высокий"
        elif any(word in message for word in ['flood', 'перегрузка']):
            analysis["problem"] = "Перегрузка хоста"
            analysis["recommendation"] = "Проверить нагрузку на хост, оптимизировать конфигурацию"
            analysis["risk_level"] = "Средний"
        else:
            analysis["problem"] = "Проблема с хостом"
            analysis["recommendation"] = "Проверить состояние и конфигурацию хоста"
            
    elif alert_type == 3:  # Network Alert
        if any(word in message for word in ['ddos', 'атака']):
            analysis["problem"] = "Возможная DDoS атака"
            analysis["recommendation"] = "Активировать защиту от DDoS, проверить сетевую инфраструктуру"
            analysis["risk_level"] = "Критический"
        elif any(word in message for word in ['flood', 'поток']):
            analysis["problem"] = "Сетевой флуд"
            analysis["recommendation"] = "Настроить ограничения трафика, проверить сетевое оборудование"
            analysis["risk_level"] = "Высокий"
        else:
            analysis["problem"] = "Сетевая аномалия"
            analysis["recommendation"] = "Проверить сетевое оборудование и конфигурацию"
            
    elif alert_type == 4:  # Interface Alert
        analysis["problem"] = "Проблема с интерфейсом"
        analysis["recommendation"] = "Проверить физическое подключение и настройки интерфейса"
        analysis["risk_level"] = "Средний"
        
    # Дополнительный анализ по содержимому сообщения
    if 'bandwidth' in message or 'трафик' in message:
        analysis["problem"] = "Превышение пропускной способности"
        analysis["recommendation"] = "Увеличить лимиты трафика или оптимизировать использование"
        
    elif 'security' in message or 'безопасность' in message:
        analysis["problem"] = "Нарушение безопасности"
        analysis["recommendation"] = "Проверить журналы безопасности, обновить правила доступа"
        analysis["risk_level"] = "Высокий"
        
    elif 'suspicious' in message or 'подозрительный' in message:
        analysis["problem"] = "Подозрительная активность"
        analysis["recommendation"] = "Провести детальный анализ активности"
        analysis["risk_level"] = "Средний"
    
    # Корректируем уровень риска на основе направления
    if analysis["direction"] == "📥 Входящее" and analysis["risk_level"] == "Низкий":
        analysis["risk_level"] = "Средний"
    elif analysis["direction"] == "📥 Входящее" and analysis["source_type"] == "🌐 Внешний интернет":
        analysis["risk_level"] = "Высокий"
    
    return analysis

def format_telegram_message(alert_data: dict) -> str:
    """Форматирует сообщение для Telegram с улучшенной аналитикой"""
    
    # Проверяем, есть ли поле alerts с массивом алертов
    if 'alerts' in alert_data and isinstance(alert_data['alerts'], list) and alert_data['alerts']:
        # Берем первый алерт из массива
        alert = alert_data['alerts'][0]
        logger.info(f"📊 Found {len(alert_data['alerts'])} alerts, processing first one")
        
        # Добавляем в историю для анализа
        historical_alerts.append(alert)
        if len(historical_alerts) > 100:  # Ограничиваем историю
            historical_alerts.pop(0)
    else:
        # Используем корневой объект как алерт
        alert = alert_data
        logger.info("📊 Using root object as alert")
    
    # Детальный парсинг всех возможных полей ntopng
    alert_id = 'N/A'
    message = 'Нет описания'
    alert_type = 'unknown'
    severity = 'info'
    
    # Парсим ID из различных полей
    for field in ['alert_id', 'id', '_id', 'alertId', 'event_id', 'uuid', 'name', 'title', 'alert_id']:
        if field in alert and alert[field] is not None:
            alert_id = alert[field]
            break
    
    # Парсим сообщение из различных полей
    message_fields = ['message', 'description', 'alert_message', 'msg', 'alert', 'info', 
                     'content', 'text', 'details', 'summary', 'string', 'subtype', 'action',
                     'reason', 'info', 'status', 'comment']
    
    found_message = False
    for field in message_fields:
        if field in alert and alert[field] is not None and str(alert[field]).strip():
            message = str(alert[field])
            found_message = True
            logger.info(f"📝 Found message in field '{field}': {message[:100]}...")
            break
    
    # Если сообщение не найдено, попробуем найти вложенные объекты
    if not found_message:
        for key, value in alert.items():
            if isinstance(value, dict):
                for sub_field in message_fields:
                    if sub_field in value and value[sub_field] is not None and str(value[sub_field]).strip():
                        message = str(value[sub_field])
                        found_message = True
                        logger.info(f"📝 Found message in nested field '{key}.{sub_field}': {message[:100]}...")
                        break
                if found_message:
                    break
    
    # Парсим тип алерта
    for field in ['alert_type', 'type', 'category', 'event_type', 'alert_category', 'family', 'alert_type']:
        if field in alert and alert[field] is not None:
            alert_type_value = alert[field]
            if isinstance(alert_type_value, int):
                alert_type = map_alert_type(alert_type_value)
            else:
                alert_type = str(alert_type_value)
            break
    
    # Парсим серьезность
    for field in ['severity', 'level', 'priority', 'alert_severity', 'gravity', 'severity']:
        if field in alert and alert[field] is not None:
            severity_value = alert[field]
            if isinstance(severity_value, int):
                severity = map_severity(severity_value)
            else:
                severity = str(severity_value)
            break
    
    # Анализируем алерт с улучшенной аналитикой
    comprehensive_analysis = enhanced_alert_analysis(alert, historical_alerts)
    
    # Эмодзи для разных уровней серьезности
    severity_emoji = {
        'critical': '🔴',
        'warning': '🟡', 
        'info': '🔵',
        'error': '🔴',
        'high': '🔴',
        'medium': '🟡',
        'low': '🔵',
        '1': '🔴',
        '2': '🔴',
        '3': '🔴',
        '4': '🟡',
        '5': '🟡',
        '6': '🔵',
        '7': '🔵',
    }
    
    emoji = severity_emoji.get(str(severity).lower(), '🔔')
    
    # Обрезаем длинное сообщение
    if len(message) > 150:
        message = message[:150] + "..."
    
    # Собираем информацию
    info_section = ""
    
    # Время
    for time_field in ['timestamp', 'time', 'alert_time', 'event_time', 'created_at']:
        if time_field in alert and alert[time_field] is not None:
            info_section += f"\n🕒 Время: {parse_timestamp(alert[time_field])}"
            break
    
    # Источник и цель с типами и дополнительной информацией
    source_display = f"{comprehensive_analysis['source']}{comprehensive_analysis['source_info']}"
    target_display = f"{comprehensive_analysis['target']}{comprehensive_analysis['target_info']}"
    
    info_section += f"\n📡 Источник: {source_display} ({comprehensive_analysis['source_type']})"
    info_section += f"\n🎯 Назначение: {target_display} ({comprehensive_analysis['target_type']})"
    info_section += f"\n📊 Направление: {comprehensive_analysis['connection_direction']}"
    
    # Дополнительные важные поля (исключаем tstamp и is_victim)
    important_fields = {
        'protocol': '📋 Протокол',
        'interface': '🔌 Интерфейс', 
        'port': '🔗 Порт',
        'bytes': '📊 Байты',
        'packets': '📦 Пакеты',
        'metric': '📐 Метрика',
        'value': '🔢 Значение',
        'threshold': '⚖️ Порог'
    }
    
    for field, display_name in important_fields.items():
        if field in alert and alert[field] is not None and field not in ['tstamp', 'is_victim']:
            info_section += f"\n{display_name}: {alert[field]}"
    
    # Расширенная аналитическая секция
    risk_score = comprehensive_analysis['composite_risk_score']
    risk_emoji = "🔴" if risk_score > 80 else "🟡" if risk_score > 50 else "🔵"
    
    analysis_section = f"""
🔍 <b>РАСШИРЕННАЯ АНАЛИТИКА</b>
├─ Общий риск: {risk_emoji} {risk_score}/100
├─ Паттерн трафика: {comprehensive_analysis['traffic_behavior']['traffic_pattern']}
├─ Уровень угроз: {comprehensive_analysis['threat_intelligence']['threat_level']}
├─ Гео-риск: {comprehensive_analysis['geo_analysis']['source']['reputation']}

🕵️‍♂️ <b>ПОВЕДЕНЧЕСКИЙ АНАЛИЗ</b>"""
    
    # Добавляем инсайты поведения
    for insight in comprehensive_analysis['traffic_behavior']['behavior_insights']:
        analysis_section += f"\n├─ {insight}"
    
    # Добавляем индикаторы угроз
    if comprehensive_analysis['threat_intelligence']['suspicious_indicators']:
        analysis_section += f"\n\n🛡️ <b>ИНДИКАТОРЫ УГРОЗ</b>"
        for indicator in comprehensive_analysis['threat_intelligence']['suspicious_indicators']:
            analysis_section += f"\n├─ {indicator}"
    
    # Добавляем прогноз
    analysis_section += f"""
\n📈 <b>ПРОГНОЗ ИНЦИДЕНТА</b>
├─ Сценарий: {comprehensive_analysis['incident_prediction']['likely_scenario']}
├─ Уверенность: {comprehensive_analysis['incident_prediction']['confidence']}
├─ Время: {comprehensive_analysis['incident_prediction']['timeline']}
└─ Эскалация: {comprehensive_analysis['incident_prediction']['escalation_probability']}%

🚨 <b>РЕКОМЕНДАЦИИ</b>"""
    
    # Добавляем рекомендации
    for i, recommendation in enumerate(comprehensive_analysis['response_recommendations']):
        prefix = "└─" if i == len(comprehensive_analysis['response_recommendations']) - 1 else "├─"
        analysis_section += f"\n{prefix} {recommendation}"
    
    # Добавляем информацию о количестве алертов если есть массив
    if 'alerts' in alert_data and isinstance(alert_data['alerts'], list) and len(alert_data['alerts']) > 1:
        info_section += f"\n📈 Всего алертов: {len(alert_data['alerts'])}"
    
    return f"""
{emoji} <b>NTOPNG АЛЕРТ - КОМПЛЕКСНЫЙ АНАЛИЗ</b>
├─ ID: <code>{alert_id}</code>
├─ Тип: {alert_type}  
├─ Серьезность: {severity}
└─ Описание: {message}{info_section}{analysis_section}
"""

@app.post("/webhook")
async def receive_webhook(request: Request):
    """
    Получение webhook от ntopng
    """
    try:
        # Получаем данные от ntopng
        data = await request.json()
        
        # Детальное логирование входящих данных
        logger.info("📨 Received webhook from ntopng")
        logger.info(f"📊 Root data keys: {list(data.keys())}")
        
        # Логируем структуру алертов если есть
        if 'alerts' in data:
            logger.info(f"📈 Found alerts array with {len(data['alerts'])} items")
            if data['alerts']:
                first_alert = data['alerts'][0]
                logger.info(f"📋 First alert keys: {list(first_alert.keys())}")
        
        # Выводим полные данные в консоль для отладки
        print("=== NTOPNG WEBHOOK STRUCTURE ===")
        print("Root keys:", list(data.keys()))
        if 'alerts' in data and data['alerts']:
            print(f"Alerts count: {len(data['alerts'])}")
            print("First alert keys:", list(data['alerts'][0].keys()))
            print("First alert data:")
            print(json.dumps(data['alerts'][0], indent=2, ensure_ascii=False))
        else:
            print("Full data:")
            print(json.dumps(data, indent=2, ensure_ascii=False))
        print("===========================")
        
        # Сохраняем в БД
        # TODO: Здесь добавить сохранение в БД
        
        # Отправляем в Telegram
        telegram_sent = False
        telegram_error = None
        
        if telegram_service:
            try:
                telegram_message = format_telegram_message(data)
                telegram_result = await telegram_service.send_message(telegram_message)
                
                if telegram_result['success']:
                    logger.info("✅ Alert sent to Telegram successfully")
                    telegram_sent = True
                else:
                    logger.error(f"❌ Failed to send to Telegram: {telegram_result.get('error')}")
                    telegram_error = telegram_result.get('error')
            except Exception as e:
                logger.error(f"❌ Error sending to Telegram: {e}")
                telegram_error = str(e)
        else:
            logger.warning("⚠️ Telegram service not available - skipping notification")
        
        return {
            "status": "success", 
            "message": "Webhook received",
            "alerts_count": len(data.get('alerts', [])),
            "data_keys": list(data.keys()),
            "telegram_sent": telegram_sent,
            "telegram_error": telegram_error
        }
        
    except json.JSONDecodeError as e:
        logger.error(f"❌ Invalid JSON in webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"❌ Error processing webhook: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/")
async def root():
    """Корневой эндпоинт"""
    return {
        "message": "Ntopng Analyzer API", 
        "version": "1.0.0",
        "telegram_available": telegram_service is not None
    }

@app.get("/debug/telegram")
async def debug_telegram():
    """Диагностика Telegram"""
    try:
        if not telegram_service:
            return {
                "telegram_configured": False,
                "error": "Telegram service not initialized",
                "settings": {
                    "bot_token_set": bool(settings.telegram_bot_token),
                    "channel_id_set": bool(settings.telegram_channel_id),
                    "bot_token": settings.telegram_bot_token[:10] + "..." if settings.telegram_bot_token else None,
                    "channel_id": settings.telegram_channel_id
                }
            }
            
        # Тестируем подключение
        test_result = await telegram_service.test_connection()
        
        return {
            "telegram_configured": True,
            "test_success": test_result['success'],
            "bot_info": {
                "username": test_result.get('bot_username'),
                "name": test_result.get('bot_name')
            },
            "error": test_result.get('error'),
            "settings": {
                "bot_token_set": bool(settings.telegram_bot_token),
                "channel_id_set": bool(settings.telegram_channel_id),
                "channel_id": settings.telegram_channel_id
            }
        }
    except Exception as e:
        return {
            "telegram_configured": False,
            "error": str(e),
            "settings": {
                "bot_token_set": bool(settings.telegram_bot_token),
                "channel_id_set": bool(settings.telegram_channel_id),
            }
        }

@app.get("/debug/env")
async def debug_env():
    """Показывает текущие настройки окружения"""
    return {
        "environment": {
            "telegram_bot_token": "SET" if os.getenv('TELEGRAM_BOT_TOKEN') else "NOT SET",
            "telegram_channel_id": "SET" if os.getenv('TELEGRAM_CHANNEL_ID') else "NOT SET", 
        },
        "current_settings": {
            "bot_token": settings.telegram_bot_token[:10] + "..." if settings.telegram_bot_token else None,
            "channel_id": settings.telegram_channel_id,
            "server_host": settings.server_host,
            "server_port": settings.server_port
        },
        "telegram_service_available": telegram_service is not None
    }

@app.get("/health")
async def health_check():
    """Проверка здоровья приложения"""
    return {
        "status": "healthy",
        "service": "ntopng-analyzer",
        "telegram_available": telegram_service is not None,
        "server": f"{settings.server_host}:{settings.server_port}"
    }

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting server on {settings.server_host}:{settings.server_port}")
    uvicorn.run(
        app, 
        host=settings.server_host, 
        port=settings.server_port,
        log_level="info"
    )