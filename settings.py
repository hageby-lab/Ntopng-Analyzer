from pydantic_settings import BaseSettings
from typing import List, Optional, Dict
from functools import lru_cache
from enum import Enum

class Settings(BaseSettings):
    """Application settings"""
    
    # Telegram
    telegram_bot_token: str = "test"
    telegram_channel_id: str = "@test"
    
    # Database - ИСПРАВЛЕННЫЙ URL для aiosqlite
    database_url: str = "sqlite+aiosqlite:///./ntopng_alerts.db"
    
    # Server
    server_host: str = "0.0.0.0"
    server_port: int = 8000
    debug: bool = True
    
    # Analysis intervals in minutes
    analysis_intervals: List[int] = [5, 15, 30, 60, 1440, 10080, 43200]
    
    # Ntopng webhook secret
    webhook_secret: Optional[str] = None
    
    # Report settings
    top_alerts_count: int = 10
    
    # Redis for caching and Celery
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl: int = 300
    
    # Logging
    log_level: str = "INFO"
    log_file: str = "logs/ntopng_analyzer.log"
    
    # API prefixes
    api_v1_prefix: str = "/api/v1"
    
    class Config:
        env_file = ".env"
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    """Get settings with caching"""
    return Settings()

# Application constants
class AlertTypes(str, Enum):
    """Alert types"""
    FLOW_FLOOD = "flow_flood"
    SCAN_DETECTED = "scan_detected"
    DDOS_ATTACK = "ddos_attack"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    BANDWIDTH_ALERT = "bandwidth_alert"
    SECURITY_ALERT = "security_alert"
    HOST_ALERT = "host_alert"
    INTERFACE_ALERT = "interface_alert"
    UNKNOWN = "unknown"

class SeverityLevels(str, Enum):
    """Severity levels"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

class Categories(str, Enum):
    """Alert categories"""
    SECURITY = "security"
    PERFORMANCE = "performance"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"

# Regular expressions for analysis
REGEX_PATTERNS = {
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'interface': r'interface[:\s]+([^\s,]+)',
}

# Patterns for alert analysis
ALERT_PATTERNS: Dict[str, str] = {
    AlertTypes.FLOW_FLOOD: r'Flow Flood|flow flood',
    AlertTypes.SCAN_DETECTED: r'Scan|scan|Port Scan',
    AlertTypes.DDOS_ATTACK: r'DDoS|Flood|DDoS Attack',
    AlertTypes.SUSPICIOUS_TRAFFIC: r'Suspicious|Anomaly|Anomalous',
    AlertTypes.BANDWIDTH_ALERT: r'Bandwidth|Throughput|Traffic',
    AlertTypes.SECURITY_ALERT: r'Security|Alert|Threat|Malicious',
    AlertTypes.HOST_ALERT: r'Host|host',
    AlertTypes.INTERFACE_ALERT: r'Interface|interface'
}

# Keywords for severity detection
SEVERITY_KEYWORDS: Dict[str, List[str]] = {
    SeverityLevels.CRITICAL: ['emergency', 'alert', 'critical', 'error'],
    SeverityLevels.WARNING: ['warning', 'notice'],
    SeverityLevels.INFO: ['info', 'debug', 'information']
}

# Analysis parameters
ANALYSIS_CONFIG = {
    'risk_scores': {
        'critical': 50,
        'warning': 25,
        'base_alert_type': 20
    },
    'max_top_items': 5,
    'recent_alerts_limit': 50,
    'cache_timeout': 300
}

# Protocols for analysis
PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']