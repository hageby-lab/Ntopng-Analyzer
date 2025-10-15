from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional, Dict, List, Any
from enum import Enum

class AlertSeverity(str, Enum):
    """Уровни серьезности алертов"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

class AlertCategory(str, Enum):
    """Категории алертов"""
    SECURITY = "security"
    PERFORMANCE = "performance"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"

# Модели запросов
class WebhookRequest(BaseModel):
    """Модель запроса для webhook ntopng"""
    message: str = Field(..., description="Текст алерта от ntopng")
    severity: Optional[str] = Field(None, description="Уровень серьезности")
    timestamp: Optional[str] = Field(None, description="Временная метка алерта")

    @validator('message')
    def message_not_empty(cls, v):
        """Валидация: сообщение не должно быть пустым"""
        if not v or not v.strip():
            raise ValueError('Message cannot be empty')
        return v.strip()

class BatchWebhookRequest(BaseModel):
    """Модель запроса для пакетной обработки алертов"""
    alerts: List[WebhookRequest] = Field(..., description="Список алертов для обработки")
    
    @validator('alerts')
    def alerts_not_empty(cls, v):
        """Валидация: список алертов не должен быть пустым"""
        if not v:
            raise ValueError('Alerts list cannot be empty')
        if len(v) > 1000:
            raise ValueError('Too many alerts in batch (max 1000)')
        return v

class TimeframeRequest(BaseModel):
    """Модель запроса для анализа временного промежутка"""
    minutes: int = Field(..., ge=1, le=43200, description="Период анализа в минутах (1-43200)")

# Модели ответов
class AlertResponse(BaseModel):
    """Модель ответа с информацией об алерте"""
    id: int = Field(..., description="ID алерта в базе данных")
    timestamp: datetime = Field(..., description="Время создания алерта")
    message: str = Field(..., description="Текст алерта")
    severity: str = Field(..., description="Уровень серьезности")
    alert_type: str = Field(..., description="Тип алерта")
    risk_score: int = Field(..., description="Оценка риска (0-100)")
    source_ip: Optional[str] = Field(None, description="IP-адрес источника")
    
    class Config:
        from_attributes = True

class AnalysisResponse(BaseModel):
    """Модель ответа с результатами анализа"""
    timeframe_minutes: int = Field(..., description="Период анализа в минутах")
    timeframe_human: str = Field(..., description="Период анализа в читаемом формате")
    total_alerts: int = Field(..., description="Общее количество алертов")
    severity_stats: Dict[str, int] = Field(..., description="Статистика по уровням серьезности")
    alert_type_stats: Dict[str, int] = Field(..., description="Статистика по типам алертов")
    source_ip_stats: Dict[str, int] = Field(..., description="Статистика по IP-адресам")
    average_risk_score: float = Field(..., description="Средняя оценка риска")
    top_alert_types: List[tuple] = Field(..., description="Топ типов алертов")
    critical_alerts_count: int = Field(..., description="Количество критических алертов")
    warning_alerts_count: int = Field(..., description="Количество предупреждений")
    start_time: datetime = Field(..., description="Начало периода анализа")
    end_time: datetime = Field(..., description="Конец периода анализа")

class HealthResponse(BaseModel):
    """Модель ответа для проверки здоровья"""
    status: str = Field(..., description="Статус сервиса")
    service: str = Field(..., description="Название сервиса")
    timestamp: datetime = Field(..., description="Время проверки")
    database_status: str = Field(..., description="Статус базы данных")
    cache_status: str = Field(..., description="Статус кэша")

class ErrorResponse(BaseModel):
    """Модель ответа об ошибке"""
    error: str = Field(..., description="Тип ошибки")
    detail: Optional[str] = Field(None, description="Детали ошибки")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Время ошибки")

class BatchProcessingResponse(BaseModel):
    """Модель ответа для пакетной обработки"""
    total_alerts: int = Field(..., description="Общее количество обработанных алертов")
    successful: int = Field(..., description="Количество успешно обработанных алертов")
    failed: int = Field(..., description="Количество алертов с ошибками")
    processing_time: float = Field(..., description="Время обработки в секундах")