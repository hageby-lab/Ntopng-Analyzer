from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional, Dict, List, Any
from enum import Enum

class AlertSeverity(str, Enum):
    """������ ����������� �������"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

class AlertCategory(str, Enum):
    """��������� �������"""
    SECURITY = "security"
    PERFORMANCE = "performance"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"

# ������ ��������
class WebhookRequest(BaseModel):
    """������ ������� ��� webhook ntopng"""
    message: str = Field(..., description="����� ������ �� ntopng")
    severity: Optional[str] = Field(None, description="������� �����������")
    timestamp: Optional[str] = Field(None, description="��������� ����� ������")

    @validator('message')
    def message_not_empty(cls, v):
        """���������: ��������� �� ������ ���� ������"""
        if not v or not v.strip():
            raise ValueError('Message cannot be empty')
        return v.strip()

class BatchWebhookRequest(BaseModel):
    """������ ������� ��� �������� ��������� �������"""
    alerts: List[WebhookRequest] = Field(..., description="������ ������� ��� ���������")
    
    @validator('alerts')
    def alerts_not_empty(cls, v):
        """���������: ������ ������� �� ������ ���� ������"""
        if not v:
            raise ValueError('Alerts list cannot be empty')
        if len(v) > 1000:
            raise ValueError('Too many alerts in batch (max 1000)')
        return v

class TimeframeRequest(BaseModel):
    """������ ������� ��� ������� ���������� ����������"""
    minutes: int = Field(..., ge=1, le=43200, description="������ ������� � ������� (1-43200)")

# ������ �������
class AlertResponse(BaseModel):
    """������ ������ � ����������� �� ������"""
    id: int = Field(..., description="ID ������ � ���� ������")
    timestamp: datetime = Field(..., description="����� �������� ������")
    message: str = Field(..., description="����� ������")
    severity: str = Field(..., description="������� �����������")
    alert_type: str = Field(..., description="��� ������")
    risk_score: int = Field(..., description="������ ����� (0-100)")
    source_ip: Optional[str] = Field(None, description="IP-����� ���������")
    
    class Config:
        from_attributes = True

class AnalysisResponse(BaseModel):
    """������ ������ � ������������ �������"""
    timeframe_minutes: int = Field(..., description="������ ������� � �������")
    timeframe_human: str = Field(..., description="������ ������� � �������� �������")
    total_alerts: int = Field(..., description="����� ���������� �������")
    severity_stats: Dict[str, int] = Field(..., description="���������� �� ������� �����������")
    alert_type_stats: Dict[str, int] = Field(..., description="���������� �� ����� �������")
    source_ip_stats: Dict[str, int] = Field(..., description="���������� �� IP-�������")
    average_risk_score: float = Field(..., description="������� ������ �����")
    top_alert_types: List[tuple] = Field(..., description="��� ����� �������")
    critical_alerts_count: int = Field(..., description="���������� ����������� �������")
    warning_alerts_count: int = Field(..., description="���������� ��������������")
    start_time: datetime = Field(..., description="������ ������� �������")
    end_time: datetime = Field(..., description="����� ������� �������")

class HealthResponse(BaseModel):
    """������ ������ ��� �������� ��������"""
    status: str = Field(..., description="������ �������")
    service: str = Field(..., description="�������� �������")
    timestamp: datetime = Field(..., description="����� ��������")
    database_status: str = Field(..., description="������ ���� ������")
    cache_status: str = Field(..., description="������ ����")

class ErrorResponse(BaseModel):
    """������ ������ �� ������"""
    error: str = Field(..., description="��� ������")
    detail: Optional[str] = Field(None, description="������ ������")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="����� ������")

class BatchProcessingResponse(BaseModel):
    """������ ������ ��� �������� ���������"""
    total_alerts: int = Field(..., description="����� ���������� ������������ �������")
    successful: int = Field(..., description="���������� ������� ������������ �������")
    failed: int = Field(..., description="���������� ������� � ��������")
    processing_time: float = Field(..., description="����� ��������� � ��������")