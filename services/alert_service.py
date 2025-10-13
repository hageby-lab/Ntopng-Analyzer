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
    ������ ��� ������� � ������������� ������� ntopng.
    
    ������������ ������� ���������, ����������� ���� ������,
    ������ ����������� � ������ ������ �����.
    """
    
    def __init__(self):
        """������������� ������� ������� �������."""
        self.alert_patterns = ALERT_PATTERNS
        self.severity_keywords = SEVERITY_KEYWORDS

    async def parse_alert_message(self, message: str) -> Dict:
        """
        ������� � ������ ��������� �� ntopng.
        
        Args:
            message: ����� ������ �� ntopng
            
        Returns:
            Dict: ������� � ������������ �������:
                - message: ������������ ���������
                - severity: ������� �����������
                - alert_type: ��� ������
                - source_ip: IP ��������
                - destination_ip: IP ����������
                - protocol: ������� ��������
                - risk_score: ������ �����
                - category: ��������� ������
                - interface: ������� ���������
                
        Raises:
            Exception: ���� ��������� ������ ��� �������
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
            
            # ����� IP-�������
            ips = re.findall(REGEX_PATTERNS['ip_address'], message)
            if len(ips) >= 1:
                analysis['source_ip'] = ips[0]
            if len(ips) >= 2:
                analysis['destination_ip'] = ips[1]
            
            # ����������� ���� ������
            analysis.update(await self._detect_alert_type(message, analysis))
            
            # ����������� ������ �����������
            analysis.update(await self._detect_severity(message, analysis))
            
            # ����� ���������� � ����������
            analysis.update(await self._extract_additional_info(message))
            
            logger.info(
                f"����� ���������������: {analysis['alert_type']} - "
                f"{analysis['severity']} (����: {analysis['risk_score']}%)"
            )
            return analysis
            
        except Exception as e:
            logger.error(f"������ ������� ������: {e}")
            raise

    async def _detect_alert_type(self, message: str, analysis: Dict) -> Dict:
        """
        ����������� ���� ������ �� ������ ���������.
        
        Args:
            message: ����� ������
            analysis: ������� ������
            
        Returns:
            Dict: ����������� ������ � ����� ������ � ������� �����
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
        ����������� ������ ����������� ������.
        
        Args:
            message: ����� ������
            analysis: ������� ������
            
        Returns:
            Dict: ����������� ������ � ������� ����������� � ������� �����
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
        ���������� �������������� ���������� �� ������.
        
        Args:
            message: ����� ������
            
        Returns:
            Dict: �������������� ���������� (��������, ���������, ���������)
        """
        result = {}
        
        # ����� ����������
        for protocol in PROTOCOLS:
            if protocol.upper() in message.upper():
                result['protocol'] = protocol
                break
        
        # ����������� ���������
        message_lower = message.lower()
        if any(word in message_lower for word in ['attack', 'security', 'threat', 'malicious']):
            result['category'] = Categories.SECURITY
        elif any(word in message_lower for word in ['bandwidth', 'throughput', 'traffic', 'flow']):
            result['category'] = Categories.PERFORMANCE
        elif any(word in message_lower for word in ['interface', 'host', 'device']):
            result['category'] = Categories.INFRASTRUCTURE
        
        # ����� ����������
        interface_match = re.search(REGEX_PATTERNS['interface'], message_lower)
        if interface_match:
            result['interface'] = interface_match.group(1)
        
        return result

class AlertQueryService:
    """
    ������ ��� ���������� �������� � ������� � ���� ������.
    
    ������������ ��������� ������� �� ��������� ���������.
    """
    
    async def get_alerts_by_timeframe(
        self, 
        session: AsyncSession, 
        minutes: int
    ) -> List[Alert]:
        """
        ��������� ������� �� ��������� ���������� �������.
        
        Args:
            session: ����������� ������ ��
            minutes: ������ � �������
            
        Returns:
            List[Alert]: ������ ������� �� ��������� ������
            
        Raises:
            Exception: ���� ��������� ������ ��� �������
        """
        try:
            since = datetime.utcnow() - timedelta(minutes=minutes)
            from sqlalchemy import select
            query = select(Alert).filter(Alert.timestamp >= since)
            result = await session.execute(query)
            alerts = result.scalars().all()
            
            logger.info(f"�������� {len(alerts)} ������� �� {minutes} �����")
            return alerts
            
        except Exception as e:
            logger.error(f"������ ��������� �������: {e}")
            raise

    async def get_recent_alerts(
        self, 
        session: AsyncSession, 
        limit: int = 50
    ) -> List[Alert]:
        """
        ��������� ��������� �������.
        
        Args:
            session: ����������� ������ ��
            limit: ������������ ���������� �������
            
        Returns:
            List[Alert]: ������ ��������� �������
            
        Raises:
            Exception: ���� ��������� ������ ��� �������
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
            
            logger.info(f"�������� {len(alerts)} ��������� �������")
            return alerts
            
        except Exception as e:
            logger.error(f"������ ��������� ��������� �������: {e}")
            raise

# ���������� ���������� ��������
alert_analysis_service = AlertAnalysisService()
alert_query_service = AlertQueryService()