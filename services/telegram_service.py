from telegram import Bot
from telegram.error import TelegramError, NetworkError, TimedOut
from loguru import logger
from settings import get_settings
from typing import Dict, Any

settings = get_settings()

class TelegramNotificationService:
    """
    ������ ��� �������� ����������� � Telegram.
    
    ������������ ����������� �������� ��������� � Telegram �����
    � ���������� ������ � ���������� ���������.
    """
    
    def __init__(self):
        """
        ������������� Telegram �������.
        
        Raises:
            ValueError: ���� ����� ���� �� ������
        """
        if not settings.telegram_bot_token:
            raise ValueError("Telegram bot token is required")
            
        self.bot = Bot(token=settings.telegram_bot_token)
        self.channel_id = settings.telegram_channel_id
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        
        logger.info("Telegram ������ ������� ���������������")

    async def send_message(self, message: str, retry_count: int = 0) -> Dict[str, Any]:
        """
        ����������� �������� ��������� � Telegram �����.
        
        Args:
            message: ����� ��������� ��� ��������
            retry_count: ������� ���������� ������� ��������
            
        Returns:
            Dict: ��������� ��������:
                - success: bool - ���������� ��������
                - message: str - �������� ����������
                - retries: int - ���������� �������
                - error: str - �������� ������ (���� ����)
        """
        if not message or not message.strip():
            return {
                'success': False,
                'message': 'Empty message',
                'retries': retry_count,
                'error': 'Message cannot be empty'
            }
        
        try:
            await self.bot.send_message(
                chat_id=self.channel_id,
                text=message,
                parse_mode='HTML'
            )
            
            logger.info("��������� ������� ���������� � Telegram")
            return {
                'success': True,
                'message': 'Message sent successfully',
                'retries': retry_count + 1
            }
            
        except (NetworkError, TimedOut) as e:
            # ������� ������ - ������� ���������
            if retry_count < self.max_retries:
                logger.warning(
                    f"������� ������ ��� �������� � Telegram. "
                    f"������� {retry_count + 1}/{self.max_retries}. "
                    f"������: {e}"
                )
                import asyncio
                await asyncio.sleep(self.retry_delay * (retry_count + 1))
                return await self.send_message(message, retry_count + 1)
            else:
                logger.error(
                    f"�� ������� ��������� ��������� � Telegram ����� "
                    f"{self.max_retries} �������. ������: {e}"
                )
                return {
                    'success': False,
                    'message': f'Network error after {self.max_retries} retries',
                    'retries': retry_count + 1,
                    'error': str(e)
                }
                
        except TelegramError as e:
            # ������ Telegram API
            error_message = f"������ Telegram API: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Telegram API error',
                'retries': retry_count + 1,
                'error': error_message
            }
            
        except Exception as e:
            # ����������� ������
            error_message = f"����������� ������ ��� �������� � Telegram: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Unexpected error',
                'retries': retry_count + 1,
                'error': error_message
            }

    async def send_report(self, analysis_report: dict) -> Dict[str, Any]:
        """
        �������� ������ ������� � Telegram.
        
        Args:
            analysis_report: ������� � ������� ������
            
        Returns:
            Dict: ��������� �������� ������
        """
        try:
            message = analysis_report.get('telegram_message', '')
            if not message:
                logger.warning("������ ��������� ��� �������� � Telegram")
                return {
                    'success': False,
                    'message': 'Empty report message',
                    'error': 'No telegram_message in analysis_report'
                }
                
            result = await self.send_message(message)
            
            if result['success']:
                logger.info(
                    f"����� ������� ��������� � Telegram. "
                    f"�������: {result['retries']}"
                )
            else:
                logger.error(
                    f"������ �������� ������ � Telegram: {result.get('error', 'Unknown error')}"
                )
                
            return result
            
        except Exception as e:
            error_message = f"������ �������� ������: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Report sending failed',
                'error': error_message
            }

# ���������� ��������� �������
telegram_service = TelegramNotificationService()