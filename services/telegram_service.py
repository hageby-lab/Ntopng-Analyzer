from telegram import Bot
from telegram.error import TelegramError, NetworkError, TimedOut
from loguru import logger
from settings import get_settings
from typing import Dict, Any

settings = get_settings()

class TelegramNotificationService:
    """
    Сервис для отправки уведомлений в Telegram.
    
    Обеспечивает асинхронную отправку сообщений в Telegram канал
    с обработкой ошибок и повторными попытками.
    """
    
    def __init__(self):
        """
        Инициализация Telegram сервиса.
        
        Raises:
            ValueError: Если токен бота не указан
        """
        if not settings.telegram_bot_token:
            raise ValueError("Telegram bot token is required")
            
        self.bot = Bot(token=settings.telegram_bot_token)
        self.channel_id = settings.telegram_channel_id
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        
        logger.info("Telegram сервис успешно инициализирован")

    async def send_message(self, message: str, retry_count: int = 0) -> Dict[str, Any]:
        """
        Асинхронная отправка сообщения в Telegram канал.
        
        Args:
            message: Текст сообщения для отправки
            retry_count: Текущее количество попыток отправки
            
        Returns:
            Dict: Результат отправки:
                - success: bool - успешность отправки
                - message: str - описание результата
                - retries: int - количество попыток
                - error: str - описание ошибки (если есть)
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
            
            logger.info("Сообщение успешно отправлено в Telegram")
            return {
                'success': True,
                'message': 'Message sent successfully',
                'retries': retry_count + 1
            }
            
        except (NetworkError, TimedOut) as e:
            # Сетевые ошибки - пробуем повторить
            if retry_count < self.max_retries:
                logger.warning(
                    f"Сетевая ошибка при отправке в Telegram. "
                    f"Попытка {retry_count + 1}/{self.max_retries}. "
                    f"Ошибка: {e}"
                )
                import asyncio
                await asyncio.sleep(self.retry_delay * (retry_count + 1))
                return await self.send_message(message, retry_count + 1)
            else:
                logger.error(
                    f"Не удалось отправить сообщение в Telegram после "
                    f"{self.max_retries} попыток. Ошибка: {e}"
                )
                return {
                    'success': False,
                    'message': f'Network error after {self.max_retries} retries',
                    'retries': retry_count + 1,
                    'error': str(e)
                }
                
        except TelegramError as e:
            # Ошибки Telegram API
            error_message = f"Ошибка Telegram API: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Telegram API error',
                'retries': retry_count + 1,
                'error': error_message
            }
            
        except Exception as e:
            # Неожиданные ошибки
            error_message = f"Неожиданная ошибка при отправке в Telegram: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Unexpected error',
                'retries': retry_count + 1,
                'error': error_message
            }

    async def send_report(self, analysis_report: dict) -> Dict[str, Any]:
        """
        Отправка отчета анализа в Telegram.
        
        Args:
            analysis_report: Словарь с данными отчета
            
        Returns:
            Dict: Результат отправки отчета
        """
        try:
            message = analysis_report.get('telegram_message', '')
            if not message:
                logger.warning("Пустое сообщение для отправки в Telegram")
                return {
                    'success': False,
                    'message': 'Empty report message',
                    'error': 'No telegram_message in analysis_report'
                }
                
            result = await self.send_message(message)
            
            if result['success']:
                logger.info(
                    f"Отчет успешно отправлен в Telegram. "
                    f"Попыток: {result['retries']}"
                )
            else:
                logger.error(
                    f"Ошибка отправки отчета в Telegram: {result.get('error', 'Unknown error')}"
                )
                
            return result
            
        except Exception as e:
            error_message = f"Ошибка отправки отчета: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Report sending failed',
                'error': error_message
            }

# Глобальный экземпляр сервиса
telegram_service = TelegramNotificationService()