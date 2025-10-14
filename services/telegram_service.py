import os
import asyncio
from telegram import Bot
from telegram.error import TelegramError, NetworkError, TimedOut
from loguru import logger
from settings import get_settings
from typing import Dict, Any

settings = get_settings()

class TelegramNotificationService:
    """
    Сервис для отправки уведомлений в Telegram.
    """
    
    def __init__(self):
        """
        Инициализация Telegram сервиса.
        """
        logger.info("Инициализация Telegram сервиса...")
        
        self.bot_token = settings.telegram_bot_token
        self.channel_id = settings.telegram_channel_id
        
        # Проверяем настройки
        if not self.bot_token:
            raise ValueError("TELEGRAM_BOT_TOKEN не настроен")
            
        if not self.channel_id:
            raise ValueError("TELEGRAM_CHANNEL_ID не настроен")
            
        if self.bot_token == "test":
            raise ValueError("TELEGRAM_BOT_TOKEN имеет тестовое значение")
        
        # Проверяем формат токена
        if ":" not in self.bot_token:
            raise ValueError(f"Неверный формат TELEGRAM_BOT_TOKEN: {self.bot_token}")
            
        logger.info(f"Bot token: {self.bot_token[:10]}...")
        logger.info(f"Channel ID: {self.channel_id}")
            
        try:
            self.bot = Bot(token=self.bot_token)
            self.max_retries = 3
            self.retry_delay = 2
            
            logger.info("Telegram сервис успешно инициализирован")
        except Exception as e:
            raise ValueError(f"Ошибка создания бота: {e}")

    async def send_message(self, message: str, retry_count: int = 0) -> Dict[str, Any]:
        """
        Асинхронная отправка сообщения в Telegram канал.
        """
        if not message or not message.strip():
            return {
                'success': False,
                'message': 'Empty message',
                'retries': retry_count,
                'error': 'Message cannot be empty'
            }
        
        try:
            logger.info(f"Отправка сообщения в Telegram: {message[:50]}...")
            
            await self.bot.send_message(
                chat_id=self.channel_id,
                text=message,
                parse_mode='HTML'
            )
            
            logger.info("✅ Сообщение успешно отправлено в Telegram")
            return {
                'success': True,
                'message': 'Message sent successfully',
                'retries': retry_count + 1
            }
            
        except (NetworkError, TimedOut) as e:
            if retry_count < self.max_retries:
                logger.warning(
                    f"Сетевая ошибка при отправке в Telegram. "
                    f"Попытка {retry_count + 1}/{self.max_retries}. "
                    f"Ошибка: {e}"
                )
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
            error_message = f"Ошибка Telegram API: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Telegram API error',
                'retries': retry_count + 1,
                'error': error_message
            }
            
        except Exception as e:
            error_message = f"Неожиданная ошибка при отправке в Telegram: {e}"
            logger.error(error_message)
            return {
                'success': False,
                'message': 'Unexpected error',
                'retries': retry_count + 1,
                'error': error_message
            }

    async def test_connection(self) -> Dict[str, Any]:
        """
        Тестирование подключения к Telegram.
        """
        try:
            # Получаем информацию о боте
            bot_info = await self.bot.get_me()
            logger.info(f"Bot info: {bot_info.username} ({bot_info.first_name})")
            
            # Только проверяем подключение, не отправляем тестовое сообщение
            return {
                'success': True,
                'bot_username': bot_info.username,
                'bot_name': bot_info.first_name,
                'message': 'Connection test completed successfully'
            }
            
        except Exception as e:
            logger.error(f"Ошибка тестирования Telegram: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Connection test failed'
            }

def get_telegram_service():
    """
    Фабрика для создания экземпляра Telegram сервиса.
    """
    try:
        logger.info("Создание Telegram сервиса...")
        
        # Проверяем настройки перед созданием
        if not settings.telegram_bot_token:
            logger.error("TELEGRAM_BOT_TOKEN не настроен")
            return None
            
        if not settings.telegram_channel_id:
            logger.error("TELEGRAM_CHANNEL_ID не настроен")
            return None
            
        service = TelegramNotificationService()
        logger.info("✅ Telegram service created successfully")
        return service
        
    except ValueError as e:
        logger.error(f"❌ Telegram service configuration error: {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Failed to create Telegram service: {e}")
        return None

# Глобальный экземпляр сервиса
telegram_service = get_telegram_service()