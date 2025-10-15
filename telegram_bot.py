import logging
from telegram import Bot
from telegram.error import TelegramError
from config import config

logger = logging.getLogger(__name__)

class TelegramNotifier:
    def __init__(self):
        self.bot = Bot(token=config.TELEGRAM_BOT_TOKEN)
        self.channel_id = config.TELEGRAM_CHANNEL_ID
    
    async def send_message(self, message: str):
        """Отправка сообщения в Telegram канал"""
        try:
            await self.bot.send_message(
                chat_id=self.channel_id,
                text=message,
                parse_mode='HTML'
            )
            logger.info("Сообщение отправлено в Telegram")
            return True
        except TelegramError as e:
            logger.error(f"Ошибка отправки в Telegram: {e}")
            return False
    
    async def send_report(self, analysis_report: dict):
        """Отправка отчета анализа"""
        message = analysis_report.get('telegram_message', '')
        if message:
            await self.send_message(message)