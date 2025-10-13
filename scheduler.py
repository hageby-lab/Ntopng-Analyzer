from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from database import SessionLocal
from analyzer import NtopngAnalyzer
from telegram_bot import TelegramNotifier
from config import config
import logging

logger = logging.getLogger(__name__)

class ReportScheduler:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.analyzer = NtopngAnalyzer()
        self.notifier = TelegramNotifier()
        self.setup_schedules()
    
    def setup_schedules(self):
        """Настройка расписания отправки отчетов"""
        
        # Каждые 5 минут
        self.scheduler.add_job(
            self.send_5min_report,
            trigger=IntervalTrigger(minutes=5),
            id='5min_report'
        )
        
        # Каждые 15 минут
        self.scheduler.add_job(
            self.send_15min_report,
            trigger=IntervalTrigger(minutes=15),
            id='15min_report'
        )
        
        # Каждые 30 минут
        self.scheduler.add_job(
            self.send_30min_report,
            trigger=IntervalTrigger(minutes=30),
            id='30min_report'
        )
        
        # Каждый час
        self.scheduler.add_job(
            self.send_1h_report,
            trigger=IntervalTrigger(hours=1),
            id='1h_report'
        )
        
        # Ежедневно в 9:00
        self.scheduler.add_job(
            self.send_daily_report,
            trigger=CronTrigger(hour=9, minute=0),
            id='daily_report'
        )
        
        # Еженедельно в понедельник в 9:00
        self.scheduler.add_job(
            self.send_weekly_report,
            trigger=CronTrigger(day_of_week='mon', hour=9, minute=0),
            id='weekly_report'
        )
        
        # Ежемесячно 1 числа в 9:00
        self.scheduler.add_job(
            self.send_monthly_report,
            trigger=CronTrigger(day=1, hour=9, minute=0),
            id='monthly_report'
        )
    
    async def send_5min_report(self):
        await self._send_timeframe_report(5)
    
    async def send_15min_report(self):
        await self._send_timeframe_report(15)
    
    async def send_30min_report(self):
        await self._send_timeframe_report(30)
    
    async def send_1h_report(self):
        await self._send_timeframe_report(60)
    
    async def send_daily_report(self):
        await self._send_timeframe_report(1440)  # 24 часа
    
    async def send_weekly_report(self):
        await self._send_timeframe_report(10080)  # 7 дней
    
    async def send_monthly_report(self):
        await self._send_timeframe_report(43200)  # 30 дней
    
    async def _send_timeframe_report(self, minutes: int):
        """Отправка отчета за указанный промежуток времени"""
        try:
            db = SessionLocal()
            analysis = self.analyzer.analyze_timeframe(db, minutes)
            telegram_message = self.analyzer.generate_report_message(analysis)
            
            analysis['telegram_message'] = telegram_message
            await self.notifier.send_report(analysis)
            
            logger.info(f"Отчет за {minutes} минут отправлен")
            db.close()
            
        except Exception as e:
            logger.error(f"Ошибка отправки отчета за {minutes} минут: {e}")
    
    def start(self):
        """Запуск планировщика"""
        self.scheduler.start()
        logger.info("Планировщик отчетов запущен")
    
    def shutdown(self):
        """Остановка планировщика"""
        self.scheduler.shutdown()
        logger.info("Планировщик отчетов остановлен")