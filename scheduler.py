from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from loguru import logger

from database import db_manager
from services.analysis_service import timeframe_analysis_service, report_generation_service
from services.telegram_service import telegram_service
from settings import get_settings

settings = get_settings()

class ReportScheduler:
    """Асинхронный планировщик отчетов"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.setup_schedules()
        logger.info("Планировщик инициализирован")

    def setup_schedules(self):
        """Настройка расписания отправки отчетов"""
        
        # Каждые 5 минут
        self.scheduler.add_job(
            self.send_5min_report,
            trigger=IntervalTrigger(minutes=5),
            id='5min_report',
            max_instances=1
        )
        
        # Каждые 15 минут
        self.scheduler.add_job(
            self.send_15min_report,
            trigger=IntervalTrigger(minutes=15),
            id='15min_report',
            max_instances=1
        )
        
        # Каждые 30 минут
        self.scheduler.add_job(
            self.send_30min_report,
            trigger=IntervalTrigger(minutes=30),
            id='30min_report',
            max_instances=1
        )
        
        # Каждый час
        self.scheduler.add_job(
            self.send_1h_report,
            trigger=IntervalTrigger(hours=1),
            id='1h_report',
            max_instances=1
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
        """Асинхронная отправка отчета за указанный промежуток времени"""
        try:
            async with db_manager.get_session() as session:
                analysis = await timeframe_analysis_service.analyze_timeframe(session, minutes)
                telegram_message = await report_generation_service.generate_telegram_report(analysis)
                
                analysis['telegram_message'] = telegram_message
                success = await telegram_service.send_report(analysis)
                
                if success:
                    logger.info(f"Отчет за {minutes} минут успешно отправлен")
                else:
                    logger.error(f"Ошибка отправки отчета за {minutes} минут")
                    
        except Exception as e:
            logger.error(f"Ошибка отправки отчета за {minutes} минут: {e}")

    def start(self):
        """Запуск планировщика"""
        try:
            self.scheduler.start()
            logger.info("Планировщик отчетов запущен")
        except Exception as e:
            logger.error(f"Ошибка запуска планировщика: {e}")
            raise

    async def shutdown(self):
        """Асинхронная остановка планировщика"""
        try:
            self.scheduler.shutdown()
            logger.info("Планировщик отчетов остановлен")
        except Exception as e:
            logger.error(f"Ошибка остановки планировщика: {e}")

# Глобальный экземпляр планировщика
report_scheduler = ReportScheduler()