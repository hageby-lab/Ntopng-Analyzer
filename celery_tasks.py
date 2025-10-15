from celery import Celery
from loguru import logger
from settings import get_settings

settings = get_settings()

# Инициализация Celery
celery_app = Celery(
    'ntopng_analyzer',
    broker=settings.redis_url,
    backend=settings.redis_url
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Europe/Moscow',
    enable_utc=True,
)

@celery_app.task(name='analyze_alerts_batch')
def analyze_alerts_batch(alert_data_list: list):
    """Фоновая задача для анализа пакета алертов"""
    try:
        from services.alert_service import alert_analysis_service
        from database import db_manager
        import asyncio
        
        async def process_alerts():
            results = []
            for alert_data in alert_data_list:
                try:
                    analysis = await alert_analysis_service.parse_alert_message(alert_data['message'])
                    alert_id = await db_manager.save_alert(analysis)
                    results.append({'alert_id': alert_id, 'status': 'success'})
                except Exception as e:
                    logger.error(f"Ошибка обработки алерта: {e}")
                    results.append({'alert_id': None, 'status': 'error', 'error': str(e)})
            return results
        
        # Запуск асинхронной обработки
        return asyncio.run(process_alerts())
        
    except Exception as e:
        logger.error(f"Ошибка в фоновой задаче: {e}")
        return {'status': 'error', 'error': str(e)}

@celery_app.task(name='generate_complex_report')
def generate_complex_report(timeframe_minutes: int):
    """Фоновая задача для генерации сложных отчетов"""
    try:
        from services.analysis_service import timeframe_analysis_service, report_generation_service
        from services.telegram_service import telegram_service
        from database import db_manager
        import asyncio
        
        async def generate_report():
            async with db_manager.get_session() as session:
                analysis = await timeframe_analysis_service.analyze_timeframe(session, timeframe_minutes)
                telegram_message = await report_generation_service.generate_telegram_report(analysis)
                
                # Отправка в Telegram
                success = await telegram_service.send_message(telegram_message)
                return {
                    'timeframe': timeframe_minutes,
                    'alerts_analyzed': analysis['total_alerts'],
                    'telegram_sent': success,
                    'report_generated': True
                }
        
        return asyncio.run(generate_report())
        
    except Exception as e:
        logger.error(f"Ошибка генерации сложного отчета: {e}")
        return {'status': 'error', 'error': str(e)}