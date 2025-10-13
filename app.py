from fastapi import FastAPI, Request, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
import time
from loguru import logger
import asyncio

from settings import get_settings
from database import db_manager, Alert
from models import (
    WebhookRequest, AlertResponse, AnalysisResponse, HealthResponse, 
    ErrorResponse, BatchWebhookRequest, BatchProcessingResponse,
    TimeframeRequest
)
from services.alert_service import alert_analysis_service, alert_query_service
from services.analysis_service import timeframe_analysis_service
from services.telegram_service import telegram_service
from services.cache_service import cache_service
from scheduler import report_scheduler
from celery_tasks import analyze_alerts_batch, generate_complex_report

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом приложения"""
    # Startup
    logger.info("Запуск Ntopng Alert Analyzer...")
    await db_manager.init_db()
    await cache_service.connect()
    report_scheduler.start()
    logger.info("Приложение успешно запущено")
    
    yield
    
    # Shutdown
    logger.info("Остановка Ntopng Alert Analyzer...")
    await report_scheduler.shutdown()
    await cache_service.disconnect()
    logger.info("Приложение остановлено")

app = FastAPI(
    title="Ntopng Alert Analyzer",
    description="Система анализа и мониторинга алертов ntopng",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Глобальные обработчики ошибок
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Глобальный обработчик исключений"""
    logger.error(f"Необработанное исключение: {exc}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal Server Error",
            detail=str(exc)
        ).dict()
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Обработчик HTTP исключений"""
    logger.warning(f"HTTP ошибка {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            detail=getattr(exc, 'detail', None)
        ).dict()
    )

# API Endpoints
@app.post(
    f"{settings.api_v1_prefix}/webhook/ntopng",
    response_model=dict,
    summary="Webhook для приема алертов от ntopng",
    description="""
    Принимает алерты от системы мониторинга ntopng.
    
    - **message**: Текст алерта (обязательный)
    - **severity**: Уровень серьезности (опциональный)
    - **timestamp**: Временная метка (опциональная)
    
    Возвращает результат анализа алерта.
    """
)
async def ntopng_webhook(
    request: WebhookRequest,
    background_tasks: BackgroundTasks
):
    """
    Обработка единичного алерта от ntopng.
    
    Args:
        request: Данные алерта
        background_tasks: Фоновые задачи FastAPI
        
    Returns:
        dict: Результат обработки алерта
    """
    try:
        logger.info(f"Получен алерт от ntopng: {request.message[:100]}...")
        
        # Асинхронный анализ алерта
        analysis = await alert_analysis_service.parse_alert_message(request.message)
        
        # Фоновая задача для сохранения
        background_tasks.add_task(
            db_manager.save_alert,
            analysis
        )
        
        logger.info(f"Алерт обработан: {analysis['alert_type']}")
        
        return {
            "status": "success",
            "alert_type": analysis['alert_type'],
            "severity": analysis['severity'],
            "risk_score": analysis['risk_score']
        }
        
    except Exception as e:
        logger.error(f"Ошибка обработки webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post(
    f"{settings.api_v1_prefix}/webhook/ntopng/batch",
    response_model=BatchProcessingResponse,
    summary="Пакетная обработка алертов",
    description="""
    Принимает несколько алертов для фоновой обработки через Celery.
    
    - **alerts**: Список алертов (максимум 1000)
    
    Каждый алерт должен содержать обязательное поле message.
    """
)
async def ntopng_webhook_batch(request: BatchWebhookRequest):
    """
    Пакетная обработка алертов через Celery.
    
    Args:
        request: Список алертов для обработки
        
    Returns:
        BatchProcessingResponse: Результат пакетной обработки
    """
    start_time = time.time()
    
    try:
        logger.info(f"Получен пакет из {len(request.alerts)} алертов")
        
        # Подготавливаем данные для Celery задачи
        alert_data_list = [
            {"message": alert.message, "severity": alert.severity}
            for alert in request.alerts
        ]
        
        # Запускаем фоновую задачу Celery
        task_result = analyze_alerts_batch.delay(alert_data_list)
        
        processing_time = time.time() - start_time
        
        return BatchProcessingResponse(
            total_alerts=len(request.alerts),
            successful=len(request.alerts),  # Предполагаем успех, т.к. задача в фоне
            failed=0,
            processing_time=round(processing_time, 3)
        )
        
    except Exception as e:
        logger.error(f"Ошибка пакетной обработки: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(
    f"{settings.api_v1_prefix}/analysis/{{timeframe_minutes}}",
    response_model=AnalysisResponse,
    summary="Анализ алертов за период",
    description="""
    Возвращает анализ алертов за указанный период в минутах.
    
    - **timeframe_minutes**: Период анализа от 1 до 43200 минут (30 дней)
    
    Использует кэширование для повышения производительности.
    """
)
async def get_analysis(timeframe_minutes: int):
    """
    Получение анализа алертов за указанный период.
    
    Args:
        timeframe_minutes: Период анализа в минутах (1-43200)
        
    Returns:
        AnalysisResponse: Результаты анализа
        
    Raises:
        HTTPException: Если период вне допустимого диапазона
    """
    if timeframe_minutes < 1 or timeframe_minutes > 43200:
        raise HTTPException(
            status_code=400, 
            detail="Timeframe must be between 1 and 43200 minutes"
        )
    
    try:
        # Проверяем кэш
        cached_report = await cache_service.get_cached_report(timeframe_minutes)
        if cached_report:
            logger.info(f"Использован кэшированный отчет за {timeframe_minutes} минут")
            return AnalysisResponse(**cached_report)
        
        # Если нет в кэше, выполняем анализ
        async with db_manager.get_session() as session:
            analysis = await timeframe_analysis_service.analyze_timeframe(
                session, timeframe_minutes
            )
            
            # Сохраняем в кэш
            await cache_service.set_cached_report(timeframe_minutes, analysis)
            
            return AnalysisResponse(**analysis)
            
    except Exception as e:
        logger.error(f"Ошибка анализа за {timeframe_minutes} минут: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(
    f"{settings.api_v1_prefix}/alerts/recent",
    response_model=dict,
    summary="Последние алерты",
    description="""
    Возвращает список последних алертов.
    
    - **limit**: Количество алертов (по умолчанию 50, максимум 1000)
    """
)
async def get_recent_alerts(limit: int = 50):
    """
    Получение последних алертов.
    
    Args:
        limit: Максимальное количество алертов (1-1000)
        
    Returns:
        dict: Список алертов и метаданные
    """
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=400, 
            detail="Limit must be between 1 and 1000"
        )
    
    try:
        async with db_manager.get_session() as session:
            alerts = await alert_query_service.get_recent_alerts(session, limit)
            
            return {
                "alerts": [
                    {
                        "id": alert.id,
                        "timestamp": alert.timestamp,
                        "message": alert.message,
                        "severity": alert.severity,
                        "type": alert.alert_type,
                        "risk_score": alert.risk_score
                    }
                    for alert in alerts
                ],
                "total": len(alerts),
                "limit": limit
            }
            
    except Exception as e:
        logger.error(f"Ошибка получения последних алертов: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Проверка здоровья сервиса",
    description="Возвращает статус всех компонентов системы."
)
async def health_check():
    """
    Проверка работоспособности сервиса и его компонентов.
    
    Returns:
        HealthResponse: Статус сервиса и компонентов
    """
    try:
        # Проверяем базу данных
        db_status = "healthy"
        try:
            async with db_manager.get_session() as session:
                from sqlalchemy import text
                await session.execute(text("SELECT 1"))
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"
        
        # Проверяем кэш
        cache_stats = await cache_service.get_cache_stats()
        cache_status = "healthy" if cache_stats.get('connected') else "unavailable"
        
        return HealthResponse(
            status="healthy",
            service="ntopng-analyzer",
            timestamp=datetime.utcnow(),
            database_status=db_status,
            cache_status=cache_status
        )
        
    except Exception as e:
        logger.error(f"Ошибка проверки здоровья: {e}")
        return HealthResponse(
            status="unhealthy",
            service="ntopng-analyzer",
            timestamp=datetime.utcnow(),
            database_status="unknown",
            cache_status="unknown"
        )

@app.post(
    f"{settings.api_v1_prefix}/alerts/{{alert_id}}/resolve",
    response_model=dict,
    summary="Пометить алерт как разрешенный",
    description="Помечает указанный алерт как разрешенный."
)
async def resolve_alert(alert_id: int):
    """
    Пометка алерта как разрешенного.
    
    Args:
        alert_id: ID алерта для пометки
        
    Returns:
        dict: Результат операции
    """
    try:
        success = await db_manager.mark_alert_resolved(alert_id)
        
        if success:
            # Инвалидируем кэш, т.к. данные изменились
            for timeframe in settings.analysis_intervals:
                await cache_service.invalidate_report_cache(timeframe)
            
            return {"status": "success", "message": f"Alert {alert_id} marked as resolved"}
        else:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка пометки алерта как разрешенного: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.debug,
        log_level="info"
    )