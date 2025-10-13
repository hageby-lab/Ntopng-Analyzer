from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import logging
import json

from database import get_db, init_db, Alert
from analyzer import NtopngAnalyzer
from scheduler import ReportScheduler
from config import config

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = FastAPI(title="Ntopng Alert Analyzer")
analyzer = NtopngAnalyzer()
scheduler = ReportScheduler()

@app.on_event("startup")
async def startup_event():
    init_db()
    scheduler.start()
    logging.info("Приложение запущено")

@app.on_event("shutdown")
async def shutdown_event():
    scheduler.shutdown()
    logging.info("Приложение остановлено")

@app.post("/webhook/ntopng")
async def ntopng_webhook(request: Request, db: Session = Depends(get_db)):
    """Webhook endpoint для приема алертов от ntopng"""
    try:
        # Получение данных от ntopng
        body = await request.body()
        alert_data = await request.json()
        
        logging.info(f"Получен алерт от ntopng: {alert_data}")
        
        # Парсинг сообщения
        if isinstance(alert_data, dict):
            message = alert_data.get('message', str(alert_data))
        else:
            message = str(alert_data)
        
        analysis = analyzer.parse_alert_message(message)
        
        # Сохранение в базу данных
        alert = Alert(
            message=analysis['message'],
            severity=analysis['severity'],
            alert_type=analysis['alert_type'],
            source_ip=analysis['source_ip'],
            destination_ip=analysis['destination_ip'],
            protocol=analysis['protocol'],
            risk_score=analysis['risk_score'],
            category=analysis['category'],
            interface=analysis.get('interface', 'unknown')
        )
        
        db.add(alert)
        db.commit()
        
        logging.info(f"Алерт сохранен в базу: {alert.id}")
        
        return JSONResponse(
            status_code=200,
            content={"status": "success", "alert_id": alert.id}
        )
        
    except Exception as e:
        logging.error(f"Ошибка обработки webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "ntopng-analyzer"}

@app.get("/analysis/{timeframe_minutes}")
async def get_analysis(timeframe_minutes: int, db: Session = Depends(get_db)):
    """Получение анализа за указанный период"""
    try:
        analysis = analyzer.analyze_timeframe(db, timeframe_minutes)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/alerts/recent")
async def get_recent_alerts(limit: int = 50, db: Session = Depends(get_db)):
    """Получение последних алертов"""
    from sqlalchemy import desc
    alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(limit).all()
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
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        reload=True
    )