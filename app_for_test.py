from fastapi import FastAPI, Request, HTTPException
from datetime import datetime
from loguru import logger
import asyncio

from settings import get_settings
from database import db_manager, Alert

settings = get_settings()

app = FastAPI(title="Ntopng Alert Analyzer", version="1.0")

@app.on_event("startup")
async def startup_event():
    try:
        await db_manager.init_db()
        logger.info("Application started successfully!")
    except Exception as e:
        logger.error(f"Startup error: {e}")

@app.post("/webhook/ntopng")
async def ntopng_webhook(request: Request):
    try:
        # Get JSON data from request
        alert_data = await request.json()
        message = alert_data.get('message', str(alert_data))
        
        # Simple alert processing
        alert = {
            'message': message,
            'severity': 'info',
            'alert_type': 'unknown',
            'risk_score': 0,
            'category': 'network'
        }
        
        # Save to database
        alert_id = await db_manager.save_alert(alert)
        
        return {
            "status": "success", 
            "alert_id": alert_id,
            "message": "Alert processed successfully"
        }
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {
            "status": "error", 
            "error": str(e)
        }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "service": "ntopng-analyzer",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    return {
        "message": "Ntopng Alert Analyzer is running!",
        "version": "1.0",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.debug
    )