from fastapi import FastAPI, Request
from datetime import datetime
from loguru import logger

from settings import get_settings
from sync_database import init_db, save_alert_sync

settings = get_settings()
app = FastAPI(title="Ntopng Alert Analyzer", version="1.0")

@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("Application started successfully!")

@app.post("/webhook/ntopng")
def ntopng_webhook(request: Request):
    try:
        alert_data = {
            'message': 'Test alert',
            'severity': 'info',
            'alert_type': 'unknown',
            'risk_score': 0,
            'category': 'network'
        }
        
        alert_id = save_alert_sync(alert_data)
        
        return {
            "status": "success", 
            "alert_id": alert_id
        }
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"status": "error", "error": str(e)}

@app.get("/health")
def health_check():
    return {
        "status": "healthy", 
        "service": "ntopng-analyzer",
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)