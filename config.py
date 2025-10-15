import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Telegram
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
    TELEGRAM_CHANNEL_ID = os.getenv('TELEGRAM_CHANNEL_ID')
    
    # Database
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./ntopng_alerts.db')
    
    # Server
    SERVER_HOST = os.getenv('SERVER_HOST', '0.0.0.0')
    SERVER_PORT = int(os.getenv('SERVER_PORT', 8000))
    
    # Analysis intervals in minutes
    ANALYSIS_INTERVALS = [5, 15, 30, 60, 1440, 10080, 43200]  # 5min, 15min, 30min, 1h, 1d, 7d, 30d
    
    # Ntopng webhook secret
    WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')
    
    # Report settings
    TOP_ALERTS_COUNT = 10

config = Config()