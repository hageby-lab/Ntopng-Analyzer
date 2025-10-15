#!/usr/bin/env python3
import os
import sys

def create_file(filename, content):
    """Создает файл с указанным содержимым"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Создан файл: {filename}")

def main():
    # Создаем директорию если её нет
    if not os.path.exists('ntopng_analyzer'):
        os.makedirs('ntopng_analyzer')
    os.chdir('ntopng_analyzer')
    
    # requirements.txt
    create_file('requirements.txt', """fastapi==0.104.1
uvicorn==0.24.0
python-telegram-bot==20.7
python-dotenv==1.0.0
sqlalchemy==2.0.23
apscheduler==3.10.4
pandas==2.1.3
jinja2==3.1.2
requests==2.31.0
alembic==1.12.1""")
    
    # config.py
    create_file('config.py', """import os
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
    ANALYSIS_INTERVALS = [5, 15, 30, 60, 1440, 10080, 43200]
    
    # Ntopng webhook secret
    WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')
    
    # Report settings
    TOP_ALERTS_COUNT = 10

config = Config()""")
    
    # Создаем остальные файлы...
    # [Вставьте содержимое остальных файлов из вышеперечисленных]
    
    print("\\nПроект успешно создан!")
    print("Не забудьте:")
    print("1. Установить зависимости: pip install -r requirements.txt")
    print("2. Создать .env файл из .env.example")
    print("3. Запустить приложение: python app.py")

if __name__ == "__main__":
    main()