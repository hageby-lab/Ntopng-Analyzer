@echo off
echo Устранение проблем с установкой...

:: Активируем виртуальное окружение
call venv\Scripts\activate.bat

:: Проверяем установленные пакеты
echo Проверка установленных пакетов...
pip list

:: Устанавливаем основные зависимости
echo Установка основных зависимостей...
pip install fastapi uvicorn python-telegram-bot python-dotenv sqlalchemy aiosqlite

:: Устанавливаем дополнительные зависимости
echo Установка дополнительных зависимостей...
pip install loguru pydantic pydantic-settings apscheduler pandas jinja2 requests

:: Проверяем установку
echo Проверка установки...
python -c "import fastapi; print('FastAPI установлен')"
python -c "import sqlalchemy; print('SQLAlchemy установлен')"
python -c "import telegram; print('Python-telegram-bot установлен')"

echo Готово! Теперь можно запустить: python app.py
pause