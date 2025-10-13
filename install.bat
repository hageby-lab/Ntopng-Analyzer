@echo off
echo Установка Ntopng Analyzer...

:: Создание виртуального окружения
python -m venv venv
call venv\Scripts\activate.bat

:: Установка зависимостей
pip install -r requirements.txt

:: Копирование файла конфигурации
copy .env.example .env

echo Установка завершена!
echo Отредактируйте файл .env и запустите: python app.py
pause