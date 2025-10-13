#!/bin/bash
echo "Установка Ntopng Analyzer..."

# Создание виртуального окружения
python3 -m venv venv
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt

# Копирование файла конфигурации
cp .env.example .env

echo "Установка завершена!"
echo "Отредактируйте файл .env и запустите: python app.py"