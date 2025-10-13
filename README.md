# Ntopng Alert Analyzer

Приложение для анализа алертов ntopng с отправкой отчетов в Telegram.

## Структура проекта

📜 Основная логика:
	app.py — точка входа (возможно Flask/FastAPI)
	analyzer.py — анализ логов
	scheduler.py — планировщик
	celery_tasks.py — фоновые задачи
	telegram_bot.py — интеграция с Telegram
	database.py, models.py — работа с БД
	services/*.py — модульная логика (алерты, кэш, телеграм и т. д.)

⚙️ Конфигурация:
	.env.example
	config.py, settings.py
	requirements.txt

🧰 Установка и вспомогательные:
	install.sh, install.bat
	create_project.py