@echo off
echo ���࠭���� �஡��� � ��⠭�����...

:: ��⨢��㥬 ����㠫쭮� ���㦥���
call venv\Scripts\activate.bat

:: �஢��塞 ��⠭������� ������
echo �஢�ઠ ��⠭�������� ����⮢...
pip list

:: ��⠭�������� �᭮��� ����ᨬ���
echo ��⠭���� �᭮���� ����ᨬ��⥩...
pip install fastapi uvicorn python-telegram-bot python-dotenv sqlalchemy aiosqlite

:: ��⠭�������� �������⥫�� ����ᨬ���
echo ��⠭���� �������⥫��� ����ᨬ��⥩...
pip install loguru pydantic pydantic-settings apscheduler pandas jinja2 requests

:: �஢��塞 ��⠭����
echo �஢�ઠ ��⠭����...
python -c "import fastapi; print('FastAPI ��⠭�����')"
python -c "import sqlalchemy; print('SQLAlchemy ��⠭�����')"
python -c "import telegram; print('Python-telegram-bot ��⠭�����')"

echo ��⮢�! ������ ����� ��������: python app.py
pause