@echo off
echo ��⠭���� Ntopng Analyzer...

:: �������� ����㠫쭮�� ���㦥���
python -m venv venv
call venv\Scripts\activate.bat

:: ��⠭���� ����ᨬ��⥩
pip install -r requirements.txt

:: ����஢���� 䠩�� ���䨣��樨
copy .env.example .env

echo ��⠭���� �����襭�!
echo ��।������ 䠩� .env � �������: python app.py
pause