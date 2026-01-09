@echo off
title Encrypt Tool Web Server
echo Starting the Encryption Tool Web Server...
echo.
echo If this is your first time, we will install dependencies.
echo.

if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate

echo Installing/Updating dependencies...
pip install -r requirements.txt
cls

echo ========================================================
echo   Server is running!
echo   Open your browser and go to: http://127.0.0.1:5000
echo   (Don't close this window while using the tool)
echo ========================================================
echo.

python app.py
pause
