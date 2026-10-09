@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" launch_demo.py
) else (
  python launch_demo.py
)
if errorlevel 1 (
  echo.
  echo Install dependencies first: python -m pip install -r requirements.txt
  pause
)
