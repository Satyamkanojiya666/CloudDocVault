@echo off
REM Double-click to run CloudDocVault on your own PC (no AWS, no internet needed after install).
cd /d %~dp0
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate
pip install -q -r requirements-local.txt
if not exist docvault.db (
    set /p DEMO=Create demo account with sample files? [y/n]: 
    if /i "%DEMO%"=="y" python seed_demo.py
)
echo.
echo Open  http://localhost:5000  in your browser   (Ctrl+C to stop)
python app.py
pause
