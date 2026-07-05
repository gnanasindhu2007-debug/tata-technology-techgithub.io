@echo off
cd /d "%~dp0"
set FLASK_RUN_HOST=0.0.0.0
"C:\Users\Admin\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -c "from app import init_db, app; init_db(); app.run(debug=True, host='0.0.0.0', port=5000)"
pause
