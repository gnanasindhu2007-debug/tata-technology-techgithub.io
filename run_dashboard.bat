@echo off
cd /d "%~dp0"
echo Starting DeepShield AI companion Streamlit dashboard...
"C:\Users\Admin\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m streamlit run streamlit_dashboard.py
pause
