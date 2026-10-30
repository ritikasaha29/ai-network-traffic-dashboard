@echo off
echo =========================================================================
echo Starting AI-Driven Network Traffic Intelligence Dashboard...
echo Course: BCSE308P Computer Networks Lab - VIT Vellore
echo Faculty Incharge: Dr. S. Ebenezer Juliet, Professor Grade 1, SCOPE
echo =========================================================================
cd /d "%~dp0"
python -m streamlit run dashboard/app.py
pause
