@echo off
title Automated PCAP Forensic Analysis and Reporting System
echo =====================================================================
echo  Automated PCAP Forensic Analysis and Reporting System
echo  Information Security Lab Mini Project
echo  Team: Riya Kushwah (58), Rahee Phapale (42), Kruthik Shetty (59)
echo =====================================================================
echo.
echo Starting Web Dashboard on http://localhost:8501 ...
echo.

set PYTHON_EXE=C:\Users\MAHE\AppData\Local\Programs\Python\Python311\python.exe

if not exist "%PYTHON_EXE%" (
    echo [ERROR] Python not found at %PYTHON_EXE%
    echo Falling back to system python...
    python -m streamlit run app.py
) else (
    "%PYTHON_EXE%" -m streamlit run app.py
)

pause
