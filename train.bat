@echo off
REM Use python.exe if py launcher is not on PATH (common on Windows)
setlocal
cd /d "%~dp0"
set PYTHONUTF8=1
python model_training.py %*
