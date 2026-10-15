@echo off
REM SENTINEL Windows agent helper (run as Administrator)
set SERVER=%1
set KEY=%2
if "%SERVER%"=="" (
  echo Usage: install.bat https://central:8443 API_KEY
  exit /b 1
)
python "%~dp0sentinel_win_agent.py" once --server %SERVER% --key %KEY%
echo.
echo To schedule every 5 minutes:
echo schtasks /Create /SC MINUTE /MO 5 /TN SentinelAgent /TR "python %~dp0sentinel_win_agent.py once --server %SERVER% --key %KEY%"
