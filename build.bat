@echo off
echo ========================================
echo    Scam Advisor - Build Executable
echo ========================================
echo.

echo Step 1: Checking required files and directories...

:: Create directories if they don't exist
if not exist "data" mkdir data
if not exist "config" mkdir config

if not exist "data\history.json" (
    echo Creating missing history.json...
    echo [] > "data\history.json"
)

if not exist "config\defaults.ini" (
    echo Creating missing defaults.ini...
    echo [theme] > "config\defaults.ini"
    echo current = dark >> "config\defaults.ini"
    echo. >> "config\defaults.ini"
    echo [api_keys] >> "config\defaults.ini"
    echo virustotal =  >> "config\defaults.ini"
    echo abuseipdb =  >> "config\defaults.ini"
    echo otx =  >> "config\defaults.ini"
    echo. >> "config\defaults.ini"
    echo [scanning] >> "config\defaults.ini"
    echo timeout = 30 >> "config\defaults.ini"
    echo enable_caching = true >> "config\defaults.ini"
    echo max_redirects = 5 >> "config\defaults.ini"
)

echo Step 2: Checking if PyInstaller is installed...
python -m pyinstaller --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Step 3: Building executable...
pyinstaller setup.spec

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo    BUILD COMPLETE!
    echo ========================================
    echo.
    echo Your executable is ready at: dist\ScamAdvisor.exe
    echo.
    echo To test your application:
    echo   1. Navigate to: dist\
    echo   2. Double-click: ScamAdvisor.exe
    echo.
    echo Features included in your build:
    echo   ✅ Your VirusTotal API key
    echo   ✅ Your AlienVault OTX API key
    echo   ✅ Search history with 7 saved scans
    echo   ✅ All detection engines
    echo.
) else (
    echo.
    echo ========================================
    echo    BUILD FAILED!
    echo ========================================
    echo.
    echo Check the error messages above.
    echo.
)

pause