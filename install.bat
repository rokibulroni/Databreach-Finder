@echo off
setlocal enabledelayedexpansion

echo ====================================================
echo        Professor OSINT - Installation Script
echo ====================================================

if not exist "professor_osint.py" (
    echo [!] Error: Please run this script from the Databreach-Finder directory.
    exit /b 1
)

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: Python 3 is not installed or not in PATH.
    echo Please install Python 3.8+ and try again.
    exit /b 1
)

set INSTALL_DIR=%USERPROFILE%\.professor_osint
set VENV_DIR=%INSTALL_DIR%\venv

echo [*] Installing Professor OSINT to %INSTALL_DIR%...

:: Create directory
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: Copy files
xcopy /E /I /Y . "%INSTALL_DIR%" >nul

echo [*] Creating Virtual Environment...
python -m venv "%VENV_DIR%"

echo [*] Installing Dependencies...
call "%VENV_DIR%\Scripts\activate.bat"
python -m pip install --upgrade pip >nul
pip install -r "%INSTALL_DIR%\requirements.txt" >nul
call deactivate

set WRAPPER_SCRIPT=%INSTALL_DIR%\professor-osint.bat
echo [*] Creating global command 'professor-osint'...

(
echo @echo off
echo call "%VENV_DIR%\Scripts\activate.bat"
echo python "%INSTALL_DIR%\professor_osint.py" %%*
echo call deactivate
) > "%WRAPPER_SCRIPT%"

echo ====================================================
echo    Installation Successful! 
echo ====================================================
echo You can now run the tool using the command:
echo     %WRAPPER_SCRIPT% --help
echo.
echo To run it from anywhere, add %INSTALL_DIR% to your system PATH.

endlocal
