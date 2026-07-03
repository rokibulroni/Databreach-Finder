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

:: Copy files (excluding local virtualenvs, git files, and installer scripts)
robocopy . "%INSTALL_DIR%" /E /XD venv .git /XF install.sh install.bat >nul
if %errorlevel% gtr 7 (
    echo [!] Error copying files.
    exit /b 1
)

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

set WEB_WRAPPER=%INSTALL_DIR%\professor-osint-web.bat
echo [*] Creating global command 'professor-osint-web'...

(
echo @echo off
echo call "%VENV_DIR%\Scripts\activate.bat"
echo python "%INSTALL_DIR%\web_app.py" %%*
echo call deactivate
) > "%WEB_WRAPPER%"

set UNINSTALL_WRAPPER=%INSTALL_DIR%\professor-osint-uninstall.bat
echo [*] Creating global uninstaller 'professor-osint-uninstall'...

(
echo @echo off
echo echo [*] Uninstalling Professor OSINT...
echo rmdir /s /q "%INSTALL_DIR%"
echo echo [+] Successfully completely uninstalled Professor OSINT.
echo del "%%~f0"
) > "%UNINSTALL_WRAPPER%"

echo ====================================================
echo    Installation Successful! 
echo ====================================================
echo You can now run the tool using the commands:
echo     %WRAPPER_SCRIPT% --help     (For CLI)
echo     %WEB_WRAPPER%          (For Web Dashboard)
echo     %UNINSTALL_WRAPPER%    (To remove everything)
echo.
echo [*] All configuration and reports will be saved centrally to: %USERPROFILE%\POSINT
echo To run it from anywhere, add %INSTALL_DIR% to your system PATH.

endlocal
