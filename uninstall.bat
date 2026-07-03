@echo off
REM Professor OSINT - Uninstaller for Windows

echo ====================================================
echo       Professor OSINT - Uninstallation Script       
echo ====================================================

set "INSTALL_DIR=%USERPROFILE%\.professor_osint"
set "BIN_DIR=%USERPROFILE%\AppData\Local\Microsoft\WindowsApps"
set "WRAPPER_SCRIPT=%BIN_DIR%\professor-osint.bat"

echo [*] Removing installation directory (%INSTALL_DIR%)...
if exist "%INSTALL_DIR%" (
    rmdir /s /q "%INSTALL_DIR%"
    echo [+] Successfully removed %INSTALL_DIR%
) else (
    echo [-] Directory not found: %INSTALL_DIR% (Skipping)
)

echo [*] Removing global command (%WRAPPER_SCRIPT%)...
if exist "%WRAPPER_SCRIPT%" (
    del /f /q "%WRAPPER_SCRIPT%"
    echo [+] Successfully removed %WRAPPER_SCRIPT%
) else (
    echo [-] File not found: %WRAPPER_SCRIPT% (Skipping)
)

echo ====================================================
echo    Uninstallation Complete! 
echo ====================================================
echo Professor OSINT has been entirely removed from your system.
echo Note: If you installed via pip, run 'pip uninstall professor-osint' instead.
pause
