#!/usr/bin/env bash

# Professor OSINT - Uninstaller for macOS & Linux

echo -e "\033[1;36m====================================================\033[0m"
echo -e "\033[1;36m      Professor OSINT - Uninstallation Script       \033[0m"
echo -e "\033[1;36m====================================================\033[0m"

INSTALL_DIR="$HOME/.professor_osint"
BIN_DIR="$HOME/.local/bin"
WRAPPER_SCRIPT="$BIN_DIR/professor-osint"

echo -e "\033[1;34m[*] Removing installation directory ($INSTALL_DIR)...\033[0m"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo -e "\033[1;32m[+] Successfully removed $INSTALL_DIR\033[0m"
else
    echo -e "\033[1;33m[-] Directory not found: $INSTALL_DIR (Skipping)\033[0m"
fi

echo -e "\033[1;34m[*] Removing global command ($WRAPPER_SCRIPT)...\033[0m"
if [ -f "$WRAPPER_SCRIPT" ]; then
    rm -f "$WRAPPER_SCRIPT"
    echo -e "\033[1;32m[+] Successfully removed $WRAPPER_SCRIPT\033[0m"
else
    echo -e "\033[1;33m[-] File not found: $WRAPPER_SCRIPT (Skipping)\033[0m"
fi

echo -e "\033[1;32m====================================================\033[0m"
echo -e "\033[1;32m   Uninstallation Complete! \033[0m"
echo -e "\033[1;32m====================================================\033[0m"
echo -e "\033[1;37mProfessor OSINT has been entirely removed from your system.\033[0m"
echo -e "\033[1;37mNote: If you installed via pip, run 'pip uninstall professor-osint' instead.\033[0m\n"
