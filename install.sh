#!/usr/bin/env bash

# Professor OSINT - One Click Installer for macOS & Linux

set -e

echo -e "\033[1;36m====================================================\033[0m"
echo -e "\033[1;36m       Professor OSINT - Installation Script        \033[0m"
echo -e "\033[1;36m====================================================\033[0m"

# Ensure we're running from the project directory
if [ ! -f "professor_osint.py" ]; then
    echo -e "\033[0;31m[!] Error: Please run this script from the Databreach-Finder directory.\033[0m"
    exit 1
fi

# Check for Python 3
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null && python --version | grep -q "Python 3"; then
    PYTHON_CMD="python"
else
    echo -e "\033[0;31m[!] Error: Python 3 is not installed. Please install Python 3.8+ and try again.\033[0m"
    exit 1
fi

echo -e "\033[1;34m[*] Found Python 3 ($PYTHON_CMD)\033[0m"

OS_TYPE=$(uname)
if [ "$OS_TYPE" == "Darwin" ]; then
    OS="mac"
else
    OS="linux"
fi

echo ""
read -p "Do you want to install VPN dependencies (OpenVPN, WireGuard) for Layer-3 security? (y/n): " vpn_choice </dev/tty
if [[ "$vpn_choice" == "y" || "$vpn_choice" == "Y" ]]; then
    echo -e "\033[1;34m[*] Installing VPN dependencies for $OS...\033[0m"
    if [ "$OS" == "mac" ]; then
        if command -v brew &>/dev/null; then
            brew install openvpn wireguard-tools
        else
            echo -e "\033[0;31m[!] Homebrew not found. Please install openvpn and wireguard-tools manually.\033[0m"
        fi
    elif [ "$OS" == "linux" ]; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y openvpn wireguard
        elif command -v pacman &>/dev/null; then
            sudo pacman -Sy --noconfirm openvpn wireguard-tools
        else
            echo -e "\033[0;31m[!] Supported package manager not found! Please install VPN tools manually.\033[0m"
        fi
    fi
fi

# Installation Directories
INSTALL_DIR="$HOME/.professor_osint"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="$HOME/.local/bin"

echo -e "\033[1;34m[*] Installing Professor OSINT to $INSTALL_DIR...\033[0m"

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

# Copy files, avoiding local virtualenvs or scripts
for item in *; do
    if [ "$item" != "venv" ] && [ "$item" != ".git" ] && [ "$item" != "install.sh" ] && [ "$item" != "install.bat" ]; then
        cp -R "$item" "$INSTALL_DIR/" 2>/dev/null || true
    fi
done

# Setup Virtual Environment
echo -e "\033[1;34m[*] Creating Virtual Environment...\033[0m"
$PYTHON_CMD -m venv "$VENV_DIR"

echo -e "\033[1;34m[*] Installing Dependencies...\033[0m"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet
pip install -r "$INSTALL_DIR/requirements.txt" --quiet
deactivate

# Create wrapper script
WRAPPER_SCRIPT="$BIN_DIR/professor-osint"
echo -e "\033[1;34m[*] Creating global command 'professor-osint'...\033[0m"

cat << EOF > "$WRAPPER_SCRIPT"
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
python "$INSTALL_DIR/professor_osint.py" "\$@"
deactivate
EOF

chmod +x "$WRAPPER_SCRIPT"

# Create Web App wrapper script
WEB_WRAPPER="$BIN_DIR/professor-osint-web"
echo -e "\033[1;34m[*] Creating global command 'professor-osint-web'...\033[0m"

cat << EOF > "$WEB_WRAPPER"
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
python "$INSTALL_DIR/web_app.py" "\$@"
deactivate
EOF

chmod +x "$WEB_WRAPPER"

# Create Uninstaller wrapper script
UNINSTALL_WRAPPER="$BIN_DIR/professor-osint-uninstall"
echo -e "\033[1;34m[*] Creating global uninstaller 'professor-osint-uninstall'...\033[0m"

cat << EOF > "$UNINSTALL_WRAPPER"
#!/usr/bin/env bash
echo -e "\033[1;31m[*] Uninstalling Professor OSINT...\033[0m"
rm -rf "$INSTALL_DIR"
rm -f "$WRAPPER_SCRIPT"
rm -f "$WEB_WRAPPER"
rm -f "\$0"
echo -e "\033[1;32m[+] Successfully completely uninstalled Professor OSINT.\033[0m"
EOF

chmod +x "$UNINSTALL_WRAPPER"

echo -e "\033[1;32m====================================================\033[0m"
echo -e "\033[1;32m   Installation Successful! \033[0m"
echo -e "\033[1;32m====================================================\033[0m"
echo -e "\033[1;37mYou can now run the tool from anywhere using the commands:\033[0m"
echo -e "\n    \033[1;33mprofessor-osint --help\033[0m   (For CLI)"
echo -e "    \033[1;33mprofessor-osint-web\033[0m      (For Web Dashboard)"
echo -e "    \033[1;31mprofessor-osint-uninstall\033[0m (To remove everything)\n"
echo -e "\033[1;34m[*] All configuration and reports will be saved centrally to: ~/POSINT\033[0m\n"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "\033[1;31m[!] NOTE: $HOME/.local/bin is not in your PATH.\033[0m"
    echo -e "\033[1;37mPlease add the following line to your ~/.bashrc or ~/.zshrc:\033[0m"
    echo -e "\033[1;33mexport PATH=\"\$HOME/.local/bin:\$PATH\"\033[0m"
fi
